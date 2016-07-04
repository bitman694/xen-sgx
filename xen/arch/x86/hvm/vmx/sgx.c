/*
 * Intel Software Guard Extensions support
 *
 * Author: Kai Huang <kai.huang@linux.intel.com>
 */

#include <asm/cpufeature.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/sgx.h>
#include <asm/hvm/vmx/vmcs.h>

static struct sgx_cpuinfo __read_mostly sgx_cpudata[NR_CPUS];
static struct sgx_cpuinfo __read_mostly boot_sgx_cpudata;

/*
 * epc_frametable keeps an array of struct epc_page for every EPC pages, so that
 * epc_page_to_mfn, epc_mfn_to_page works straightforwardly. The array will be
 * allocated dynamically according to machine's EPC size.
 */
static struct epc_page *epc_frametable = NULL;
/*
 * EPC is mapped to Xen's virtual address at once, so that each EPC page's
 * virtual address is epc_base_vaddr + offset.
 */
static void *epc_base_vaddr = NULL;

/* Global free EPC pages list. */
static struct list_head free_epc_list;
static spinlock_t epc_lock;

#define total_epc_npages (boot_sgx_cpudata.epc_size >> PAGE_SHIFT)
#define epc_base_mfn (boot_sgx_cpudata.epc_base >> PAGE_SHIFT)

/* Current number of free EPC pages in free_epc_list */
static unsigned long free_epc_npages = 0;

unsigned long epc_page_to_mfn(struct epc_page *epg)
{
    BUG_ON(!epc_frametable);
    BUG_ON(!epc_base_mfn);

    return epc_base_mfn + (epg - epc_frametable);
}

struct epc_page *epc_mfn_to_page(unsigned long mfn)
{
    BUG_ON(!epc_frametable);
    BUG_ON(!epc_base_mfn);

    return epc_frametable + (mfn - epc_base_mfn);
}

struct epc_page *alloc_epc_page(void)
{
    struct epc_page *epg;

    spin_lock(&epc_lock);
    epg = list_first_entry_or_null(&free_epc_list, struct epc_page, list);
    if ( epg ) {
        list_del(&epg->list);
        free_epc_npages--;
    }
    spin_unlock(&epc_lock);

    return epg;
}

void free_epc_page(struct epc_page *epg)
{
    spin_lock(&epc_lock);
    list_add_tail(&epg->list, &free_epc_list);
    free_epc_npages++;
    spin_unlock(&epc_lock);
}

void *map_epc_page_to_xen(struct epc_page *epg)
{
    BUG_ON(!epc_base_vaddr);
    BUG_ON(!epc_frametable);

    return (void *)(((unsigned long)(epc_base_vaddr)) +
            ((epg - epc_frametable) << PAGE_SHIFT));
}

void unmap_epc_page(void *addr)
{
    /* Nothing */
}

/* ENCLS opcode */
#define ENCLS   .byte 0x0f, 0x01, 0xcf

/*
 * ENCLS leaf functions
 *
 * However currently we only needs EREMOVE..
 */
enum {
    ECREATE = 0x0,
    EADD    = 0x1,
    EINIT   = 0x2,
    EREMOVE = 0x3,
    EDGBRD  = 0x4,
    EDGBWR  = 0x5,
    EEXTEND = 0x6,
    ELDU    = 0x8,
    EBLOCK  = 0x9,
    EPA     = 0xA,
    EWB     = 0xB,
    ETRACK  = 0xC,
    EAUG    = 0xD,
    EMODPR  = 0xE,
    EMODT   = 0xF,
};

/*
 * ENCLS error code
 *
 * Currently we only need SGX_CHILD_PRESENT
 */
#define SGX_CHILD_PRESENT   13

static inline int __encls(unsigned long rax, unsigned long rbx,
                          unsigned long rcx, unsigned long rdx)
{
    int ret;

    asm volatile ( "ENCLS;\n\t"
            : "=a" (ret)
            : "a" (rax), "b" (rbx), "c" (rcx), "d" (rdx)
            : "memory", "cc");

    return ret;
}

static inline int __eremove(void *epc)
{
    unsigned long rbx = 0, rdx = 0;

    return __encls(EREMOVE, rbx, (unsigned long)epc, rdx);
}

static int sgx_eremove(struct epc_page *epg)
{
    void *addr = map_epc_page_to_xen(epg);
    int ret;

    BUG_ON(!addr);

    ret =  __eremove(addr);

    unmap_epc_page(addr);

    return ret;
}

/*
 * Reset domain's EPC with EREMOVE. free_epc indicates whether to free EPC
 * pages during reset. This will be called when domain goes into S3-S5 state
 * (with free_epc being false), and when domain is destroyed (with free_epc
 * being true).
 *
 * It is possible that EREMOVE will be called for SECS when it still has
 * children present, in which case SGX_CHILD_PRESENT will be returned. In this
 * case, SECS page is kept to a tmp list and after all EPC pages have been
 * called with EREMOVE, we call EREMOVE for all the SECS pages again, and this
 * time SGX_CHILD_PRESENT should never occur as all children should have been
 * removed.
 *
 * If unexpected error returned by EREMOVE, it means the EPC page becomes
 * abnormal, so it will not be freed even free_epc is true, as further use of
 * this EPC can cause unexpected error, potentially damaging other domains.
 */
static int __hvm_reset_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages, bool_t free_epc)
{
    struct list_head secs_list;
    struct list_head *p, *tmp;
    unsigned long i;
    int ret = 0;

    INIT_LIST_HEAD(&secs_list);

    for ( i = 0; i < epc_npages; i++ )
    {
        struct epc_page *epg;
        unsigned long gfn;
        mfn_t mfn;
        p2m_type_t t;
        int r;

        gfn = i + epc_base_pfn;
        mfn = get_gfn_query(d, gfn, &t);
        if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
        {
            printk("Domain %d: Reset EPC error: invalid MFN for gfn 0x%lx\n",
                    d->domain_id, gfn);
            put_gfn(d, gfn);
            ret = -EFAULT;
            continue;
        }

        if ( unlikely(!p2m_is_epc(t)) )
        {
            printk("Domain %d: Reset EPC error: (gfn 0x%lx, mfn 0x%lx): " 
                    "is not p2m_epc.\n", d->domain_id, gfn, mfn_x(mfn));
            put_gfn(d, gfn);
            ret = -EFAULT;
            continue;
        }

        put_gfn(d, gfn);

        epg = epc_mfn_to_page(mfn_x(mfn));

        /* EREMOVE the EPC page to make it invalid */
        r = sgx_eremove(epg);
        if ( r == SGX_CHILD_PRESENT )
        {
            list_add_tail(&epg->list, &secs_list);
            continue;
        }

        if ( r )
        {
            printk("Domain %d: Reset EPC error: (gfn 0x%lx, mfn 0x%lx): "
                    "EREMOVE returns %d\n", d->domain_id, gfn, mfn_x(mfn), r);
            ret = r;
            if ( free_epc )
                printk("WARNING: EPC (mfn 0x%lx) becomes abnormal. "
                        "Remove it from useable EPC.", mfn_x(mfn));
            continue;
        }

        if ( free_epc )
        {
            /* If EPC page is going to be freed, then also remove the mapping */
            if ( clear_epc_p2m_entry(d, gfn, mfn) )
            {
                printk("Domain %d: Reset EPC error: (gfn 0x%lx, mfn 0x%lx): "
                        "clear p2m entry failed.\n", d->domain_id, gfn,
                        mfn_x(mfn));
                ret = -EFAULT;
            }
            free_epc_page(epg);
        }
    }

    list_for_each_safe(p, tmp, &secs_list)
    {
        struct epc_page *epg = list_entry(p, struct epc_page, list);
        int r;

        r = sgx_eremove(epg);
        if ( r )
        {
            printk("Domain %d: Reset EPC error: mfn 0x%lx: "
                    "EREMOVE returns %d for SECS page\n",
                    d->domain_id, epc_page_to_mfn(epg), r);
            ret = r;
            list_del(p);

            if ( free_epc )
                printk("WARNING: EPC (mfn 0x%lx) becomes abnormal. "
                        "Remove it from useable EPC.",
                        epc_page_to_mfn(epg));
            continue;
        }

        if ( free_epc )
            free_epc_page(epg);
    }

    return ret;
}

static void __hvm_unpopulate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long populated_npages)
{
    unsigned long i;

    for ( i = 0; i < populated_npages; i++ )
    {
        struct epc_page *epg;
        unsigned long gfn;
        mfn_t mfn;
        p2m_type_t t;

        gfn = i + epc_base_pfn;
        mfn = get_gfn_query(d, gfn, &t);
        if ( unlikely(mfn_eq(mfn, INVALID_MFN)) )
        {
            /*
             * __hvm_unpopulate_epc only called when creating the domain on
             * failure, therefore we can just ignore this error.
             */
            printk("%s: Domain %u gfn 0x%lx returns invalid mfn\n", __func__,
                    d->domain_id, gfn);
            put_gfn(d, gfn);
            continue;
        }

        if ( unlikely(!p2m_is_epc(t)) )
        {
            printk("%s: Domain %u gfn 0x%lx returns non-EPC p2m type: %d\n",
                    __func__, d->domain_id, gfn, (int)t);
            put_gfn(d, gfn);
            continue;
        }

        put_gfn(d, gfn);

        if ( clear_epc_p2m_entry(d, gfn, mfn) )
        {
            printk("clear_epc_p2m_entry failed: gfn 0x%lx, mfn 0x%lx\n",
                    gfn, mfn_x(mfn));
            continue;
        }

        epg = epc_mfn_to_page(mfn_x(mfn));
        free_epc_page(epg);
    }
}

static int __hvm_populate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages)
{
    unsigned long i;
    int ret;

    for ( i = 0; i < epc_npages; i++ )
    {
        struct epc_page *epg = alloc_epc_page();
        unsigned long mfn;

        if ( !epg )
        {
            printk("%s: Out of EPC\n", __func__);
            ret = -ENOMEM;
            goto err;
        }

        mfn = epc_page_to_mfn(epg);
        ret = set_epc_p2m_entry(d, i + epc_base_pfn, _mfn(mfn));
        if ( ret )
        {
            printk("%s: set_epc_p2m_entry failed with %d: gfn 0x%lx, "
                    "mfn 0x%lx\n", __func__, ret, i + epc_base_pfn, mfn);
            free_epc_page(epg);
            goto err;
        }
    }

    return 0;

err:
    __hvm_unpopulate_epc(d, epc_base_pfn, i);
    return ret;
}

int hvm_populate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages)
{
    struct sgx_domain *sgx = to_sgx(d);
    int ret;

    if ( hvm_epc_populated(d) )
        return -EBUSY;

    if ( !epc_base_pfn || !epc_npages )
        return -EINVAL;

    if ( (ret = __hvm_populate_epc(d, epc_base_pfn, epc_npages)) )
        return ret;

    sgx->epc_base_pfn = epc_base_pfn;
    sgx->epc_npages = epc_npages;

    return 0;
}

/*
 *
*
 * This function returns error immediately if there's any unexpected error
 * during this process.
 */
int hvm_reset_epc(struct domain *d, bool_t free_epc)
{
    struct sgx_domain *sgx = to_sgx(d);

    if ( !hvm_epc_populated(d) )
        return 0;

    return __hvm_reset_epc(d, sgx->epc_base_pfn, sgx->epc_npages, free_epc);
}

void hvm_destroy_epc(struct domain *d)
{
    hvm_reset_epc(d, true);
}

static bool_t sgx_enabled_in_bios(void)
{
    uint64_t val, sgx_enabled = IA32_FEATURE_CONTROL_SGX_ENABLE |
                                IA32_FEATURE_CONTROL_LOCK;

    rdmsrl(MSR_IA32_FEATURE_CONTROL, val);

    return (val & sgx_enabled) == sgx_enabled;
}

static void __detect_sgx(int cpu)
{
    struct sgx_cpuinfo *sgxinfo = &sgx_cpudata[cpu];
    u32 eax, ebx, ecx, edx;

    memset(sgxinfo, 0, sizeof(*sgxinfo));

    /*
     * In reality if SGX is not enabled in BIOS, SGX CPUID should report
     * invalid SGX info, but we do the check anyway to make sure.
     */
    if ( !sgx_enabled_in_bios() )
    {
        printk("CPU%d: SGX disabled in BIOS.\n", cpu);
        goto not_supported;
    }

    /*
     * CPUID.0x12.0x0:
     *
     *  EAX [0]:    whether SGX1 is supported.
     *      [1]:    whether SGX2 is supported.
     *  EBX [31:0]: miscselect
     *  ECX [31:0]: reserved
     *  EDX [7:0]:  MaxEnclaveSize_Not64
     *      [15:8]: MaxEnclaveSize_64
     */
    cpuid_count(SGX_CPUID, 0x0, &eax, &ebx, &ecx, &edx);
    sgxinfo->cap = eax & (SGX_CAP_SGX1 | SGX_CAP_SGX2);
    sgxinfo->miscselect = ebx;
    sgxinfo->max_enclave_size32 = edx & 0xff;
    sgxinfo->max_enclave_size64 = (edx & 0xff00) >> 8;

    if ( !(eax & SGX_CAP_SGX1) )
    {
        /* We may reach here if BIOS doesn't enable SGX */
        printk("CPU%d: CPUID.0x12.0x0 reports not SGX support.\n", cpu);
        goto not_supported;
    }

    /*
     * CPUID.0x12.0x1:
     *
     *  EAX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[31:0]
     *  EBX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[63:32]
     *  ECX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[95:64]
     *  EDX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[127:96]
     */
    cpuid_count(SGX_CPUID, 0x1, &eax, &ebx, &ecx, &edx);
    sgxinfo->secs_attr_bitmask[0] = eax;
    sgxinfo->secs_attr_bitmask[1] = ebx;
    sgxinfo->secs_attr_bitmask[2] = ecx;
    sgxinfo->secs_attr_bitmask[3] = edx;

    /*
     * CPUID.0x12.0x2:
     *
     *  EAX [3:0]:      0000: this sub-leaf is invalid
     *                  0001: this sub-leaf enumerates EPC resource
     *      [11:4]:     reserved
     *      [31:12]:    bits 31:12 of physical address of EPC base (when
     *                  EAX[3:0] is 0001, which applies to following)
     *  EBX [19:0]:     bits 51:32 of physical address of EPC base
     *      [31:20]:    reserved
     *  ECX [3:0]:      0000: EDX:ECX are 0
     *                  0001: this is EPC section.
     *      [11:4]:     reserved
     *      [31:12]:    bits 31:12 of EPC size
     *  EDX [19:0]:     bits 51:32 of EPC size
     *      [31:20]:    reserved
     *
     *  TODO: So far assume there's only one EPC resource.
     */
    cpuid_count(SGX_CPUID, 0x2, &eax, &ebx, &ecx, &edx);
    if ( !(eax & 0x1) || !(ecx & 0x1) )
    {
        /* We may reach here if BIOS doesn't enable SGX */
        printk("CPU%d: CPUID.0x12.0x2 reports invalid EPC resource.\n", cpu);
        goto not_supported;
    }
    sgxinfo->epc_base = (((u64)(ebx & 0xfffff)) << 32) | (eax & 0xfffff000);
    sgxinfo->epc_size = (((u64)(edx & 0xfffff)) << 32) | (ecx & 0xfffff000);

    return;

not_supported:
    memset(sgxinfo, 0, sizeof(*sgxinfo));
}

void detect_sgx(int cpu)
{
    /* Caller (vmx_cpu_up) has checked cpu_has_vmx_encls */
    if ( !cpu_has_sgx || boot_cpu_data.cpuid_level < SGX_CPUID )
    {
        setup_clear_cpu_cap(X86_FEATURE_SGX);
        return;
    }

    __detect_sgx(cpu);
}

static void __init disable_sgx(void)
{
    memset(&boot_sgx_cpudata, 0, sizeof (struct sgx_cpuinfo));
    /*
     * X86_FEATURE_SGX is cleared in boot_cpu_data so that cpu_has_sgx
     * can be used anywhere to check whether SGX is supported by Xen.
     *
     * FIXME: also adjust boot_cpu_data.cpuid_level ?
     */
    setup_clear_cpu_cap(X86_FEATURE_SGX);
}

static void __init print_sgx_cpuinfo(struct sgx_cpuinfo *sgxinfo)
{
    printk("SGX: \n"
           "\tCAP: %s,%s\n"
           "\tEPC: [0x%"PRIx64", 0x%"PRIx64")\n",
           boot_sgx_cpudata.cap & SGX_CAP_SGX1 ? "SGX1" : "",
           boot_sgx_cpudata.cap & SGX_CAP_SGX2 ? "SGX2" : "",
           boot_sgx_cpudata.epc_base,
           boot_sgx_cpudata.epc_base + boot_sgx_cpudata.epc_size);
}

/*
 * Check SGX CPUID info all for all CPUs, and only support SGX when all CPUs
 * report the same SGX info. SDM (37.7.2 Intel SGX Resource Enumeration Leaves)
 * says "software should not assume that if Intel SGX instructions are
 * supported on one hardware thread, they are also supported elsewhere.".
 * For simplicity, we only support SGX when all CPUs reports consistent SGX
 * info.
 *
 * boot_sgx_cpudata is set to store the *common* SGX CPUID info.
 */
static bool_t __init check_sgx_consistency(void)
{
    int i;

    for_each_online_cpu ( i )
    {
        struct sgx_cpuinfo *s = &sgx_cpudata[i];

        if ( memcmp(&boot_sgx_cpudata, s, sizeof (*s)) )
        {
            printk("SGX inconsistency between CPU 0 and CPU %d. "
                    "Disable SGX.\n", i);
            memset(&boot_sgx_cpudata, 0,  sizeof (*s));
            return false;
        }
    }

    return true;
}

static int inline npages_to_order(unsigned long npages)
{
    int order = 0;

    while ( (1 << order) < npages )
        order++;

    return order;
}

static int __init init_epc_frametable(unsigned long npages)
{
    unsigned long i, order;

    order = npages * sizeof(struct epc_page);
    order >>= 12;
    order = npages_to_order(order);

    epc_frametable = alloc_xenheap_pages(order, 0);
    if ( !epc_frametable )
        return -ENOMEM;

    for ( i = 0; i < npages; i++ )
    {
        struct epc_page *epg = epc_frametable + i;

        list_add_tail(&epg->list, &free_epc_list);
    }

    return 0;
}

static void destroy_epc_frametable(unsigned long npages)
{
    unsigned long order;

    if ( !epc_frametable )
        return;

    order = npages * sizeof(struct epc_page);
    order >>= 12;
    order = npages_to_order(order);

    free_xenheap_pages(epc_frametable, order);
}

static int __init sgx_init_epc(void)
{
    int r;

    INIT_LIST_HEAD(&free_epc_list);
    spin_lock_init(&epc_lock);

    r = init_epc_frametable(total_epc_npages);
    if ( r )
    {
        printk("Failed to allocate EPC frametable. Disable SGX.\n");
        return r;
    }

    epc_base_vaddr = ioremap_cache(epc_base_mfn << PAGE_SHIFT,
            total_epc_npages << PAGE_SHIFT);
    if ( !epc_base_vaddr )
    {
        printk("Failed to ioremap_cache EPC. Disable SGX.\n");
        destroy_epc_frametable(total_epc_npages);
        return -EFAULT;
    }

    free_epc_npages = total_epc_npages;

    return 0;
}

static int __init sgx_init(void)
{
    /* Assume CPU 0 is always online */
    boot_sgx_cpudata = sgx_cpudata[0];

    if ( !(boot_sgx_cpudata.cap & SGX_CAP_SGX1) )
        goto not_supported;

    if ( !check_sgx_consistency() )
        goto not_supported;

    if ( sgx_init_epc() )
        goto not_supported;

    print_sgx_cpuinfo(&boot_sgx_cpudata);

    return 0;
not_supported:
    disable_sgx();
    return -EINVAL;
}
__initcall(sgx_init);

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
