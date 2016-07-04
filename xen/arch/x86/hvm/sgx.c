/*
 * Intel Software Guard Extensions support
 *
 * Author: Kai Huang <kai.huang@linux.intel.com>
 */

#include <xen/list.h>
#include <xen/errno.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <asm/p2m.h>
#include <asm/hvm/sgx.h>

#define CPUID_SGX   0x12

/*
 * CPUID.0x12.0x1 reports 128-bit bitmap (eax~edx) of 1-setting of
 * SECS.ATTRIBUTES[128], meaning if some bit i is 1 (in eax~edx), software is
 * able to set corresponding bit in SECS.ATTRIBUTES[i].
 */
struct sgx_secs_attr_bitmask {
    u64 init:1;
    u64 debug:1;
    u64 mode64bit:1;
    u64 reserved0:1;
    u64 provisionkey:1;
    u64 einittokenkey:1;
    u64 reserved1:58;
    u64 xfrm;
};

/*
 * SGX physical info structure. Toolstack may needs this info for displaying
 * physical EPC size, setting up CPUID emulation for guest, etc.
 *
 * TODO:
 *
 * SDM actually says it's possible there are multiple EPC resources on the
 * machine (CPUID.0x12, ECX starting with 0x2 enumerates available EPC resources
 * until invalid EPC resource is returned). But in reality I've never seen any
 * machine has more than one EPC resource, so for simplicity we assume there is
 * only one EPC resource for now. As other software components don't need to
 * know exactly how many EPC resources the machine has, this info is
 * self-contained, and we can easily extend to support multiple EPC resources in
 * the future.
 */
struct sgx_cpuinfo {
#define SGX_CAP_SGX1    (1UL << 0)
#define SGX_CAP_SGX2    (1UL << 1)
    u32 cap;
    u32 miscselect;
    u8 max_enclave_size64;
    u8 max_enclave_size32;
    /* struct sgx_secs_attr_bitmask */
    u32 secs_attr_bitmask[4];
    u64 epc_base;
    u64 epc_size;
};

/*
 * SDM says 'Information returned by CPUID.12H is thread specific; software
 * should not assume that if Intel SGX instructions are supported on one
 * hardware thread, they are also supported elsewhere', but it doesn't say
 * whether different threads will report different information if they all
 * support SGX. Looks it's still possible that different threads may return
 * different info such as whether SGX2 is supported... Therefore we should
 * minimize SGX capabilities exposed to guests so that all vcpus can run on all
 * possible threads.
 */
static struct sgx_cpuinfo __read_mostly sgx_cpudata[NR_CPUS];
/* sgx_boot_cpudata holds minimal SGX capability for all CPUs */
static struct sgx_cpuinfo __read_mostly *sgx_boot_cpudata = NULL;

static void __init update_sgx_boot_cpudata(struct sgx_cpuinfo *sgxc)
{
    struct sgx_cpuinfo *bs = sgx_boot_cpudata;

    BUG_ON(!bs);

    if ( bs == sgxc )
        return;

    bs->cap &= sgxc->cap;

    if ( bs->miscselect > sgxc->miscselect )
        bs->miscselect = sgxc->miscselect;

    if ( bs->max_enclave_size32 > sgxc->max_enclave_size32 )
        bs->max_enclave_size32 = sgxc->max_enclave_size32;
    if ( bs->max_enclave_size64 > sgxc->max_enclave_size64 )
        bs->max_enclave_size64 = sgxc->max_enclave_size64;

    bs->secs_attr_bitmask[0] &= sgxc->secs_attr_bitmask[0];
    bs->secs_attr_bitmask[1] &= sgxc->secs_attr_bitmask[1];
    bs->secs_attr_bitmask[2] &= sgxc->secs_attr_bitmask[2];
    bs->secs_attr_bitmask[3] &= sgxc->secs_attr_bitmask[3];
}

/*
 * According to SDM SGX info returned by CPUID is per-thread, therefore we need
 * to detect SGX capability for each thread, as we only want to support SGX when
 * all CPUs support SGX. This function detects SGX info for particular CPU.
 *
 * Note this function may clear X86_FEATURE_SGX in c->x86_capability in case of
 * any error, so it should be called after CPUID.0x7.0x0 has been detected.
 */
void __init detect_sgx(struct cpuinfo_x86 *c)
{
    int cpu = smp_processor_id();
    struct sgx_cpuinfo *sgxc;
    unsigned int eax, ebx, ecx, edx;

    sgxc = sgx_cpudata + cpu;

    /*
     * The same as identify_cpu, assume this function is called firstly when
     * c == &boot_cpu_data.
     */
    if ( c == &boot_cpu_data )
        sgx_boot_cpudata = sgxc;

    memset(sgxc, 0, sizeof(*sgxc));

    if ( !cpu_has(c, X86_FEATURE_SGX) )
        return;

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
    cpuid_count(CPUID_SGX, 0x0, &eax, &ebx, &ecx, &edx);
    sgxc->cap = eax & (SGX_CAP_SGX1 | SGX_CAP_SGX2);
    sgxc->miscselect = ebx;
    sgxc->max_enclave_size32 = edx & 0xff;
    sgxc->max_enclave_size64 = (edx & 0xff00) >> 8;

    if ( !(eax & SGX_CAP_SGX1) )
    {
        /* This should never happen. Or probably we can just BUG. */
        printk("CPU %d: CPUID.0x12.0x0 reports no SGX capability. "
                "Disable SGX.\n", cpu);
        clear_bit(X86_FEATURE_SGX, c->x86_capability);
        goto out;
    }

    /*
     * CPUID.0x12.0x1:
     *
     *  EAX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[31:0]
     *  EBX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[63:32]
     *  ECX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[95:64]
     *  EDX [31:0]: bitmask of 1-setting of SECS.ATTRIBUTES[127:96]
     */
    cpuid_count(CPUID_SGX, 0x1, &eax, &ebx, &ecx, &edx);
    sgxc->secs_attr_bitmask[0] = eax;
    sgxc->secs_attr_bitmask[1] = ebx;
    sgxc->secs_attr_bitmask[2] = ecx;
    sgxc->secs_attr_bitmask[3] = edx;

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
     *  FIXME: So far assume there's only one EPC resource.
     */
    cpuid_count(CPUID_SGX, 0x2, &eax, &ebx, &ecx, &edx);
    if ( !(eax & 0x1) || !(ecx & 0x1) )
    {
        /* This should not happen neither */
        printk("CPU %d: CPUID.0x12.0x2 reports invalid EPC resource.\n", cpu);
        clear_bit(X86_FEATURE_SGX, c->x86_capability);
        goto out;
    }
    sgxc->epc_base = (((u64)(ebx & 0xfffff)) << 32) | (eax & 0xfffff000);
    sgxc->epc_size = (((u64)(edx & 0xfffff)) << 32) | (ecx & 0xfffff000);

    if ( c != &boot_cpu_data )
    {
        if ( (sgxc->epc_base != sgx_boot_cpudata->epc_base) ||
                (sgxc->epc_size != sgx_boot_cpudata->epc_size) )
        {
            /* This should not happen neither */
            printk("CPU %d: CPUID reports different EPC resource with boot "
                    "cpu.\n", cpu);
            clear_bit(X86_FEATURE_SGX, c->x86_capability);
            goto out;
        }
    }

out:
    update_sgx_boot_cpudata(sgxc);
}

/*
 * EPC page infomation structure. Each EPC has one struct epc_page to keep EPC
 * page info, just like struct page_info for normal memory.
 *
 * So far in reality machine's EPC size won't execeed hundreds MB, so for
 * simplicity currently we just put all free EPC pages in global free list.
 */
struct epc_page {
    struct list_head list;  /* all free EPC pages are in global free list. */
};

/*
 * epc_frametable keeps an array of struct epc_page for every EPC pages, so that
 * epc_page_to_mfn, epc_mfn_to_page works straightforwardly. The array will be
 * allocated dynamically according to machine's EPC size.
 */
static struct epc_page *epc_frametable = NULL;

/* Global free EPC pages list. */
static struct list_head free_epc_list;
static spinlock_t epc_lock;

/* Total number of EPC pages that machine has */
static unsigned long total_epc_npages = 0;
/* Current number of free EPC pages in free_epc_list */
static unsigned long free_epc_npages = 0;

bool_t sgx_enabled = 0;

static int npages_to_order(unsigned long npages)
{
    int order = 0;

    while ( (1 << order) < npages )
        order++;

    return order;
}

static int init_epc_frametable(unsigned long npages)
{
    unsigned long i, order;

    order = npages * sizeof(struct epc_page);
    order >>= 12;
    order = npages_to_order(order);
    printk("%s: npages 0x%lx, epc_frametable order 0x%lx\n", __func__,
            npages, order);

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

static void fini_epc_frametable(unsigned long npages)
{
    unsigned long order;

    order = npages * sizeof(struct epc_page);
    order >>= 12;
    order = npages_to_order(order);
    printk("%s: npages 0x%lx, epc_frametable order 0x%lx\n", __func__,
            npages, order);

    free_xenheap_pages(epc_frametable, order);
}

void sgx_init(void)
{
    unsigned long npages;

    /* Doesn't support SGX if hardware doesn't support it */
    if ( !(sgx_boot_cpudata->cap & SGX_CAP_SGX1) )
        return;

    INIT_LIST_HEAD(&free_epc_list);
    spin_lock_init(&epc_lock);

    npages = sgx_boot_cpudata->epc_size >> PAGE_SHIFT;
    if ( init_epc_frametable(npages) )
        return;

    free_epc_npages = total_epc_npages = npages;

    sgx_enabled = 1;
}

void sgx_fini(void)
{
    if ( !epc_frametable )
        return;

    fini_epc_frametable(total_epc_npages);
    sgx_enabled = 0;
}

unsigned long epc_page_to_mfn(struct epc_page *epg)
{
    unsigned long epc_base_mfn =
        (unsigned long)(sgx_boot_cpudata->epc_base) >> PAGE_SHIFT;

    BUG_ON(!epc_frametable);
    BUG_ON(!epc_base_mfn);

    return epc_base_mfn + (epg - epc_frametable);
}

struct epc_page *epc_mfn_to_page(unsigned long mfn)
{
    unsigned long epc_base_mfn =
        (unsigned long)(sgx_boot_cpudata->epc_base) >> PAGE_SHIFT;

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

#define to_sgx(d)   (&((d)->arch.hvm_domain.sgx))

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
             * failure or when destroying it, therefore we can just ignore this
             * error.
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

static void hvm_unpopulate_epc(struct domain *d)
{
    struct sgx_domain *sgx = to_sgx(d);

    __hvm_unpopulate_epc(d, sgx->epc_base_pfn, sgx->epc_npages);
}

static int hvm_populate_epc(struct domain *d, unsigned long epc_base_pfn,
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

int hvm_enable_sgx(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages)
{
    struct sgx_domain *sgx = to_sgx(d);
    int ret;

    if ( !hvm_sgx_allowed(d) )
        return -ENODEV;

    if ( hvm_sgx_enabled(d) )
        return -EBUSY;

    if ( !epc_base_pfn || !epc_npages )
        return -EINVAL;

    if ( (ret = hvm_populate_epc(d, epc_base_pfn, epc_npages)) )
        return ret;

    sgx->enabled = 1;
    sgx->epc_base_pfn = epc_base_pfn;
    sgx->epc_npages = epc_npages;

    return 0;
}

void hvm_disable_sgx(struct domain *d)
{
    struct sgx_domain *sgx = to_sgx(d);

    if ( !hvm_sgx_enabled(d) )
        return;

    hvm_unpopulate_epc(d);
    sgx->enabled = 0;
}
