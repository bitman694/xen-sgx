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
