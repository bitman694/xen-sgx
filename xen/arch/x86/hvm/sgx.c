/*
 * Intel Software Guard Extensions support
 *
 * Author: Kai Huang <kai.huang@linux.intel.com>
 */

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
