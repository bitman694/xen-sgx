/*
 * Intel Software Guard Extensions support
 *
 * Copyright (c) 2016, Intel Corporation.
 *
 * Author: Kai Huang <kai.huang@linux.intel.com>
 */
#ifndef __ASM_X86_HVM_VMX_SGX_H__
#define __ASM_X86_HVM_VMX_SGX_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/init.h>
#include <asm/processor.h>
#include <xen/list.h>
#include <public/hvm/params.h>   /* HVM_PARAM_SGX */

#define SGX_CPUID 0x12

/*
 * SGX info reported by SGX CPUID.
 *
 * TODO:
 *
 * SDM (37.7.2 Intel SGX Resource Enumeration Leaves) actually says it's
 * possible there are multiple EPC resources on the machine (CPUID.0x12,
 * ECX starting with 0x2 enumerates available EPC resources until invalid
 * EPC resource is returned). But this is only for multiple socket server,
 * which we current don't support now (there are additional things need to
 * be done as well). So far for simplicity we assume there is only one EPC.
 */
struct sgx_cpuinfo {
#define SGX_CAP_SGX1    (1UL << 0)
#define SGX_CAP_SGX2    (1UL << 1)
    uint32_t cap;
    uint32_t miscselect;
    uint8_t max_enclave_size64;
    uint8_t max_enclave_size32;
    uint32_t secs_attr_bitmask[4];
    uint64_t epc_base;
    uint64_t epc_size;
};

/* Detect SGX info for particular CPU via SGX CPUID */
void detect_sgx(int cpu);

/*
 * EPC page infomation structure. Each EPC has one struct epc_page to keep EPC
 * page info, just like struct page_info for normal memory.
 *
 * So far in reality machine's EPC size won't execeed 100MB, so currently just
 * put all free EPC pages in global free list.
 */
struct epc_page {
    struct list_head list;  /* all free EPC pages are in global free list. */
};

struct epc_page *alloc_epc_page(void);
void free_epc_page(struct epc_page *epg);
unsigned long epc_page_to_mfn(struct epc_page *epg);
struct epc_page *epc_mfn_to_page(unsigned long mfn);
void *map_epc_page_to_xen(struct epc_page *epg);
void unmap_epc_page(void *addr);

struct sgx_domain {
    unsigned long epc_base_pfn;
    unsigned long epc_npages;
};

#define to_sgx(d)   (&((d)->arch.hvm_domain.vmx.sgx))
#define hvm_epc_populated(d)  (!!((d)->arch.hvm_domain.vmx.sgx.epc_base_pfn))

int hvm_populate_epc(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages);
int hvm_reset_epc(struct domain *d, bool_t free_epc);
void hvm_destroy_epc(struct domain *d);

/* Per-vcpu SGX structure */
struct sgx_vcpu {
    uint64_t ia32_sgxlepubkeyhash[4];
    /*
     * Although SDM says if SGX is present, then IA32_SGXLEPUBKEYHASHn are
     * available for read, but in reality for SKYLAKE client machines, those
     * those MSRs are not available if SGX is present.
     */
    bool_t readable;
    bool_t writable;
};
#define to_sgx_vcpu(v)  (&(v->arch.hvm_vmx.sgx))

bool_t sgx_ia32_sgxlepubkeyhash_writable(void);
bool_t domain_has_sgx(struct domain *d);
bool_t domain_has_sgx_launch_control(struct domain *d);

void sgx_vcpu_init(struct vcpu *v);
void sgx_ctxt_switch_to(struct vcpu *v);
int sgx_msr_read_intercept(struct vcpu *v, unsigned int msr, u64 *msr_content);
int sgx_msr_write_intercept(struct vcpu *v, unsigned int msr, u64 msr_content);

#endif  /* __ASM_X86_HVM_VMX_SGX_H__ */
