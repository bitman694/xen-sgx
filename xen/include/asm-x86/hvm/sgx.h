/*
 * Intel Software Guard Extensions support
 *
 * Copyright (c) 2016, Intel Corporation.
 *
 * Author: Kai Huang <kai.huang@linux.intel.com>
 */
#ifndef __ASM_X86_HVM_SGX_H__
#define __ASM_X86_HVM_SGX_H__

#include <xen/config.h>
#include <xen/types.h>
#include <xen/init.h>
#include <asm/processor.h>
#include <public/hvm/params.h>   /* HVM_PARAM_SGX */

/*
 * Detect sgx info for particular cpu as sgx info returned by cpuid is
 * per-thread. Called from identify_cpu.
 */
void __init detect_sgx(struct cpuinfo_x86 *c);

struct epc_page;

void sgx_init(void);
void sgx_fini(void);
/*
 * To indicate whether SGX is enabled in Xen. Hardware supports SGX doesn't mean
 * Xen supports exposing SGX to guest.
 */
extern bool_t sgx_enabled;
struct epc_page *alloc_epc_page(void);
void free_epc_page(struct epc_page *epg);
unsigned long epc_page_to_mfn(struct epc_page *epg);
struct epc_page *epc_mfn_to_page(unsigned long mfn);

struct sgx_domain {
    bool_t enabled;
    unsigned long epc_base_pfn;
    unsigned long epc_npages;
};

#define hvm_sgx_allowed(d)  ((d)->arch.hvm_domain.params[HVM_PARAM_SGX])
#define hvm_sgx_enabled(d)  ((d)->arch.hvm_domain.sgx.enabled)

int hvm_enable_sgx(struct domain *d, unsigned long epc_base_pfn,
        unsigned long epc_npages);
void hvm_disable_sgx(struct domain *d);

#endif  /* __ASM_X86_HVM_SGX_H__ */
