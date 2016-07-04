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

#endif  /* __ASM_X86_HVM_SGX_H__ */
