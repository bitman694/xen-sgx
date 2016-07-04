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

#endif  /* __ASM_X86_HVM_SGX_H__ */
