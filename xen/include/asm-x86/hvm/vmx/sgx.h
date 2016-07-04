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

#endif  /* __ASM_X86_HVM_VMX_SGX_H__ */
