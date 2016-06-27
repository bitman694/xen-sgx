/*
 * arch-x86/xen-sgx.h
 *
 * Xen interface for Intel SGX.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Copyright (c) 2016, Intel Corporation.
 */
#ifndef __XEN_PUBLIC_ARCH_X86_SGX_H__
#define __XEN_PUBLIC_ARCH_X86_SGX_H__

/* New arch specific hypercall for Intel SGX operations. __HYPERVISOR_arch_0
 * is used by Xen x86 machine check, and __HYPERVISOR_arch_1 is used by
 * paging_domctl_continuation, so choose __HYPERVISOR_arch_2 ... */
#define __HYPERVISOR_sgx_op  __HYPERVISOR_arch_2

/*
 * SGX interfaces for EPC:
 *
 *  - XEN_SGX_get_physinfo:
 *      Get platform's physical SGX info. Supposed to be used by xl tools.
 *  - XEN_SGX_get_dominfo:
 *      Get domain's SGX info.
 *  - XEN_SGX_set_dominfo:
 *      Setup domain's SGX info, and populate EPC.
 */
#define XEN_SGX_get_physinfo    0x1
struct xen_sgx_physinfo {
    /* OUT */
    uint64_t phys_epc_npages;
    uint64_t free_epc_npages;
};

typedef struct xen_sgx_physinfo xen_sgx_physinfo_t;
DEFINE_XEN_GUEST_HANDLE(xen_sgx_physinfo_t);

#define XEN_SGX_get_dominfo     0x2
#define XEN_SGX_set_dominfo     0x3
struct xen_sgx_dominfo {
    /* IN */
    domid_t domid;
    /* IN for XEN_SGX_setup_epc; OUT for XEN_SGX_get_dominfo */
    uint64_t epc_base_pfn;
    uint64_t epc_npages;
};

typedef struct xen_sgx_dominfo xen_sgx_dominfo_t;
DEFINE_XEN_GUEST_HANDLE(xen_sgx_dominfo_t);

struct xen_sgx_op {
    int cmd;    /* XEN_SGX_* */
    union {
        struct xen_sgx_physinfo physinfo;
        struct xen_sgx_dominfo dominfo;
    } u;
};
typedef struct xen_sgx_op xen_sgx_op_t;
DEFINE_XEN_GUEST_HANDLE(xen_sgx_op_t);

#endif  /* !__XEN_PUBLIC_ARCH_X86_SGX_H__ */
