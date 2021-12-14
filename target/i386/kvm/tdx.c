/*
 * QEMU TDX support
 *
 * Copyright Intel
 *
 * Author:
 *      Xiaoyao Li <xiaoyao.li@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory
 *
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/kvm.h"

#include "hw/i386/x86.h"
#include "kvm_i386.h"
#include "tdx.h"

#define TDX_SUPPORTED_KVM_FEATURES  ((1ULL << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1ULL << KVM_FEATURE_PV_UNHALT) | \
                                     (1ULL << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1ULL << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1ULL << KVM_FEATURE_POLL_CONTROL) | \
                                     (1ULL << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1ULL << KVM_FEATURE_MSI_EXT_DEST_ID))

static TdxGuest *tdx_guest;

/* It's valid after kvm_confidential_guest_init()->kvm_tdx_init() */
bool is_tdx_vm(void)
{
    return !!tdx_guest;
}

enum tdx_ioctl_level{
    TDX_PLATFORM_IOCTL,
    TDX_VM_IOCTL,
    TDX_VCPU_IOCTL,
};

static int __tdx_ioctl(void *state, enum tdx_ioctl_level level, int cmd_id,
                        __u32 flags, void *data)
{
    struct kvm_tdx_cmd tdx_cmd;
    int r;

    memset(&tdx_cmd, 0x0, sizeof(tdx_cmd));

    tdx_cmd.id = cmd_id;
    tdx_cmd.flags = flags;
    tdx_cmd.data = (__u64)(unsigned long)data;

    switch (level) {
    case TDX_PLATFORM_IOCTL:
        r = kvm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VM_IOCTL:
        r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    case TDX_VCPU_IOCTL:
        r = kvm_vcpu_ioctl(state, KVM_MEMORY_ENCRYPT_OP, &tdx_cmd);
        break;
    default:
        error_report("Invalid tdx_ioctl_level %d", level);
        exit(1);
    }

    return r;
}

static inline int tdx_platform_ioctl(int cmd_id, __u32 flags, void *data)
{
    return __tdx_ioctl(NULL, TDX_PLATFORM_IOCTL, cmd_id, flags, data);
}

static inline int tdx_vm_ioctl(int cmd_id, __u32 flags, void *data)
{
    return __tdx_ioctl(NULL, TDX_VM_IOCTL, cmd_id, flags, data);
}

static inline int tdx_vcpu_ioctl(void *vcpu_fd, int cmd_id, __u32 flags,
                                 void *data)
{
    return  __tdx_ioctl(vcpu_fd, TDX_VCPU_IOCTL, cmd_id, flags, data);
}

static struct kvm_tdx_capabilities *tdx_caps;

static void get_tdx_capabilities(void)
{
    struct kvm_tdx_capabilities *caps;
    /* 1st generation of TDX reports 6 cpuid configs */
    int nr_cpuid_configs = 6;
    int r, size;

    do {
        size = sizeof(struct kvm_tdx_capabilities) +
               nr_cpuid_configs * sizeof(struct kvm_tdx_cpuid_config);
        caps = g_malloc0(size);
        caps->nr_cpuid_configs = nr_cpuid_configs;

        r = tdx_platform_ioctl(KVM_TDX_CAPABILITIES, 0, caps);
        if (r == -E2BIG) {
            g_free(caps);
            nr_cpuid_configs *= 2;
            if (nr_cpuid_configs > KVM_MAX_CPUID_ENTRIES) {
                error_report("KVM TDX seems broken");
                exit(1);
            }
        } else if (r < 0) {
            g_free(caps);
            error_report("KVM_TDX_CAPABILITIES failed: %s\n", strerror(-r));
            exit(1);
        }
    }
    while (r == -E2BIG);

    tdx_caps = caps;
}

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (!tdx_caps) {
        get_tdx_capabilities();
    }

    tdx_guest = tdx;

    return 0;
}

void tdx_get_supported_cpuid(uint32_t function, uint32_t index, int reg,
                             uint32_t *ret)
{
    switch (function) {
    case 1:
        if (reg == R_ECX) {
            *ret &= ~CPUID_EXT_VMX;
        }
        break;
    case 0xd:
        if (index == 0) {
            if (reg == R_EAX) {
                *ret &= (uint32_t)tdx_caps->xfam_fixed0 & CPUID_XSTATE_XCR0_MASK;
                *ret |= (uint32_t)tdx_caps->xfam_fixed1 & CPUID_XSTATE_XCR0_MASK;
            } else if (reg == R_EDX) {
                *ret &= (tdx_caps->xfam_fixed0 & CPUID_XSTATE_XCR0_MASK) >> 32;
                *ret |= (tdx_caps->xfam_fixed1 & CPUID_XSTATE_XCR0_MASK) >> 32;
            }
        } else if (index == 1) {
            if (reg == R_ECX) {
                *ret &= (uint32_t)tdx_caps->xfam_fixed0 & CPUID_XSTATE_XSS_MASK;
                *ret |= (uint32_t)tdx_caps->xfam_fixed1 & CPUID_XSTATE_XSS_MASK;
            } else if (reg == R_EDX) {
                *ret &= (tdx_caps->xfam_fixed0 & CPUID_XSTATE_XSS_MASK) >> 32;
                *ret |= (tdx_caps->xfam_fixed1 & CPUID_XSTATE_XSS_MASK) >> 32;
            }
        }
        break;
    case KVM_CPUID_FEATURES:
        if (reg == R_EAX) {
            *ret &= TDX_SUPPORTED_KVM_FEATURES;
        }
        break;
    default:
        /* TODO: Use tdx_caps to adjust CPUID leafs. */
        break;
    }
}

/* tdx guest */
OBJECT_DEFINE_TYPE_WITH_INTERFACES(TdxGuest,
                                   tdx_guest,
                                   TDX_GUEST,
                                   CONFIDENTIAL_GUEST_SUPPORT,
                                   { TYPE_USER_CREATABLE },
                                   { NULL })

static void tdx_guest_init(Object *obj)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    tdx->attributes = 0;
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}
