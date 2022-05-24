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
#include "qemu/mmap-alloc.h"
#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "standard-headers/asm-x86/kvm_para.h"
#include "sysemu/kvm.h"
#include "sysemu/sysemu.h"

#include "exec/address-spaces.h"
#include "hw/i386/apic_internal.h"
#include "hw/i386/e820_memory_layout.h"
#include "hw/i386/x86.h"
#include "hw/i386/tdvf.h"
#include "hw/i386/tdvf-hob.h"
#include "kvm_i386.h"
#include "tdx.h"

#define TDX_SUPPORTED_KVM_FEATURES  ((1ULL << KVM_FEATURE_NOP_IO_DELAY) | \
                                     (1ULL << KVM_FEATURE_PV_UNHALT) | \
                                     (1ULL << KVM_FEATURE_PV_TLB_FLUSH) | \
                                     (1ULL << KVM_FEATURE_PV_SEND_IPI) | \
                                     (1ULL << KVM_FEATURE_POLL_CONTROL) | \
                                     (1ULL << KVM_FEATURE_PV_SCHED_YIELD) | \
                                     (1ULL << KVM_FEATURE_MSI_EXT_DEST_ID))

#define TDX_TD_ATTRIBUTES_DEBUG             BIT_ULL(0)
#define TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE   BIT_ULL(28)
#define TDX_TD_ATTRIBUTES_PKS               BIT_ULL(30)
#define TDX_TD_ATTRIBUTES_PERFMON           BIT_ULL(63)

#define TDX_MIN_TSC_FREQUENCY_KHZ   (100 * 1000)
#define TDX_MAX_TSC_FREQUENCY_KHZ   (10 * 1000 * 1000)

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

static TdxFirmwareEntry *tdx_get_hob_entry(TdxGuest *tdx)
{
    TdxFirmwareEntry *entry;

    for_each_tdx_fw_entry(&tdx->tdvf, entry) {
        if (entry->type == TDVF_SECTION_TYPE_TD_HOB) {
            return entry;
        }
    }
    error_report("TDVF metadata doesn't specify TD_HOB location.");
    exit(1);
}

static void tdx_add_ram_entry(uint64_t address, uint64_t length, uint32_t type)
{
    uint32_t nr_entries = tdx_guest->nr_ram_entries;
    tdx_guest->ram_entries = g_renew(TdxRamEntry, tdx_guest->ram_entries,
                                     nr_entries + 1);

    tdx_guest->ram_entries[nr_entries].address = address;
    tdx_guest->ram_entries[nr_entries].length = length;
    tdx_guest->ram_entries[nr_entries].type = type;
    tdx_guest->nr_ram_entries++;
}

static int tdx_accept_ram_range(uint64_t address, uint64_t length)
{
    uint64_t head_start, tail_start, head_length, tail_length;
    uint64_t tmp_address, tmp_length;
    TdxRamEntry *e;
    int i;

    for (i = 0; i < tdx_guest->nr_ram_entries; i++) {
        e = &tdx_guest->ram_entries[i];

        if (address + length < e->address ||
            e->address + e->length < address) {
                continue;
        }

        /*
         * The to-be-accepted ram range must be fully contained by one
         * RAM entry.
         */
        if (e->address > address ||
            e->address + e->length < address + length) {
            return -EINVAL;
        }

        if (e->type == TDX_RAM_ADDED) {
            return -EINVAL;
        }

        break;
    }

    if (i == tdx_guest->nr_ram_entries) {
        return -1;
    }

    tmp_address = e->address;
    tmp_length = e->length;

    e->address = address;
    e->length = length;
    e->type = TDX_RAM_ADDED;

    head_length = address - tmp_address;
    if (head_length > 0) {
        head_start = tmp_address;
        tdx_add_ram_entry(head_start, head_length, TDX_RAM_UNACCEPTED);
    }

    tail_start = address + length;
    if (tail_start < tmp_address + tmp_length) {
        tail_length = tmp_address + tmp_length - tail_start;
        tdx_add_ram_entry(tail_start, tail_length, TDX_RAM_UNACCEPTED);
    }

    return 0;
}

static int tdx_ram_entry_compare(const void *lhs_, const void* rhs_)
{
    const TdxRamEntry *lhs = lhs_;
    const TdxRamEntry *rhs = rhs_;

    if (lhs->address == rhs->address) {
        return 0;
    }
    if (le64_to_cpu(lhs->address) > le64_to_cpu(rhs->address)) {
        return 1;
    }
    return -1;
}

static void tdx_init_ram_entries(void)
{
    unsigned i, j, nr_e820_entries;

    nr_e820_entries = e820_get_num_entries();
    tdx_guest->ram_entries = g_new(TdxRamEntry, nr_e820_entries);

    for (i = 0, j = 0; i < nr_e820_entries; i++) {
        uint64_t addr, len;

        if (e820_get_entry(i, E820_RAM, &addr, &len)) {
            tdx_guest->ram_entries[j].address = addr;
            tdx_guest->ram_entries[j].length = len;
            tdx_guest->ram_entries[j].type = TDX_RAM_UNACCEPTED;
            j++;
        }
    }
    tdx_guest->nr_ram_entries = j;
}

static void tdx_post_init_vcpus(void)
{
    TdxFirmwareEntry *hob;
    CPUState *cpu;
    int r;

    hob = tdx_get_hob_entry(tdx_guest);
    CPU_FOREACH(cpu) {
        apic_force_x2apic(X86_CPU(cpu)->apic_state);

        r = tdx_vcpu_ioctl(cpu, KVM_TDX_INIT_VCPU, 0, (void *)hob->address);
        if (r < 0) {
            error_report("KVM_TDX_INIT_VCPU failed %s", strerror(-r));
            exit(1);
        }
    }
}

static void tdx_finalize_vm(Notifier *notifier, void *unused)
{
    TdxFirmware *tdvf = &tdx_guest->tdvf;
    TdxFirmwareEntry *entry;
    int r;

    tdx_init_ram_entries();

    for_each_tdx_fw_entry(tdvf, entry) {
        switch (entry->type) {
        case TDVF_SECTION_TYPE_BFV:
        case TDVF_SECTION_TYPE_CFV:
            entry->mem_ptr = tdvf->mem_ptr + entry->data_offset;
            break;
        case TDVF_SECTION_TYPE_TD_HOB:
        case TDVF_SECTION_TYPE_TEMP_MEM:
            entry->mem_ptr = qemu_ram_mmap(-1, entry->size,
                                           qemu_real_host_page_size(), 0, 0);
            tdx_accept_ram_range(entry->address, entry->size);
            break;
        default:
            error_report("Unsupported TDVF section %d", entry->type);
            exit(1);
        }
    }

    qsort(tdx_guest->ram_entries, tdx_guest->nr_ram_entries,
          sizeof(TdxRamEntry), &tdx_ram_entry_compare);

    tdvf_hob_create(tdx_guest, tdx_get_hob_entry(tdx_guest));

    tdx_post_init_vcpus();

    for_each_tdx_fw_entry(tdvf, entry) {
        struct kvm_tdx_init_mem_region mem_region = {
            .source_addr = (__u64)entry->mem_ptr,
            .gpa = entry->address,
            .nr_pages = entry->size / 4096,
        };

        __u32 flags = entry->attributes & TDVF_SECTION_ATTRIBUTES_MR_EXTEND ?
                      KVM_TDX_MEASURE_MEMORY_REGION : 0;

        r = tdx_vm_ioctl(KVM_TDX_INIT_MEM_REGION, flags, &mem_region);
        if (r < 0) {
             error_report("KVM_TDX_INIT_MEM_REGION failed %s", strerror(-r));
             exit(1);
        }

        if (entry->type == TDVF_SECTION_TYPE_TD_HOB ||
            entry->type == TDVF_SECTION_TYPE_TEMP_MEM) {
            qemu_ram_munmap(-1, entry->mem_ptr, entry->size);
            entry->mem_ptr = NULL;
        }
    }

    r = tdx_vm_ioctl(KVM_TDX_FINALIZE_VM, 0, NULL);
    if (r < 0) {
        error_report("KVM_TDX_FINALIZE_VM failed %s", strerror(-r));
        exit(0);
    }
    tdx_guest->parent_obj.ready = true;
}

static Notifier tdx_machine_done_notify = {
    .notify = tdx_finalize_vm,
};

int tdx_kvm_init(MachineState *ms, Error **errp)
{
    X86MachineState *x86ms = X86_MACHINE(ms);
    TdxGuest *tdx = (TdxGuest *)object_dynamic_cast(OBJECT(ms->cgs),
                                                    TYPE_TDX_GUEST);

    if (x86ms->smm == ON_OFF_AUTO_AUTO) {
        x86ms->smm = ON_OFF_AUTO_OFF;
    } else if (x86ms->smm == ON_OFF_AUTO_ON) {
        error_setg(errp, "TDX VM doesn't support SMM");
        return -EINVAL;
    }

    if (x86ms->pic == ON_OFF_AUTO_AUTO) {
        x86ms->pic = ON_OFF_AUTO_OFF;
    } else if (x86ms->pic == ON_OFF_AUTO_ON) {
        error_setg(errp, "TDX VM doesn't support PIC");
        return -EINVAL;
    }

    x86ms->eoi_intercept_unsupported = true;

    if (!tdx_caps) {
        get_tdx_capabilities();
    }

    /*
     * Set kvm_readonly_mem_allowed to false, because TDX only supports readonly
     * memory for shared memory but not for private memory. Besides, whether a
     * memslot is private or shared is not determined by QEMU.
     *
     * Thus, just mark readonly memory not supported for simplicity.
     */
    kvm_readonly_mem_allowed = false;

    qemu_add_machine_init_done_notifier(&tdx_machine_done_notify);

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

static int tdx_validate_attributes(TdxGuest *tdx)
{
    if (((tdx->attributes & tdx_caps->attrs_fixed0) | tdx_caps->attrs_fixed1) !=
        tdx->attributes) {
            error_report("Invalid attributes 0x%lx for TDX VM (fixed0 0x%llx, fixed1 0x%llx)",
                          tdx->attributes, tdx_caps->attrs_fixed0, tdx_caps->attrs_fixed1);
            return -EINVAL;
    }

    /*
    if (tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG) {
        error_report("Current QEMU doesn't support attributes.debug[bit 0] for TDX VM");
        return -EINVAL;
    }
    */

    return 0;
}

static int setup_td_guest_attributes(X86CPU *x86cpu)
{
    CPUX86State *env = &x86cpu->env;

    tdx_guest->attributes |= (env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS) ?
                             TDX_TD_ATTRIBUTES_PKS : 0;
    tdx_guest->attributes |= x86cpu->enable_pmu ? TDX_TD_ATTRIBUTES_PERFMON : 0;

    return tdx_validate_attributes(tdx_guest);
}

int tdx_pre_create_vcpu(CPUState *cpu)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    X86CPU *x86cpu = X86_CPU(cpu);
    CPUX86State *env = &x86cpu->env;
    struct kvm_tdx_init_vm init_vm;
    int r = 0;

    qemu_mutex_lock(&tdx_guest->lock);
    if (tdx_guest->initialized) {
        goto out;
    }

    r = -EINVAL;
    if (env->tsc_khz && (env->tsc_khz < TDX_MIN_TSC_FREQUENCY_KHZ ||
                         env->tsc_khz > TDX_MAX_TSC_FREQUENCY_KHZ)) {
        error_report("Invalid TSC %ld KHz, must specify cpu_frequency between [%d, %d] kHz",
                      env->tsc_khz, TDX_MIN_TSC_FREQUENCY_KHZ,
                      TDX_MAX_TSC_FREQUENCY_KHZ);
        goto out;
    }

    if (env->tsc_khz % (25 * 1000)) {
        error_report("Invalid TSC %ld KHz, it must be multiple of 25MHz", env->tsc_khz);
        goto out;
    }

    r = kvm_vm_ioctl(kvm_state, KVM_SET_TSC_KHZ, env->tsc_khz);
    if (r < 0) {
        error_report("Unable to set TSC frequency to %" PRId64 " kHz", env->tsc_khz);
        goto out;
    }

    r = setup_td_guest_attributes(x86cpu);
    if (r) {
        goto out;
    }

    memset(&init_vm, 0, sizeof(init_vm));
    init_vm.cpuid.nent = kvm_x86_arch_cpuid(env, init_vm.entries, 0);

    init_vm.attributes = tdx_guest->attributes;
    init_vm.max_vcpus = ms->smp.cpus;

    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrconfigid) != sizeof(tdx_guest->mrconfigid));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrowner) != sizeof(tdx_guest->mrowner));
    QEMU_BUILD_BUG_ON(sizeof(init_vm.mrownerconfig) != sizeof(tdx_guest->mrownerconfig));
    memcpy(init_vm.mrconfigid, tdx_guest->mrconfigid, sizeof(init_vm.mrconfigid));
    memcpy(init_vm.mrowner, tdx_guest->mrowner, sizeof(init_vm.mrowner));
    memcpy(init_vm.mrownerconfig, tdx_guest->mrownerconfig, sizeof(init_vm.mrownerconfig));

    r = tdx_vm_ioctl(KVM_TDX_INIT_VM, 0, &init_vm);
    if (r < 0) {
        error_report("KVM_TDX_INIT_VM failed %s", strerror(-r));
        goto out;
    }

    tdx_guest->initialized = true;

out:
    qemu_mutex_unlock(&tdx_guest->lock);
    return r;
}
int tdx_parse_tdvf(void *flash_ptr, int size)
{
    return tdvf_parse_metadata(&tdx_guest->tdvf, flash_ptr, size);
}

static bool tdx_guest_get_sept_ve_disable(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return !!(tdx->attributes & TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE);
}

static void tdx_guest_set_sept_ve_disable(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    if (value) {
        tdx->attributes |= TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    } else {
        tdx->attributes &= ~TDX_TD_ATTRIBUTES_SEPT_VE_DISABLE;
    }
}

static bool tdx_guest_get_debug(Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    return !!(tdx->attributes & TDX_TD_ATTRIBUTES_DEBUG);
}

static void tdx_guest_set_debug(Object *obj, bool value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);

    if (value) {
        tdx->attributes |= TDX_TD_ATTRIBUTES_DEBUG;
    } else {
        tdx->attributes &= ~TDX_TD_ATTRIBUTES_DEBUG;
    }
}

static char *tdx_guest_get_quote_generation(
    Object *obj, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    return g_strdup(tdx->quote_generation_str);
}

static void tdx_guest_set_quote_generation(
    Object *obj, const char *value, Error **errp)
{
    TdxGuest *tdx = TDX_GUEST(obj);
    tdx->quote_generation = socket_parse(value, errp);
    if (!tdx->quote_generation)
        return;

    g_free(tdx->quote_generation_str);
    tdx->quote_generation_str = g_strdup(value);
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

    qemu_mutex_init(&tdx->lock);

    tdx->attributes = 0;

    object_property_add_bool(obj, "sept-ve-disable",
                             tdx_guest_get_sept_ve_disable,
                             tdx_guest_set_sept_ve_disable);
    object_property_add_bool(obj, "debug",
                             tdx_guest_get_debug,
                             tdx_guest_set_debug);
    object_property_add_sha384(obj, "mrconfigid", tdx->mrconfigid,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrowner", tdx->mrowner,
                               OBJ_PROP_FLAG_READWRITE);
    object_property_add_sha384(obj, "mrownerconfig", tdx->mrownerconfig,
                               OBJ_PROP_FLAG_READWRITE);

    tdx->quote_generation_str = NULL;
    tdx->quote_generation = NULL;
    object_property_add_str(obj, "quote-generation-service",
                            tdx_guest_get_quote_generation,
                            tdx_guest_set_quote_generation);

    tdx->event_notify_interrupt = -1;
}

static void tdx_guest_finalize(Object *obj)
{
}

static void tdx_guest_class_init(ObjectClass *oc, void *data)
{
}

#define TDG_VP_VMCALL_GET_QUOTE                         0x10002ULL
#define TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT      0x10004ULL

#define TDG_VP_VMCALL_SUCCESS           0x0000000000000000ULL
#define TDG_VP_VMCALL_RETRY             0x0000000000000001ULL
#define TDG_VP_VMCALL_INVALID_OPERAND   0x8000000000000000ULL
#define TDG_VP_VMCALL_ALIGN_ERROR       0x8000000000000002ULL

#define TDX_GET_QUOTE_STRUCTURE_VERSION 1ULL

#define TDX_VP_GET_QUOTE_SUCCESS                0ULL
#define TDX_VP_GET_QUOTE_IN_FLIGHT              (-1ULL)
#define TDX_VP_GET_QUOTE_ERROR                  0x8000000000000000ULL
#define TDX_VP_GET_QUOTE_QGS_UNAVAILABLE        0x8000000000000001ULL

/* Limit to avoid resource starvation. */
#define TDX_GET_QUOTE_MAX_BUF_LEN       (128 * 1024)
#define TDX_MAX_GET_QUOTE_REQUEST       16

/* Format of pages shared with guest. */
struct tdx_get_quote_header {
    /* Format version: must be 1 in little endian. */
    uint64_t structure_version;

    /*
     * GetQuote status code in little endian:
     *   Guest must set error_code to 0 to avoid information leak.
     *   Qemu sets this before interrupting guest.
     */
    uint64_t error_code;

    /*
     * in-message size in little endian: The message will follow this header.
     * The in-message will be send to QGS.
     */
    uint32_t in_len;

    /*
     * out-message size in little endian:
     * On request, out_len must be zero to avoid information leak.
     * On return, message size from QGS. Qemu overwrites this field.
     * The message will follows this header.  The in-message is overwritten.
     */
    uint32_t out_len;

    /*
     * Message buffer follows.
     * Guest sets message that will be send to QGS.  If out_len > in_len, guest
     * should zero remaining buffer to avoid information leak.
     * Qemu overwrites this buffer with a message returned from QGS.
     */
};

struct tdx_get_quote_task {
    uint32_t apic_id;
    hwaddr gpa;
    uint64_t buf_len;
    struct tdx_get_quote_header hdr;
    int event_notify_interrupt;
    QIOChannelSocket *ioc;
};

struct x86_msi {
    union {
        struct {
            uint32_t    reserved_0              : 2,
                        dest_mode_logical       : 1,
                        redirect_hint           : 1,
                        reserved_1              : 1,
                        virt_destid_8_14        : 7,
                        destid_0_7              : 8,
                        base_address            : 12;
        } QEMU_PACKED x86_address_lo;
        uint32_t address_lo;
    };
    union {
        struct {
            uint32_t    reserved        : 8,
                        destid_8_31     : 24;
        } QEMU_PACKED x86_address_hi;
        uint32_t address_hi;
    };
    union {
        struct {
            uint32_t    vector                  : 8,
                        delivery_mode           : 3,
                        dest_mode_logical       : 1,
                        reserved                : 2,
                        active_low              : 1,
                        is_level                : 1;
        } QEMU_PACKED x86_data;
        uint32_t data;
    };
};

static void tdx_td_notify(struct tdx_get_quote_task *t)
{
    struct x86_msi x86_msi;
    struct kvm_msi msi;
    int ret;

    /* It is optional for host VMM to interrupt TD. */
    if(!(32 <= t->event_notify_interrupt && t->event_notify_interrupt <= 255))
        return;

    x86_msi = (struct x86_msi) {
        .x86_address_lo  = {
            .reserved_0 = 0,
            .dest_mode_logical = 0,
            .redirect_hint = 0,
            .reserved_1 = 0,
            .virt_destid_8_14 = 0,
            .destid_0_7 = t->apic_id & 0xff,
        },
        .x86_address_hi = {
            .reserved = 0,
            .destid_8_31 = t->apic_id >> 8,
        },
        .x86_data = {
            .vector = t->event_notify_interrupt,
            .delivery_mode = APIC_DM_FIXED,
            .dest_mode_logical = 0,
            .reserved = 0,
            .active_low = 0,
            .is_level = 0,
        },
    };
    msi = (struct kvm_msi) {
        .address_lo = x86_msi.address_lo,
        .address_hi = x86_msi.address_hi,
        .data = x86_msi.data,
        .flags = 0,
        .devid = 0,
    };
    ret = kvm_vm_ioctl(kvm_state, KVM_SIGNAL_MSI, &msi);
    if (ret < 0) {
        /* In this case, no better way to tell it to guest.  Log it. */
        error_report("TDX: injection %d failed, interrupt lost (%s).\n",
                     t->event_notify_interrupt, strerror(-ret));
    }
}

/*
 * TODO: If QGS doesn't reply for long time, make it an error and interrupt
 * guest.
 */
static void tdx_handle_get_quote_connected(QIOTask *task, gpointer opaque)
{
    struct tdx_get_quote_task *t = opaque;
    Error *err = NULL;
    char *in_data = NULL;
    char *out_data = NULL;
    size_t out_len;
    ssize_t size;
    MachineState *ms;
    TdxGuest *tdx;

    t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_ERROR);
    if (qio_task_propagate_error(task, NULL)) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }

    in_data = g_malloc(le32_to_cpu(t->hdr.in_len));
    if (address_space_read(&address_space_memory, t->gpa + sizeof(t->hdr),
                           MEMTXATTRS_UNSPECIFIED, in_data,
                           le32_to_cpu(t->hdr.in_len)) != MEMTX_OK) {
        goto error;
    }

    if (qio_channel_write_all(QIO_CHANNEL(t->ioc), in_data,
                              le32_to_cpu(t->hdr.in_len), &err) ||
        err) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }

    out_data = g_malloc(t->buf_len);
    out_len = 0;
    size = 0;
    while (true) {
        char *buf;
        size_t buf_size;

        if (out_len < t->buf_len) {
            buf = out_data + out_len;
            buf_size = t->buf_len - out_len;
        } else {
            /*
             * The received data is too large to fit in the shared GPA.
             * Discard the received data and try to know the data size.
             */
            buf = out_data;
            buf_size = t->buf_len;
        }

        size = qio_channel_read(QIO_CHANNEL(t->ioc), buf, buf_size, &err);
        if (err) {
            break;
        }
        if (size <= 0) {
            break;
        }
        out_len += size;
    }
    /*
     * Treat partial read as success and let the QGS client to handle it because
     * the client knows better about the QGS.
     */
    if (out_len == 0 && (err || size < 0)) {
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_QGS_UNAVAILABLE);
        goto error;
    }
    if (out_len > 0 && out_len > t->buf_len) {
        /*
         * There is no specific error code defined for this case(E2BIG) at the
         * moment.
         * TODO: Once an error code for this case is defined in GHCI spec ,
         * update the error code.
         */
        t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_ERROR);
        t->hdr.out_len = cpu_to_le32(out_len);
        goto error_hdr;
    }

    if (address_space_write(
            &address_space_memory, t->gpa + sizeof(t->hdr),
            MEMTXATTRS_UNSPECIFIED, out_data, out_len) != MEMTX_OK) {
        goto error;
    }
    /*
     * Even if out_len == 0, it's a success.  It's up to the QGS-client contract
     * how to interpret the zero-sized message as return message.
     */
    t->hdr.out_len = cpu_to_le32(out_len);
    t->hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_SUCCESS);

error:
    if (t->hdr.error_code != cpu_to_le64(TDX_VP_GET_QUOTE_SUCCESS)) {
        t->hdr.out_len = cpu_to_le32(0);
    }
error_hdr:
    if (address_space_write(
            &address_space_memory, t->gpa,
            MEMTXATTRS_UNSPECIFIED, &t->hdr, sizeof(t->hdr)) != MEMTX_OK) {
        error_report("TDX: failed to updsate GetQuote header.\n");
    }
    tdx_td_notify(t);

    qio_channel_close(QIO_CHANNEL(t->ioc), &err);
    object_unref(OBJECT(t->ioc));
    g_free(in_data);
    g_free(out_data);

    /* Maintain the number of in-flight requests. */
    ms = MACHINE(qdev_get_machine());
    tdx = TDX_GUEST(ms->cgs);
    qemu_mutex_lock(&tdx->lock);
    tdx->quote_generation_num--;
    qemu_mutex_unlock(&tdx->lock);

    return;
}

static void tdx_handle_get_quote(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    hwaddr gpa = vmcall->in_r12;
    uint64_t buf_len = vmcall->in_r13;
    struct tdx_get_quote_header hdr;
    MachineState *ms;
    TdxGuest *tdx;
    QIOChannelSocket *ioc;
    struct tdx_get_quote_task *t;

    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    if (!QEMU_IS_ALIGNED(gpa, 4096) || !QEMU_IS_ALIGNED(buf_len, 4096)) {
        vmcall->status_code = TDG_VP_VMCALL_ALIGN_ERROR;
        return;
    }
    if (buf_len == 0) {
        return;
    }

    if (address_space_read(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                           &hdr, sizeof(hdr)) != MEMTX_OK) {
        return;
    }
    if (le64_to_cpu(hdr.structure_version) != TDX_GET_QUOTE_STRUCTURE_VERSION) {
        return;
    }
    /*
     * Paranoid: Guest should clear error_code and out_len to avoid information
     * leak.  Enforce it.  The initial value of them doesn't matter for qemu to
     * process the request.
     */
    if (le64_to_cpu(hdr.error_code) != TDX_VP_GET_QUOTE_SUCCESS ||
        le32_to_cpu(hdr.out_len) != 0) {
        return;
    }

    /* Only safe-guard check to avoid too large buffer size. */
    if (buf_len > TDX_GET_QUOTE_MAX_BUF_LEN ||
        le32_to_cpu(hdr.in_len) > TDX_GET_QUOTE_MAX_BUF_LEN ||
        le32_to_cpu(hdr.in_len) > buf_len) {
        return;
    }

    /* Mark the buffer in-flight. */
    hdr.error_code = cpu_to_le64(TDX_VP_GET_QUOTE_IN_FLIGHT);
    if (address_space_write(&address_space_memory, gpa, MEMTXATTRS_UNSPECIFIED,
                            &hdr, sizeof(hdr)) != MEMTX_OK) {
        return;
    }

    ms = MACHINE(qdev_get_machine());
    tdx = TDX_GUEST(ms->cgs);
    ioc = qio_channel_socket_new();

    t = g_malloc(sizeof(*t));
    t->apic_id = cpu->apic_id;
    t->gpa = gpa;
    t->buf_len = buf_len;
    t->hdr = hdr;
    t->ioc = ioc;

    qemu_mutex_lock(&tdx->lock);
    /*
     * If Quote Generation Service(QGS) isn't unavailable, return RETRY in the
     * expectation that the cloud admin will set later.
     */
    if (!tdx->quote_generation ||
        /* Prevent too many in-flight get-quote request. */
        tdx->quote_generation_num >= TDX_MAX_GET_QUOTE_REQUEST) {
        qemu_mutex_unlock(&tdx->lock);
        vmcall->status_code = TDG_VP_VMCALL_RETRY;
        object_unref(OBJECT(ioc));
        g_free(t);
        return;
    }
    tdx->quote_generation_num++;
    t->event_notify_interrupt = tdx->event_notify_interrupt;
    qio_channel_socket_connect_async(
        ioc, tdx->quote_generation, tdx_handle_get_quote_connected, t, g_free,
        NULL);
    qemu_mutex_unlock(&tdx->lock);

    vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
}

static void tdx_handle_setup_event_notify_interrupt(struct kvm_tdx_vmcall *vmcall)
{
    MachineState *ms = MACHINE(qdev_get_machine());
    TdxGuest *tdx = TDX_GUEST(ms->cgs);
    int event_notify_interrupt = vmcall->in_r12;

    if (32 <= event_notify_interrupt && event_notify_interrupt <= 255) {
        qemu_mutex_lock(&tdx->lock);
        tdx->event_notify_interrupt = event_notify_interrupt;
        qemu_mutex_unlock(&tdx->lock);
        vmcall->status_code = TDG_VP_VMCALL_SUCCESS;
    }
}

static void tdx_handle_vmcall(X86CPU *cpu, struct kvm_tdx_vmcall *vmcall)
{
    vmcall->status_code = TDG_VP_VMCALL_INVALID_OPERAND;

    /* For now handle only TDG.VP.VMCALL. */
    if (vmcall->type != 0) {
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        return;
    }

    switch (vmcall->subfunction) {
    case TDG_VP_VMCALL_GET_QUOTE:
        tdx_handle_get_quote(cpu, vmcall);
        break;
    case TDG_VP_VMCALL_SETUP_EVENT_NOTIFY_INTERRUPT:
        tdx_handle_setup_event_notify_interrupt(vmcall);
        break;
    default:
        warn_report("unknown tdg.vp.vmcall type 0x%llx subfunction 0x%llx",
                    vmcall->type, vmcall->subfunction);
        break;
    }
}

void tdx_handle_exit(X86CPU *cpu, struct kvm_tdx_exit *tdx_exit)
{
    switch (tdx_exit->type) {
    case KVM_EXIT_TDX_VMCALL:
        tdx_handle_vmcall(cpu, &tdx_exit->u.vmcall);
        break;
    default:
        warn_report("unknown tdx exit type 0x%x", tdx_exit->type);
        break;
    }
}
