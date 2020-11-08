#ifndef PFS
#define PFS

#include "pf_common.h"
#include "ss_patcher.h"

#include "13/pf.h"
#include "14/pf.h"

#define MAXPF                       (50)
#define NUM_SUPPORTED_VERSIONS      (2)

#define PFS_END(x) (x[0].pf_unused == 0x41 && x[1].pf_unused == 0x41)
#define IS_PF_UNUSED(x) (x->pf_unused == 1)

/* Format:
 *
 * { { iOS 13 patchfinder }, { iOS 14 patchfinder } }
 *
 * Not all patchfinders are different across versions.
 *
 * This array will end with
 * { PF_END, PF_END }
 */
struct pf g_all_pfs[MAXPF][NUM_SUPPORTED_VERSIONS] = {
    {
        PF_DECL_FULL("proc_pid finder iOS 13",
            LISTIZE({
                0xb4000000,     /* cbz x0, n */
                0xaa0303fa,     /* mov x26, x3 */
                0xb4000003,     /* cbz x3, n */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            3, XNU_PF_ACCESS_32BIT, proc_pid_finder_13,
            "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("proc_pid finder iOS 14",
            LISTIZE({
                0xb4000000,     /* cbz x0, n */
                0xaa0303f9,     /* mov x25, x3 */
                0xb4000003,     /* cbz x3, n */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            3, XNU_PF_ACCESS_32BIT, proc_pid_finder_13,
            "com.apple.driver.AppleMobileFileIntegrity", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("sysent finder iOS 13",
            LISTIZE({
                0x1a803000,     /* csel Wn, Wn, Wn, cc */
                0x12003c00,     /* and Wn, Wn, 0xffff */
                0x10000000,     /* adrp Xn, n or adr Xn, n */
            }),
            LISTIZE({
                0xffe0fc00,     /* ignore all but condition code */
                0xfffffc00,     /* ignore all but immediate */
                0x1f000000,     /* ignore everything */
            }),
            3, sysent_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysent finder iOS 14",
            LISTIZE({
                0x1a803000,     /* csel Wn, Wn, Wn, cc */
                0x92403c00,     /* and Xn, Xn, 0xffff */
                0x52800300,     /* mov Wn, 0x18 */
            }),
            LISTIZE({
                0xffe0fc00,     /* ignore all but condition code */
                0xfffffc00,     /* ignore all but immediate */
                0xffffffe0,     /* ignore Rd */
            }),
            3, sysent_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("kalloc_canblock finder iOS 13",
            LISTIZE({
                0xaa0003f3,     /* mov x19, x0 */
                0xf90003ff,     /* str xzr, [sp, n] */
                0xf9400000,     /* ldr Xn, [Xn] */
                0xf11fbc1f,     /* cmp Xn, 0x7ef */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffc00000,     /* ignore immediate, Rn, and Rt */
                0xfffffc1f,     /* ignore Rn */
            }),
            4, kalloc_canblock_finder_13, "__TEXT_EXEC"),
        PF_DECL32("kalloc_external finder iOS 14",
            LISTIZE({
                0x79406409,     /* ldrh w9, [x0, 0x32] */
                0xcb080123,     /* sub x3, x9, x8 */
                0x52a001a2,     /* mov w2, 0xd0000 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            3, kalloc_external_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("kfree_addr finder iOS 13",
            LISTIZE({
                0x10000009,     /* adrp x9, n or adr x9, n */
                0x0,            /* ignore this instruction */
                0xfa538002,     /* ccmp Xn, x19, #2, hi */
                0x10000000,     /* adrp Xn, n or adr Xn, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfffffc1f,     /* ignore Xn */
                0x1f000000,     /* ignore everything */
                0x0,            /* ignore this instruction */
            }),
            5, kfree_addr_finder_13, "__TEXT_EXEC"),
        PF_DECL32("kfree_ext finder iOS 14",
            LISTIZE({
                0x54000008,     /* b.hi n */
                0xaa0303e9,     /* mov x9, x3 */
                0xeb08015f,     /* cmp x10, x8 */
                0x54000008,     /* b.hi n */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
            }),
            4, kfree_ext_finder_14, "__TEXT_EXEC"),
    },
    {
        /* iOS 13 patchfinder works fine on iOS 14 */
        PF_DECL32("mach_syscall patcher iOS 13",
            LISTIZE({
                0xb9400000,     /* ldr Wn, [x0] */
                0x7100501f,     /* cmp Wn, 0x14 */
                0x54000001,     /* b.ne n */
                0xb9403a60,     /* ldr Wn, [x19, 0x38] */
            }),
            LISTIZE({
                0xffffffe0,     /* ignore Wn */
                0xfffffc1f,     /* ignore Wn */
                0xff00001f,     /* ignore immediate */
                0xffffffe0,     /* ignore Wn */
            }),
            4, mach_syscall_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("mach_syscall patcher iOS 14",
            LISTIZE({
                0xb9400000,     /* ldr Wn, [x0] */
                0x7100501f,     /* cmp Wn, 0x14 */
                0x54000001,     /* b.ne n */
                0xb9403a60,     /* ldr Wn, [x19, 0x38] */
            }),
            LISTIZE({
                0xffffffe0,     /* ignore Wn */
                0xfffffc1f,     /* ignore Wn */
                0xff00001f,     /* ignore immediate */
                0xffffffe0,     /* ignore Wn */
            }),
            4, mach_syscall_patcher_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("Unused executable code finder iOS 13",
            LISTIZE({
                0xd538d092,     /* mrs x18, tpidr_el1 */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18] */
                0xd61f0240,     /* br x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* match all but immediate */
                0xffc003ff,     /* match all but immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, ExceptionVectorsBase_finder_13, "__TEXT_EXEC"),
        PF_DECL32("Unused executable code finder iOS 14",
            LISTIZE({
                0xd538d092,     /* mrs x18, tpidr_el1 */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18, n] */
                0xf9400252,     /* ldr x18, [x18] */
                0xd61f0240,     /* br x18 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* match all but immediate */
                0xffc003ff,     /* match all but immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, ExceptionVectorsBase_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("sysctl__kern_children finder iOS 13",
            LISTIZE({
                0x10000013,     /* ADRP X19, n or ADR X19, n */
                0x0,            /* ignore this instruction */
                0x10000014,     /* ADRP X20, n or ADR X20, n */
                0x0,            /* ignore this instruction */
                0x10000015,     /* ADRP X21, n or ADR X21, n */
                0x0,            /* ignore this instruction */
                0x10000016,     /* ADRP X22, n or ADR X22, n */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            8, sysctl__kern_children_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysctl__kern_children & sysctl_register_oid finder iOS 14",
            LISTIZE({
                0x9e670260,     /* fmov d0, x19 */
                0x0e205800,     /* cnt v0.8b, v0.8b */
                0x2e303800,     /* uaddlv h0, v0.8b */
                0x1e260008,     /* fmov w8, s0 */
                0x7100827f,     /* cmp w19, 0x20 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            5, sysctl__kern_children_and_register_oid_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("sysctl_register_oid finder iOS 13",
            LISTIZE({
                0xb4000013,     /* cbz x19, n */
                0xf9000013,     /* str x19, [xn, n] */
                0x91002000,     /* add xn, xn, 8 */
                0xf9000260,     /* str xn, [x19, n] */
                0xf9400000,     /* ldr x0, [xn, n] */
                0x94000000,     /* bl n (_sysctl_register_oid) */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc0001f,     /* ignore all but Rt */
                0xfffffc00,     /* only match immediate */
                0xffc003e0,     /* ignore immediate and Rt */
                0xffc0001f,     /* ignore all but Rt */
                0xfc000000,     /* ignore immediate */
            }),
            6, sysctl_register_oid_finder_13, "__TEXT_EXEC"),
        PF_UNUSED,
    },
    {
        PF_DECL_FULL("hook_system_check_sysctlbyname finder iOS 13",
            LISTIZE({
                0x7100101f,     /* cmp wn, 4 */
                0x54000003,     /* b.cc n */
                0xb9400000,     /* ldr wn, [xn] */
                0x7100041f,     /* cmp wn, 1 */
                0x54000001,     /* b.ne n */
                0xb9400400,     /* ldr wn, [xn, 4] */
                0x7100381f,     /* cmp wn, 0xe */
                0x54000001,     /* b.ne n */
            }),
            LISTIZE({
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
            }),
            8, XNU_PF_ACCESS_32BIT, hook_system_check_sysctlbyname_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("hook_system_check_sysctlbyname finder iOS 14",
            LISTIZE({
                0xf100101f,     /* cmp xn, 4 */
                0x54000003,     /* b.cc n */
                0xb9400000,     /* ldr wn, [xn] */
                0x7100041f,     /* cmp wn, 1 */
                0x54000001,     /* b.ne n */
                0xb9400400,     /* ldr wn, [xn, 4] */
                0x7100381f,     /* cmp wn, 0xe */
                0x54000001,     /* b.ne n */
            }),
            LISTIZE({
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
                0xfffffc00,     /* ignore Rn and Rt */
                0xfffffc1f,     /* ignore Rn */
                0xff00001f,     /* ignore immediate */
            }),
            8, XNU_PF_ACCESS_32BIT, hook_system_check_sysctlbyname_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL_FULL("lck_grp_alloc_init finder iOS 13",
            LISTIZE({
                0xf9400260,     /* ldr x0, [x19] */
                0xf9400281,     /* ldr x1, [x20, n] */
                0x94000000,     /* bl n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
            }),
            3, XNU_PF_ACCESS_32BIT, lck_grp_alloc_init_finder_13,
            "com.apple.security.sandbox", "__TEXT_EXEC", NULL),
        PF_DECL_FULL("lck_grp_alloc_init finder iOS 14",
            LISTIZE({
                0x910063e3,     /* add x3, sp, 0x18 */
                0x910023e5,     /* add x5, sp, 0x8 */
                0xaa1303e0,     /* mov x0, x19 */
                0x52800802,     /* mov w2, 0x40 */
                0x52800104,     /* mov w4, 0x8 */
                0xd2800006,     /* mov x6, 0 */
                0xd2800007,     /* mov x7, 0 */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            7, XNU_PF_ACCESS_32BIT, lck_grp_alloc_init_finder_14,
            "com.apple.kec.corecrypto", "__TEXT_EXEC", NULL),
    },
    {
        PF_DECL32("lck_rw_alloc_init finder iOS 13",
            LISTIZE({
                0xd37ced01,     /* lsl x1, x8, #4 */
                0x94000000,     /* bl n (bzero) */
                0x10000008,     /* adrp x8, n or adr x8, n */
                0x0,            /* ignore this instruction */
                0xd2800001,     /* mov x1, 0 */
                0x94000000,     /* bl n (lck_rw_alloc_init) */
                0xf9000260,     /* str x0, [x19, n] */
                0xb5000000,     /* cbnz x0, n */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0x1f00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xff00001f,     /* ignore immediate */
            }),
            8, lck_rw_alloc_init_finder_13, "__TEXT_EXEC"),
        PF_DECL32("lck_rw_alloc_init finder iOS 14",
            LISTIZE({
                0x94000000,     /* bl n (lck_rw_alloc_init) */
                0xf90002a0,     /* str x0, [x21] */
                0xb4000000,     /* cbz x0, n */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0x35000000,     /* cbnz w0, n */
                0x52804000,     /* mov w0, 0x200 */
            }),
            LISTIZE({
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0x0,            /* ignore this instruction */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            7, lck_rw_alloc_init_finder_14, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("unix_syscall patcher iOS 13",
            LISTIZE({
                0xf940469a,     /* ldr x26, [x20, 0x88] */
                0xb500001a,     /* cbnz x26, n */
                0xb9400a9a,     /* ldr w26, [x20, 0x8] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            3, unix_syscall_patcher_13, "__TEXT_EXEC"),
        PF_DECL32("unix_syscall patcher iOS 14",
            LISTIZE({
                0xf940469a,     /* ldr x26, [x20, 0x88] */
                0xb500001a,     /* cbnz x26, n */
                0x7940129a,     /* ldrh w26, [x20, 0x8] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xff00001f,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            3, unix_syscall_patcher_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("sysctl_handle_long finder iOS 13",
            LISTIZE({
                0xb4000001,     /* cbz x1, n */
                0xd10003ff,     /* sub sp, sp, n */
                0xa9004ff4,     /* stp x20, x19, [sp, n] */
                0xa9007bfd,     /* stp x29, x30, [sp, n] */
                0x0,            /* ignore this instruction */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0103f3,     /* mov x19, x1 */
                0xf9400028,     /* ldr x8, [x1] */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            8, sysctl_handle_long_finder_13, "__TEXT_EXEC"),
        PF_DECL32("sysctl_handle_long finder iOS 14",
            LISTIZE({
                0xb4000001,     /* cbz x1, n */
                0xd10003ff,     /* sub sp, sp, n */
                0xa9004ff4,     /* stp x20, x19, [sp, n] */
                0xa9007bfd,     /* stp x29, x30, [sp, n] */
                0x0,            /* ignore this instruction */
                0xaa0303f4,     /* mov x20, x3 */
                0xaa0103f3,     /* mov x19, x1 */
                0xf9400028,     /* ldr x8, [x1] */
            }),
            LISTIZE({
                0xff00001f,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0xffc07fff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            8, sysctl_handle_long_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("name2oid and its dependencies finder iOS 13",
            LISTIZE({
                0x10000000,     /* adrp xn, n or adr xn, n (n = _sysctl_geometry_lock) */
                0xf9400000,     /* ldr x0, [xn, n] */
                0x94000000,     /* bl n (_lck_rw_lock_shared) */
                0x910003e1,     /* add x1, sp, n */
                0x910003e2,     /* add x2, sp, n */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n (_name2oid) */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f000000,     /* ignore everything */
                0xffc0001f,     /* ignore all but Rt */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            8, name2oid_and_its_dependencies_finder_13, "__TEXT_EXEC"),
        PF_DECL32("name2oid and its dependencies finder iOS 14",
            LISTIZE({
                0x10000000,     /* adrp xn, n or adr xn, n (n = _sysctl_geometry_lock) */
                0xf9400000,     /* ldr x0, [xn, n] */
                0x94000000,     /* bl n (_lck_rw_lock_shared) */
                0x910003e1,     /* add x1, sp, n */
                0x910003e2,     /* add x2, sp, n */
                0x0,            /* ignore this instruction */
                0x94000000,     /* bl n (_name2oid) */
                0x0,            /* ignore this instruction */
            }),
            LISTIZE({
                0x1f000000,     /* ignore everything */
                0xffc0001f,     /* ignore all but Rt */
                0xfc000000,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
                0x0,            /* ignore this instruction */
                0xfc000000,     /* ignore immediate */
                0x0,            /* ignore this instruction */
            }),
            8, name2oid_and_its_dependencies_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("thread_exception_return finder iOS 13",
            LISTIZE({
                0xd538d080,     /* mrs x0, tpidr_el1 */
                0x91000015,     /* add x21, x0, n */
                0xf94002b5,     /* ldr x21, [x21] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            3, thread_exception_return_finder_13, "__TEXT_EXEC"),
        PF_DECL32("thread_exception_return finder iOS 14",
            LISTIZE({
                0xd538d080,     /* mrs x0, tpidr_el1 */
                0x91000015,     /* add x21, x0, n */
                0xf94002b5,     /* ldr x21, [x21] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            3, thread_exception_return_finder_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("unix_syscall_return scanner iOS 13",
            LISTIZE({
                0xd538d096,     /* mrs x22, TPIDR_EL1 */
                0x94000000,     /* bl n */
                0xaa0003f4,     /* mov x20, x0 */
                0xf94002d5,     /* ldr x21, [x22, n] */
                0xf94002c1,     /* ldr x1, [x22, n] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            5, unix_syscall_return_scanner_13, "__TEXT_EXEC"),
        PF_DECL32("unix_syscall_return scanner iOS 14",
            LISTIZE({
                0xd538d096,     /* mrs x22, TPIDR_EL1 */
                0x94000000,     /* bl n */
                0xaa0003f4,     /* mov x20, x0 */
                0xf94002d5,     /* ldr x21, [x22, n] */
                0xf94002c1,     /* ldr x1, [x22, n] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffc003ff,     /* ignore immediate */
            }),
            5, unix_syscall_return_scanner_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("thread_syscall_return scanner iOS 13",
            LISTIZE({
                0xa9bf7bfd,     /* stp x29, x30, [sp, -0x10]! */
                0x910003fd,     /* mov x29, sp */
                0xd538d088,     /* mrs x8, TPIDR_EL1 */
                0xf9400109,     /* ldr x9, [x8, n] */
                0x93407c08,     /* sxtw x8, w0 */
                0xf9000528,     /* str x8, [x9, #0x8] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, thread_syscall_return_scanner_13, "__TEXT_EXEC"),
        PF_DECL32("thread_syscall_return scanner iOS 14",
            LISTIZE({
                0xa9bf7bfd,     /* stp x29, x30, [sp, -0x10]! */
                0x910003fd,     /* mov x29, sp */
                0xd538d088,     /* mrs x8, TPIDR_EL1 */
                0xf9400109,     /* ldr x9, [x8, n] */
                0x93407c08,     /* sxtw x8, w0 */
                0xf9000528,     /* str x8, [x9, #0x8] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
                0xffc003ff,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xffffffff,     /* match exactly */
            }),
            6, thread_syscall_return_scanner_13, "__TEXT_EXEC"),
    },
    {
        PF_DECL32("platform_syscall scanner iOS 13",
            LISTIZE({
                0xd538d080,     /* mrs x0, TPIDR_EL1 */
                0x94000000,     /* bl n */
                0x94000000,     /* bl n */
                0xf9000408,     /* str x8, [x0, #8] */
                0x94000000,     /* bl n */
                0xa940d013,     /* ldp x19, x20, [x0, #8] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            6, platform_syscall_scanner_13, "__TEXT_EXEC"),
        PF_DECL32("platform_syscall scanner iOS 14",
            LISTIZE({
                0xd538d080,     /* mrs x0, TPIDR_EL1 */
                0x94000000,     /* bl n */
                0x94000000,     /* bl n */
                0xf9000408,     /* str x8, [x0, #8] */
                0x94000000,     /* bl n */
                0xa940d013,     /* ldp x19, x20, [x0, #8] */
            }),
            LISTIZE({
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
                0xfc000000,     /* ignore immediate */
                0xffffffff,     /* match exactly */
            }),
            6, platform_syscall_scanner_13, "__TEXT_EXEC"),
    },
    { PF_END, PF_END },
};

struct pf stalker_main_patcher_pf[NUM_SUPPORTED_VERSIONS] = {
    PF_DECL32("svc_stalker main patcher iOS 13",
        LISTIZE({
            0xb9408a60,     /* ldr wn, [x19, #0x88] (trap_no = state->__x[16]) */
            0xd538d080,     /* mrs xn, tpidr_el1    (xn = current_thread()) */
            0x12800000,     /* mov wn, 0xffffffff   (wn = throttle_level_none) */
        }),
        LISTIZE({
            0xffffffe0,     /* ignore Wn in LDR */
            0xffffffe0,     /* ignore Xn in MRS */
            0xffffffe0,     /* ignore Wn in MOV */
        }),
        3, stalker_main_patcher, "__TEXT_EXEC"),
    PF_DECL32("svc_stalker main patcher iOS 14",
        LISTIZE({
            0xb9408a60,     /* ldr wn, [x19, #0x88] (trap_no = state->__x[16]) */
            0xd538d080,     /* mrs xn, tpidr_el1    (xn = current_thread()) */
            0x12800000,     /* mov wn, 0xffffffff   (wn = throttle_level_none) */
        }),
        LISTIZE({
            0xffffffe0,     /* ignore Wn in LDR */
            0xffffffe0,     /* ignore Xn in MRS */
            0xffffffe0,     /* ignore Wn in MOV */
        }),
        3, stalker_main_patcher, "__TEXT_EXEC"),
};

#endif
