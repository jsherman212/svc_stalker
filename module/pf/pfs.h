#ifndef PFS
#define PFS

#include "pf_common.h"

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
 * This array will end with
 * { PF_END, PF_END }
 */
struct pf g_all_pfs[MAXPF][NUM_SUPPORTED_VERSIONS] = {
    {
        /* proc_pid finder callback works on both iOS 13 and iOS 14 */
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
        /* sysent finder callback works on both iOS 13 and iOS 14 */
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
    { PF_END, PF_END },
};

#endif
