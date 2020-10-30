#ifndef PFS
#define PFS

#include "pf_common.h"

#include "13/pf.h"

#define MAXPF                       (50)
#define NUM_SUPPORTED_VERSIONS      (2)

#define PFS_END(x) (x[0].pf_unused == 0x41 && x[1].pf_unused == 0x41)

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
    { PF_END, PF_END },
};

#endif
