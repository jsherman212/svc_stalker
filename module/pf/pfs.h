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
        PF_DECL_FULL("proc_pid finder ios13",
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
        PF_DECL_FULL("proc_pid finder ios14",
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
    { PF_END, PF_END },
};

#endif
