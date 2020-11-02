#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "common/common.h"
#include "common/pongo.h"

#include "pf/offsets.h"
#include "pf/pfs.h"

uint64_t *stalker_cache_base = NULL;
uint64_t *stalker_cache_cursor = NULL;

uint32_t g_kern_version_major = 0;

static uint32_t g_kern_version_minor = 0;
static uint32_t g_kern_version_revision = 0;

static bool getkernelv_callback(xnu_pf_patch_t *patch, void *cacheable_stream){
    xnu_pf_disable_patch(patch);
    char *version = cacheable_stream;

    /* on all kernels, major, minor, and version are no larger than 2 chars */
    char major_s[3] = {0};
    char minor_s[3] = {0};
    char revision_s[3] = {0};

    /* skip ahead until we get a digit */
    while(!isdigit(*version))
        version++;
    
    for(int i=0; *version != '.'; i++, version++)
        major_s[i] = *version;

    version++;

    for(int i=0; *version != '.'; i++, version++)
        minor_s[i] = *version;

    version++;

    for(int i=0; *version != ':'; i++, version++)
        revision_s[i] = *version;

    /* currently, I only use major, but I get the rest in case I need
     * them in the future
     */
    g_kern_version_major = atoi(major_s);
    g_kern_version_minor = atoi(minor_s);
    g_kern_version_revision = atoi(revision_s);

    if(g_kern_version_major == 19)
        printf("svc_stalker: iOS 13.x detected\n");
    else if(g_kern_version_major == 20)
        printf("svc_stalker: iOS 14.x detected\n");
    else{
        printf("svc_stalker: error: unknown\n"
                "  major %d\n",
                g_kern_version_major);

        stalker_fatal_error();
    }

    /* so we can use this to index into g_all_pfs */
    g_kern_version_major -= 19;

    return true;
}

static void stalker_getkernelv(const char *cmd, char *args){
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_8BIT);

    xnu_pf_range_t *__TEXT___const = xnu_pf_section(mh_execute_header, "__TEXT",
            "__const");

    if(!__TEXT___const){
        puts("svc_stalker: xnu_pf_section");
        puts("   returned NULL for");
        puts("   __TEXT:__const?");

        stalker_fatal_error();
    }

    const char *vers = "Darwin Kernel Version ";

    /* hardcoded so clang does not generate ___chkstk_darwin calls */
    uint64_t ver[21];
    uint64_t masks[21];

    for(int i=0; i<21; i++){
        ver[i] = vers[i];
        masks[i] = 0xff;
    }

    uint64_t count = sizeof(ver) / sizeof(*ver);

    xnu_pf_maskmatch(patchset, "kernel version finder", ver, masks, count,
            false, getkernelv_callback);
    xnu_pf_emit(patchset);
    xnu_pf_apply(__TEXT___const, patchset);
    xnu_pf_patchset_destroy(patchset);
}

#define MAXKEXTRANGE MAXPF

struct kextrange {
    xnu_pf_range_t *range;
    char *kext;
    char *seg;
    char *sect;
};

/* static bool xnu_pf_range_eq(xnu_pf_range_t *left, xnu_pf_range_t *right){ */
/*     return left->va == right->va && left->size == right->size; */
/* } */

/* purpose of this function is to add patchfinder ranges for kexts in such
 * a way that there are no duplicates in `*ranges`
 */
static void add_kext_range(struct kextrange **ranges, const char *kext,
        const char *seg, const char *sect, size_t *nkextranges_out){
    size_t nkextranges = *nkextranges_out;

    /* printf("kext %p seg %p sect %p nkextranges %zu\n", kext, seg, sect, nkextranges); */

    if(nkextranges == MAXKEXTRANGE)
        return;

    /* first, check if this kext is already present */
    for(size_t i=0; i<nkextranges; i++){
        struct kextrange *kr = ranges[i];

        /* printf("Looking at kextrange %zu\n", i); */

        /* kext will never be NULL, otherwise, this function would have
         * no point
         */

        if(strcmp(kr->kext, kext) == 0)
            return;

        if(seg && strcmp(kr->seg, seg) == 0)
            return;

        if(sect && strcmp(kr->sect, sect) == 0)
            return;
    }

    /* new kext, make its range */
    struct mach_header_64 *mh = xnu_pf_get_kext_header(mh_execute_header, kext);

    if(!mh){
        printf( "svc_stalker: could not\n"
                "   get Mach header for\n"
                "   %s\n", kext);

        stalker_fatal_error();
    }

    struct kextrange *kr = malloc(sizeof(struct kextrange));
    memset(kr, 0, sizeof(*kr));

    if(sect)
        kr->range = xnu_pf_section(mh, (void *)seg, (char *)sect);
    else
        kr->range = xnu_pf_segment(mh, (void *)seg);

    size_t kextl = 0, segl = 0, sectl = 0;
    
    kextl = strlen(kext);

    char *kn = malloc(kextl + 1);
    strcpy(kn, kext);
    kn[kextl] = '\0';
    kr->kext = kn;

    if(seg){
        segl = strlen(seg);
        char *segn = malloc(segl + 1);
        strcpy(segn, seg);
        segn[segl] = '\0';
        kr->seg = segn;
    }

    if(sect){
        sectl = strlen(sect);
        char *sectn = malloc(sectl + 1);
        strcpy(sectn, sect);
        sectn[sectl] = '\0';
        kr->sect = sectn;
    }

    /* printf("%s: ranges[%zu] = %p\n", __func__, nkextranges, kr); */
    ranges[nkextranges] = kr;
    
    *nkextranges_out = nkextranges + 1;
}

static void stalker_prep2(const char *cmd, char *args){
    /* all the patchfinders in pf/pfs.h currently do 32 bit */
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);

    size_t nkextranges = 0;
    struct kextrange **kextranges = malloc(sizeof(struct kextrange *) * MAXKEXTRANGE);

    for(int i=0; !PFS_END(g_all_pfs[i]); i++){
        struct pf *pf = &g_all_pfs[i][g_kern_version_major];

        if(IS_PF_UNUSED(pf))
            continue;

        /* printf("%s: chose '%s'\n", __func__, pf->pf_name); */

        /* xnu_pf_range_t *pf_range = NULL; */

        const char *pf_kext = pf->pf_kext;
        const char *pf_segment = pf->pf_segment;
        const char *pf_section = pf->pf_section;

        /* if(pf_kext) */
        /*     printf("kext '%s'\n", pf_kext); */
        
        /* printf("segment '%s'\n", pf_segment); */

        /* if(pf_section) */
        /*     printf("section '%s'\n", pf_section); */

        if(pf_kext){
            add_kext_range(kextranges, pf_kext, pf_segment, pf_section,
                    &nkextranges);
        }

        xnu_pf_maskmatch(patchset, (char *)pf->pf_name, pf->pf_matches,
                pf->pf_masks, pf->pf_mmcount, false, pf->pf_callback);
    }

    /* printf("%s: nkextranges %zu\n", __func__, nkextranges); */

    xnu_pf_emit(patchset);

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");
    xnu_pf_apply(__TEXT_EXEC, patchset);

    for(size_t i=0; i<nkextranges; i++){
        /* printf("%s: kextrange %zu: '%s'\n", __func__, i, kextranges[i]->kext); */

        xnu_pf_range_t *range = kextranges[i]->range;
        xnu_pf_apply(range, patchset);
    }

    xnu_pf_patchset_destroy(patchset);
}

#if 0
static void stalker_prep(const char *cmd, char *args){
    /* None of these patches are required so I can display an error message
     * that the user can read if something isn't found instead of panicking
     */
    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);

    uint64_t proc_pid_finder_match[] = {
        0xb4000000,     /* CBZ X0, n */
        0xaa0303fa,     /* MOV X26, X3 */
        0xb4000003,     /* CBZ X3, n */
    };

    const size_t num_proc_pid_matches = sizeof(proc_pid_finder_match) /
        sizeof(*proc_pid_finder_match);

    uint64_t proc_pid_finder_masks[] = {
        0xff00001f,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xff00001f,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "proc_pid finder", proc_pid_finder_match,
            proc_pid_finder_masks, num_proc_pid_matches, false, proc_pid_finder);

    uint64_t sysent_finder_match[] = {
        0x1a803000,     /* CSEL Wn, Wn, Wn, CC */
        0x12003c00,     /* AND Wn, Wn, 0xffff */
        0x10000000,     /* ADRP Xn, n or ADR Xn, n */
    };

    const size_t num_sysent_matches = sizeof(sysent_finder_match) /
        sizeof(*sysent_finder_match);

    uint64_t sysent_finder_masks[] = {
        0xffe0fc00,     /* ignore all but condition code */
        0xfffffc00,     /* ignore all but immediate */
        0x1f000000,     /* ignore everything */
    };

    xnu_pf_maskmatch(patchset, "sysent finder", sysent_finder_match,
            sysent_finder_masks, num_sysent_matches, false, sysent_finder);

    uint64_t kalloc_canblock_match[] = {
        0xaa0003f3,     /* MOV X19, X0 */
        0xf90003ff,     /* STR XZR, [SP, n] */
        0xf9400000,     /* LDR Xn, [Xn] */
        0xf11fbc1f,     /* CMP Xn, 0x7ef */
    };

    const size_t num_kalloc_canblock_matches = sizeof(kalloc_canblock_match) /
        sizeof(*kalloc_canblock_match);

    uint64_t kalloc_canblock_masks[] = {
        0xffffffff,     /* match exactly */
        0xffc003ff,     /* ignore immediate */
        0xffc00000,     /* ignore immediate, Rn, and Rt */
        0xfffffc1f,     /* ignore Rn */
    };

    xnu_pf_maskmatch(patchset, "kalloc_canblock finder", kalloc_canblock_match,
            kalloc_canblock_masks, num_kalloc_canblock_matches, false,
            kalloc_canblock_finder);

    uint64_t kfree_addr_match[] = {
        0x10000009,     /* ADRP X9, n or ADR X9, n */
        0x0,            /* ignore this instruction */
        0xfa538002,     /* CCMP Xn, X19, #2, HI */
        0x10000000,     /* ADRP Xn, n or ADR Xn, n */
        0x0,            /* ignore this instruction */
    };

    const size_t num_kfree_addr_matches = sizeof(kfree_addr_match) /
        sizeof(*kfree_addr_match);

    uint64_t kfree_addr_masks[] = {
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0xfffffc1f,     /* ignore Xn */
        0x1f000000,     /* ignore everything */
        0x0,            /* ignore this instruction */
    };

    xnu_pf_maskmatch(patchset, "kfree_addr finder", kfree_addr_match,
            kfree_addr_masks, num_kfree_addr_matches, false, kfree_addr_finder);

    uint64_t mach_syscall_patcher_match[] = {
        0xb9400000,     /* LDR Wn, [X0] */
        0x7100501f,     /* CMP Wn, 0x14 */
        0x54000001,     /* B.NE n */
        0xb9403a60,     /* LDR Wn, [X19, 0x38] */
    };

    const size_t num_mach_syscall_matches = sizeof(mach_syscall_patcher_match) /
        sizeof(*mach_syscall_patcher_match);

    uint64_t mach_syscall_patcher_masks[] = {
        0xffffffe0,     /* ignore Wn */
        0xfffffc1f,     /* ignore Wn */
        0xff00001f,     /* ignore immediate */
        0xffffffe0,     /* ignore Wn */
    };

    xnu_pf_maskmatch(patchset, "mach_syscall finder", mach_syscall_patcher_match,
            mach_syscall_patcher_masks, num_mach_syscall_matches, false,
            mach_syscall_patcher);

    uint64_t ExceptionVectorsBase_finder_match[] = {
        0xd538d092,     /* MRS X18, TPIDR_EL1 */
        0xf9400252,     /* LDR X18, [X18, n] */
        0xf9400252,     /* LDR X18, [X18, n] */
        0xf9400252,     /* LDR X18, [X18] */
        0xd61f0240,     /* BR X18 */
    };

    const size_t num_ExceptionVectorsBase_matches =
        sizeof(ExceptionVectorsBase_finder_match) /
        sizeof(*ExceptionVectorsBase_finder_match);

    uint64_t ExceptionVectorsBase_finder_masks[] = {
        0xffffffff,     /* match exactly */
        0xffc003ff,     /* match all but immediate */
        0xffc003ff,     /* match all but immediate */
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
    };

    xnu_pf_maskmatch(patchset, "ExceptionVectorsBase finder",
            ExceptionVectorsBase_finder_match, ExceptionVectorsBase_finder_masks,
            num_ExceptionVectorsBase_matches, false, ExceptionVectorsBase_finder);

    uint64_t sysctl__kern_children_finder_matches[] = {
        0x10000013,     /* ADRP X19, n or ADR X19, n */
        0x0,            /* ignore this instruction */
        0x10000014,     /* ADRP X20, n or ADR X20, n */
        0x0,            /* ignore this instruction */
        0x10000015,     /* ADRP X21, n or ADR X21, n */
        0x0,            /* ignore this instruction */
        0x10000016,     /* ADRP X22, n or ADR X22, n */
        0x0,            /* ignore this instruction */
        0x10000017,     /* ADRP X23, n or ADR X23, n */
        0x0,            /* ignore this instruction */
    };

    const size_t num_sysctl__kern_children_finder_matches =
        sizeof(sysctl__kern_children_finder_matches) /
        sizeof(*sysctl__kern_children_finder_matches);

    uint64_t sysctl__kern_children_finder_masks[] = {
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
    };

    xnu_pf_maskmatch(patchset, "sysctl__kern_children finder",
            sysctl__kern_children_finder_matches, sysctl__kern_children_finder_masks,
            num_sysctl__kern_children_finder_matches, false,
            sysctl__kern_children_finder);

    uint64_t sysctl_register_oid_finder_matches[] = {
        0xb4000013,     /* CBZ X19, n */
        0xf9000013,     /* STR X19, [Xn, n] */
        0x91002000,     /* ADD Xn, Xn, 8 */
        0xf9000260,     /* STR Xn, [X19, n] */
        0xf9400000,     /* LDR X0, [Xn, n] */
        0x94000000,     /* BL n (_sysctl_register_oid) */
    };

    const size_t num_sysctl_register_oid_finder_matches =
        sizeof(sysctl_register_oid_finder_matches) /
        sizeof(*sysctl_register_oid_finder_matches);

    uint64_t sysctl_register_oid_finder_masks[] = {
        0xff00001f,     /* ignore immediate */
        0xffc0001f,     /* ignore all but Rt */
        0xfffffc00,     /* only match immediate */
        0xffc003e0,     /* ignore immediate and Rt */
        0xffc0001f,     /* ignore all but Rt */
        0xfc000000,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "sysctl_register_oid",
            sysctl_register_oid_finder_matches, sysctl_register_oid_finder_masks,
            num_sysctl_register_oid_finder_matches, false,
            sysctl_register_oid_finder);

    uint64_t sysctl_handle_long_finder_matches[] = {
        0xb4000001,     /* CBZ X1, n */
        0xd10003ff,     /* SUB SP, SP, n */
        0xa9004ff4,     /* STP X20, X19, [SP, n] */
        0xa9007bfd,     /* STP X29, X30, [SP, n] */
        0x0,            /* ignore this instruction */
        0xaa0303f4,     /* MOV X20, X3 */
        0xaa0103f3,     /* MOV X19, X1 */
        0xf9400028,     /* LDR X8, [X1] */
        0xf90007e8,     /* STR X8, [SP, 8] */
    };

    const size_t num_sysctl_handle_long_finder_matches =
        sizeof(sysctl_handle_long_finder_matches) /
        sizeof(*sysctl_handle_long_finder_matches);

    uint64_t sysctl_handle_long_finder_masks[] = {
        0xff00001f,     /* ignore immediate */
        0xffc003ff,     /* ignore immediate */
        0xffc07fff,     /* ignore immediate */
        0xffc07fff,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
    };

    xnu_pf_maskmatch(patchset, "sysctl_handle_long finder",
            sysctl_handle_long_finder_matches, sysctl_handle_long_finder_masks,
            num_sysctl_handle_long_finder_matches, false,
            sysctl_handle_long_finder);

    uint64_t name2oid_and_its_dependencies_finder_matches[] = {
        0x10000000,     /* ADRP Xn, n or ADR Xn, n (n = _sysctl_geometry_lock) */
        0xf9400000,     /* LDR X0, [Xn, n] */
        0x94000000,     /* BL n (_lck_rw_lock_shared) */
        0x910003e1,     /* ADD X1, SP, n */
        0x910003e2,     /* ADD X2, SP, n */
        0x0,            /* ignore this instruction */
        0x94000000,     /* BL n (_name2oid) */
        0x0,            /* ignore this instruction */
        0xf9400000,     /* LDR X0, [Xn, n] */
        0x94000000,     /* BL n (_lck_rw_done) */
    };

    const size_t num_name2oid_and_its_dependencies_finder_matches =
        sizeof(name2oid_and_its_dependencies_finder_matches) /
        sizeof(*name2oid_and_its_dependencies_finder_matches);

    uint64_t name2oid_and_its_dependencies_finder_masks[] = {
        0x1f000000,     /* ignore everything */
        0xffc0001f,     /* ignore all but Rt */
        0xfc000000,     /* ignore immediate */
        0xffc003ff,     /* ignore immediate */
        0xffc003ff,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0xfc000000,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0xffc0001f,     /* ignore all but Rt */
        0xfc000000,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "name2oid and its dependencies finder",
            name2oid_and_its_dependencies_finder_matches,
            name2oid_and_its_dependencies_finder_masks,
            num_name2oid_and_its_dependencies_finder_matches, false,
            name2oid_and_its_dependencies_finder);

    uint64_t hook_system_check_sysctlbyname_finder_matches[] = {
        0x7100101f,     /* CMP Wn, 4 */
        0x54000003,     /* B.CC n */
        0xb9400000,     /* LDR Wn, [Xn] */
        0x7100041f,     /* CMP Wn, 1 */
        0x54000001,     /* B.NE n */
        0xb9400400,     /* LDR Wn, [Xn, 4] */
        0x7100381f,     /* CMP Wn, 0xe */
        0x54000001,     /* B.NE n */
    };

    const size_t num_hook_system_check_sysctlbyname_finder_matches =
        sizeof(hook_system_check_sysctlbyname_finder_matches) /
        sizeof(*hook_system_check_sysctlbyname_finder_matches);

    uint64_t hook_system_check_sysctlbyname_finder_masks[] = {
        0xfffffc1f,     /* ignore Rn */
        0xff00001f,     /* ignore immediate */
        0xfffffc00,     /* ignore Rn and Rt */
        0xfffffc1f,     /* ignore Rn */
        0xff00001f,     /* ignore immediate */
        0xfffffc00,     /* ignore Rn and Rt */
        0xfffffc1f,     /* ignore Rn */
        0xff00001f,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "hook_system_check_sysctlbyname finder",
            hook_system_check_sysctlbyname_finder_matches,
            hook_system_check_sysctlbyname_finder_masks,
            num_hook_system_check_sysctlbyname_finder_matches, false,
            hook_system_check_sysctlbyname_finder);

    uint64_t thread_exception_return_finder_matches[] = {
        0xd538d080,     /* MRS X0, TPIDR_EL1 */
        0x91000015,     /* ADD X21, X0, n */
        0xf94002b5,     /* LDR X21, [X21] */
    };

    const size_t num_thread_exception_return_finder_matches =
        sizeof(thread_exception_return_finder_matches) /
        sizeof(*thread_exception_return_finder_matches);

    uint64_t thread_exception_return_finder_masks[] = {
        0xffffffff,     /* match exactly */
        0xffc003ff,     /* ignore immediate */
        0xffffffff,     /* match exactly */
    };

    xnu_pf_maskmatch(patchset, "thread_exception_return finder",
            thread_exception_return_finder_matches,
            thread_exception_return_finder_masks,
            num_thread_exception_return_finder_matches, false,
            thread_exception_return_finder);

    uint64_t thread_syscall_return_scanner_matches[] = {
        0xa9bf7bfd,     /* stp x29, x30, [sp, -0x10]! */
        0x910003fd,     /* mov x29, sp */
        0xd538d088,     /* mrs x8, TPIDR_EL1 */
        0xf9400109,     /* ldr x9, [x8, n] */
        0x93407c08,     /* sxtw x8, w0 */
        0xf9000528,     /* str x8, [x9, #0x8] */
    };

    const size_t num_thread_syscall_return_scanner_matches =
        sizeof(thread_syscall_return_scanner_matches) /
        sizeof(*thread_syscall_return_scanner_matches);

    uint64_t thread_syscall_return_scanner_masks[] = {
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
        0xffc003ff,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xffffffff,     /* match exactly */
    };

    xnu_pf_maskmatch(patchset, "thread_syscall_return scanner",
            thread_syscall_return_scanner_matches,
            thread_syscall_return_scanner_masks,
            num_thread_syscall_return_scanner_matches, false,
            thread_syscall_return_scanner);

    uint64_t platform_syscall_scanner_matches[] = {
        0xd538d080,     /* mrs x0, TPIDR_EL1 */
        0x94000000,     /* bl n */
        0x94000000,     /* bl n */
        0xf9000408,     /* str x8, [x0, #8] */
        0x94000000,     /* bl n */
        0xa940d013,     /* ldp x19, x20, [x0, #8] */
    };

    const size_t num_platform_syscall_scanner_matches =
        sizeof(platform_syscall_scanner_matches) /
        sizeof(*platform_syscall_scanner_matches);

    uint64_t platform_syscall_scanner_masks[] = {
        0xffffffff,     /* match exactly */
        0xfc000000,     /* ignore immediate */
        0xfc000000,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xfc000000,     /* ignore immediate */
        0xffffffff,     /* match exactly */
    };

    xnu_pf_maskmatch(patchset, "platform_syscall scanner",
            platform_syscall_scanner_matches, platform_syscall_scanner_masks,
            num_platform_syscall_scanner_matches, false,
            platform_syscall_scanner);

    uint64_t unix_syscall_return_scanner_matches[] = {
        0xd538d096,     /* mrs x22, TPIDR_EL1 */
        0x94000000,     /* bl n */
        0xaa0003f4,     /* mov x20, x0 */
        0xf94002d5,     /* ldr x21, [x22, n] */
        0xf94002c1,     /* ldr x1, [x22, n] */
    };

    const size_t num_unix_syscall_return_scanner_matches =
        sizeof(unix_syscall_return_scanner_matches) /
        sizeof(*unix_syscall_return_scanner_matches);

    uint64_t unix_syscall_return_scanner_masks[] = {
        0xffffffff,     /* match exactly */
        0xfc000000,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xffc003ff,     /* ignore immediate */
        0xffc003ff,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "unix_syscall_return scanner",
            unix_syscall_return_scanner_matches, unix_syscall_return_scanner_masks,
            num_unix_syscall_return_scanner_matches, false,
            unix_syscall_return_scanner);

    uint64_t lck_grp_alloc_init_finder_matches[] = {
        0xf9400260,     /* ldr x0, [x19] */
        0xf9400281,     /* ldr x1, [x20, n] */
        0x94000000,     /* bl n */
    };

    const size_t num_lck_grp_alloc_init_finder_matches =
        sizeof(lck_grp_alloc_init_finder_matches) /
        sizeof(*lck_grp_alloc_init_finder_matches);

    uint64_t lck_grp_alloc_init_finder_masks[] = {
        0xffffffff,     /* match exactly */
        0xffc003ff,     /* ignore immediate */
        0xfc000000,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "lck_grp_alloc_init finder",
            lck_grp_alloc_init_finder_matches, lck_grp_alloc_init_finder_masks,
            num_lck_grp_alloc_init_finder_matches, false,
            lck_grp_alloc_init_finder);

    uint64_t lck_rw_alloc_init_finder_matches[] = {
        0xb4000000,     /* cbz x0, n */
        0xd37ced01,     /* lsl x1, x8, #4 */
        0x94000000,     /* bl n (bzero) */
        0x10000008,     /* adrp x8, n or adr x8, n */
        0x0,            /* ignore this instruction */
        0xd2800001,     /* mov x1, 0 */
        0x94000000,     /* bl n (lck_rw_alloc_init) */
        0xf9000260,     /* str x0, [x19, n] */
        0xb5000000,     /* cbnz x0, n */
    };

    const size_t num_lck_rw_alloc_init_finder_matches =
        sizeof(lck_rw_alloc_init_finder_matches) /
        sizeof(*lck_rw_alloc_init_finder_matches);

    uint64_t lck_rw_alloc_init_finder_masks[] = {
        0xff00001f,     /* ignore immediate */
        0xffffffff,     /* match exactly */
        0xfc000000,     /* ignore immediate */
        0x1f00001f,     /* ignore immediate */
        0x0,            /* ignore this instruction */
        0xffffffff,     /* match exactly */
        0xfc000000,     /* ignore immediate */
        0xffc003ff,     /* ignore immediate */
        0xff00001f,     /* ignore immediate */
    };

    xnu_pf_maskmatch(patchset, "lck_rw_alloc_init finder",
            lck_rw_alloc_init_finder_matches, lck_rw_alloc_init_finder_masks,
            num_lck_rw_alloc_init_finder_matches, false,
            lck_rw_alloc_init_finder);

    uint64_t unix_syscall_patcher_matches[] = {
        0xf940469a,     /* ldr x26, [x20, 0x88] */
        0xb500001a,     /* cbnz x26, n */
        0xb9400a9a,     /* ldr w26, [x20, 0x8] */
    };

    const size_t num_unix_syscall_patcher_matches =
        sizeof(unix_syscall_patcher_matches) /
        sizeof(*unix_syscall_patcher_matches);

    uint64_t unix_syscall_patcher_masks[] = {
        0xffffffff,     /* match exactly */
        0xff00001f,     /* ignore immediate */
        0xffffffff,     /* match exactly */
    };

    xnu_pf_maskmatch(patchset, "unix_syscall patcher",
            unix_syscall_patcher_matches, unix_syscall_patcher_masks,
            num_unix_syscall_patcher_matches, false,
            unix_syscall_patcher);

    /* AMFI for proc_pid */
    struct mach_header_64 *AMFI = xnu_pf_get_kext_header(mh_execute_header,
            "com.apple.driver.AppleMobileFileIntegrity");

    if(!AMFI){
        puts("svc_stalker: xnu_pf_get_kext_header");
        puts("  returned NULL for AMFI?");

        stalker_fatal_error();
    }

    xnu_pf_range_t *AMFI___TEXT_EXEC = xnu_pf_segment(AMFI, "__TEXT_EXEC");

    /* XXX XXX if ios14, also apply this to com.apple.kec.corecrypto
     * segment for lck_grp_alloc_init
     */

    /* sandbox for hook_system_check_sysctlbyname and lck_grp_alloc_init */
    struct mach_header_64 *sandbox = xnu_pf_get_kext_header(mh_execute_header,
            "com.apple.security.sandbox");

    if(!sandbox){
        puts("svc_stalker: xnu_pf_get_kext_header");
        puts("  returned NULL for");
        puts("  com.apple.security.sandbox?");

        stalker_fatal_error();
    }

    xnu_pf_range_t *sandbox___TEXT_EXEC = xnu_pf_segment(sandbox, "__TEXT_EXEC");

    /* __TEXT_EXEC for everything else */
    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");

    xnu_pf_emit(patchset);
    xnu_pf_apply(AMFI___TEXT_EXEC, patchset);
    xnu_pf_apply(sandbox___TEXT_EXEC, patchset);
    xnu_pf_apply(__TEXT_EXEC, patchset);
    xnu_pf_patchset_destroy(patchset);
}
#endif

#if 0
static void stalker_patch_ss(const char *cmd, char *args){
    /* XXX fine for iOS 14 */
    uint64_t stalker_main_patcher_match[] = {
        0xb9408a60,     /* LDR Wn, [X19, #0x88] (trap_no = state->__x[16]) */
        0xd538d080,     /* MRS Xn, TPIDR_EL1    (Xn = current_thread()) */
        0x12800000,     /* MOV Wn, 0xFFFFFFFF   (Wn = THROTTLE_LEVEL_NONE) */
    };

    const size_t num_matches = sizeof(stalker_main_patcher_match) / 
        sizeof(*stalker_main_patcher_match);

    uint64_t stalker_main_patcher_masks[] = {
        0xffffffe0,     /* ignore Wn in LDR */
        0xffffffe0,     /* ignore Xn in MRS */
        0xffffffe0,     /* ignore Wn in MOV */
    };

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");

    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    xnu_pf_maskmatch(patchset, "stalker main patcher", stalker_main_patcher_match,
            stalker_main_patcher_masks, num_matches, false,
            stalker_main_patcher);
    xnu_pf_emit(patchset);
    xnu_pf_apply(__TEXT_EXEC, patchset);

    xnu_pf_patchset_destroy(patchset);
}
#endif

static void (*next_preboot_hook)(void);

static void stalker_preboot_hook(void){
    /* write all offsets to stalker cache and boot */

    printf("%s: stalker cache = %p va %#llx\n", __func__, stalker_cache_base,
            xnu_ptr_to_va(stalker_cache_base));

    printf("svc_stalker: inited stalker cache\n");

    if(next_preboot_hook)
        next_preboot_hook();
}

#if 0
static void stalker_main_patcher_noboot(const char *cmd, char *args){
    uint64_t stalker_main_patcher_match[] = {
        0xb9408a60,     /* LDR Wn, [X19, #0x88] (trap_no = state->__x[16]) */
        0xd538d080,     /* MRS Xn, TPIDR_EL1    (Xn = current_thread()) */
        0x12800000,     /* MOV Wn, 0xFFFFFFFF   (Wn = THROTTLE_LEVEL_NONE) */
    };

    const size_t num_matches = sizeof(stalker_main_patcher_match) / 
        sizeof(*stalker_main_patcher_match);

    uint64_t stalker_main_patcher_masks[] = {
        0xffffffe0,     /* ignore Wn in LDR */
        0xffffffe0,     /* ignore Xn in MRS */
        0xffffffe0,     /* ignore Wn in MOV */
    };

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");

    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    xnu_pf_maskmatch(patchset, "stalker main patcher", stalker_main_patcher_match,
            stalker_main_patcher_masks, num_matches, false,
            stalker_main_patcher);
    xnu_pf_emit(patchset);
    xnu_pf_apply(__TEXT_EXEC, patchset);

    xnu_pf_patchset_destroy(patchset);
}
#endif

void module_entry(void){
    puts("svc_stalker: loaded!");

    /* XXX now I need to keep a counter in the pf file */
    /* memset(g_platform_syscall_ter_calls, 0, sizeof(uint32_t *) * g_max_ter_calls); */
    /* memset(g_thread_syscall_return_ter_calls, 0, sizeof(uint32_t *) * g_max_ter_calls); */
    /* memset(g_unix_syscall_return_ter_calls, 0, sizeof(uint32_t *) * g_max_ter_calls); */

    mh_execute_header = xnu_header();
    kernel_slide = xnu_slide_value(mh_execute_header);

    next_preboot_hook = preboot_hook;
    preboot_hook = stalker_preboot_hook;

    command_register("stalker-getkernelv", "get kernel version", stalker_getkernelv);
    /* command_register("stalker-prep", "prep to patch sleh_synchronous", stalker_prep); */
    command_register("stalker-prep2", "prep to patch sleh_synchronous", stalker_prep2);
    /* command_register("stalker-patch-ss", "patch sleh_synchronous", stalker_patch_ss); */
    /* command_register("stalker-mp-noboot", "patch sleh_synchronous without booting", */
    /*         stalker_main_patcher_noboot); */
}

const char *module_name = "svc_stalker";

struct pongo_exports exported_symbols[] = {
    { .name = 0, .value = 0 }
};
