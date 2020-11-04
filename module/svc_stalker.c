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
        if(strcmp(kr->kext, kext) == 0){
            /* same segment? It will be the same range even if the section differs */
            if(seg && strcmp(kr->seg, seg) == 0)
                return;

            if(sect && strcmp(kr->sect, sect) == 0)
                return;
        }
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
    command_register("stalker-prep", "prep to patch sleh_synchronous", stalker_prep);
    /* command_register("stalker-patch-ss", "patch sleh_synchronous", stalker_patch_ss); */
    /* command_register("stalker-mp-noboot", "patch sleh_synchronous without booting", */
    /*         stalker_main_patcher_noboot); */
}

const char *module_name = "svc_stalker";

struct pongo_exports exported_symbols[] = {
    { .name = 0, .value = 0 }
};
