#include "pongo.h"

static void (*next_preboot_hook)(void);

static struct mach_header_64 *mh_execute_header;
static uint64_t kernel_slide;

/* thanks @bazad */
#define sa_for_va(va)   ((uint64_t)(va) - kernel_slide)
#define va_for_sa(sa)   ((uint64_t)(sa) + kernel_slide)
#define ptr_for_sa(sa)  ((void *)(((sa) - 0xFFFFFFF007004000uLL) + (uint8_t *)mh_execute_header))
#define ptr_for_va(va)  (ptr_for_sa(sa_for_va(va)))
#define sa_for_ptr(ptr) ((uint64_t)((uint8_t *)(ptr) - (uint8_t *)mh_execute_header) + 0xFFFFFFF007004000uLL)
#define va_for_ptr(ptr) (va_for_sa(sa_for_ptr(ptr)))
#define pa_for_ptr(ptr) (sa_for_ptr(ptr) - gBootArgs->virtBase + gBootArgs->physBase)

#define UCHAR_MAX 255

/* thanks @xerub */
static unsigned char * boyermoore_horspool_memmem(const unsigned char* haystack,
        size_t hlen, const unsigned char* needle, size_t nlen) {
    size_t last, scan = 0;
    size_t bad_char_skip[UCHAR_MAX + 1]; /* Officially called:
                                          * bad character shift */

    /* Sanity checks on the parameters */
    if (nlen <= 0 || !haystack || !needle)
        return NULL;

    /* ---- Preprocess ---- */
    /* Initialize the table to default value */
    /* When a character is encountered that does not occur
     * in the needle, we can safely skip ahead for the whole
     * length of the needle.
     */
    for (scan = 0; scan <= UCHAR_MAX; scan = scan + 1)
        bad_char_skip[scan] = nlen;

    /* C arrays have the first byte at [0], therefore:
     * [nlen - 1] is the last byte of the array. */
    last = nlen - 1;

    /* Then populate it with the analysis of the needle */
    for (scan = 0; scan < last; scan = scan + 1)
        bad_char_skip[needle[scan]] = last - scan;

    /* ---- Do the matching ---- */

    /* Search the haystack, while the needle can still be within it. */
    while (hlen >= nlen)
    {
        /* scan from the end of the needle */
        for (scan = last; haystack[scan] == needle[scan]; scan = scan - 1)
            if (scan == 0) /* If the first byte matches, we've found it. */
                return (void *)haystack;

        /* otherwise, we need to skip some bytes and start again.
           Note that here we are getting the skip value based on the last byte
           of needle, no matter where we didn't match. So if needle is: "abcd"
           then we are skipping based on 'd' and that value will be 4, and
           for "abcdd" we again skip on 'd' but the value will be only 1.
           The alternative of pretending that the mismatched character was
           the last character is slower in the normal case (E.g. finding
           "abcd" in "...azcd..." gives 4 by using 'd' but only
           4-2==2 using 'z'. */
        hlen     -= bad_char_skip[haystack[last]];
        haystack += bad_char_skip[haystack[last]];
    }

    return NULL;
}

static void stalker_fatal(void){
    /* puts("failed: spinning forever"); */
    /* for(;;); */
    panic("stalker: fatal error\n");
}

static bool sleh_synchronous_patcher(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;
    
    /* so far, we've matched these successfully:
     *  LDR Wn, [X19, #0x88]
     *  MRS Xn, TPIDR_EL1
     *  MOV Wn, 0xFFFFFFFF
     *  
     * these will be an entrypoint to finding where I need to write the
     * branch to our handle_svc hook
     */

    for(int i=-10; i<10; i++){
        print_register(opcode_stream[i]);
    }

    return true;
}

static void stalker_apply_patches(const char *cmd, char *args){
    puts("inside stalker_apply_patches");

    /* struct segment_command_64 *__TEXT = macho_get_segment(mh_execute_header, */
    /*         "__TEXT"); */

    /* if(!__TEXT){ */
    /*     puts("stalker_apply_patches: couldn't get __TEXT segment"); */
    /*     return; */
    /*     /1* stalker_fatal(); *1/ */
    /* } */

    /* struct section_64 *__cstring = macho_get_section(__TEXT, "__cstring"); */

    /* if(!__cstring){ */
    /*     puts("stalker_apply_patches: couldn't get __cstring section"); */
    /*     return; */
    /*     /1* stalker_fatal(); *1/ */
    /* } */

    /* uint64_t cstring_start = __cstring->addr; */
    /* uint64_t cstring_end = cstring_start + __cstring->size; */


    /* print_register(cstring_start); */
    /* print_register(cstring_end); */

    /* print_register(strlen("Invalid SVC_64 context")); */

    /* return; */
    /* uint64_t invalid_svc64_context = boyermoore_horspool_memmem(va_for_ptr(__cstring->addr), */
    /*         __cstring->size, (uint8_t *)"Invalid SVC_64 context", */
    /*         strlen("Invalid SVC_64 context")); */

    /* puts("invalid_svc64_context:"); */
    /* print_register(invalid_svc64_context); */

    uint64_t sleh_synchronous_patcher_match[] = {
        0xb9408a60,     /* LDR Wn, [X19, #0x88] (trap_no = saved_state.__x[16] */
        0xd538d080,     /* MRS Xn, TPIDR_EL1    (Xn = current_thread()) */
        0x12800000,     /* MOV Wn, 0xFFFFFFFF   (Wn = THROTTLE_LEVEL_NONE) */
    };

    const size_t num_matches = sizeof(sleh_synchronous_patcher_match) / 
        sizeof(*sleh_synchronous_patcher_match);

    uint64_t sleh_synchronous_patcher_masks[] = {
        0xffffffe0,     /* ignore Wn in LDR */
        0xffffffe0,     /* ignore Xn in MRS */
        0xffffffe0,     /* ignore Wn in MOV */
    };

    /* const size_t num_masks = sizeof(sleh_synchronous_patcher_masks) / */ 
    /*     sizeof(*sleh_synchronous_patcher_masks); */


    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    xnu_pf_maskmatch(patchset, sleh_synchronous_patcher_match,
            sleh_synchronous_patcher_masks, num_matches, true, sleh_synchronous_patcher);
    xnu_pf_emit(patchset);
    xnu_pf_apply(xnu_pf_segment(mh_execute_header, "__TEXT_EXEC"), patchset);
    xnu_pf_patchset_destroy(patchset);


    puts("------DONE------");
}

static void stalker_preboot_hook(void){
    puts("inside stalker_preboot_hook");

    /* do checkrain's kernel patches first */
    if(next_preboot_hook)
        next_preboot_hook();

    /* stalker_apply_patches(); */

    /* puts("spinning forever"); */
    /* for(;;); */
}

void module_entry(void){
    puts("svc_stalker pongoOS module entry");

    mh_execute_header = xnu_header();
    kernel_slide = xnu_slide_value(mh_execute_header);

    next_preboot_hook = preboot_hook;
    preboot_hook = stalker_preboot_hook;

    command_register("stalker-patch", "apply sleh_synchronous patches",
            stalker_apply_patches);
}

const char *module_name = "svc_stalker";

struct pongo_exports exported_symbols[] = {
    { .name = 0, .value = 0 }
};
