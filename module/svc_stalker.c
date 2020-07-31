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

static void stalker_fatal(void){
    /* puts("failed: spinning forever"); */
    /* for(;;); */
    panic("stalker: fatal error\n");
}

#define IS_B_NE(opcode) ((opcode & 0xff000001) == 0x54000001)

static bool sleh_synchronous_patcher(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;
    
    /* so far, we've matched these successfully:
     *  LDR Wn, [X19, #0x88]
     *  MRS Xn, TPIDR_EL1
     *  MOV Wn, 0xFFFFFFFF
     *  
     * these will be an entrypoint to finding where we need to write the
     * branch to our handle_svc replacement. If we're in the right place,
     * we should find
     *  LDR Wn, [X19]
     *  CMP Wn, 0x15
     *  B.NE xxx
     *  LDRB Wn, [X19, n]
     *  TST Wn, 0xc
     *  B.NE xxx
     *
     * right above where opcode_stream points. LDR Wn, [X19] is where we'll
     * write the branch to our replacement.
     */

    opcode_stream--;

    /* not B.NE xxx? */
    if(!IS_B_NE(*opcode_stream)){
        puts("sleh_synchronous_patcher: Not b.ne, opcode:");
        print_register(*opcode_stream);
        return false;
    }

    opcode_stream--;

    /* not TST Wn, 0xc? */
    if((*opcode_stream & 0xfffffc1f) != 0x721e041f){
        puts("sleh_synchronous_patcher: Not tst Wn, 0xc, opcode:");
        print_register(*opcode_stream);
        return false;
    }

    opcode_stream--;

    /* not LDRB Wn, [X19, n]? */
    if((*opcode_stream & 0xffc003e0) != 0x39400260){
        puts("sleh_synchronous_patcher: Not ldrb Wn, [x19, n], opcode:");
        print_register(*opcode_stream);
        return false;
    }

    opcode_stream--;

    /* not B.NE xxx? */
    if(!IS_B_NE(*opcode_stream)){
        puts("sleh_synchronous_patcher: Not b.ne, opcode:");
        print_register(*opcode_stream);
        return false;
    }

    opcode_stream--;

    /* not CMP Wn, 0x15? */
    if((*opcode_stream & 0xfffffc1f) != 0x7100541f){
        puts("sleh_synchronous_patcher: Not cmp Wn, 0x15, opcode:");
        print_register(*opcode_stream);
        return false;
    }

    opcode_stream--;

    /* not LDR Wn, [X19]? */
    if((*opcode_stream & 0xffffffe0) != 0xb9400260){
        puts("sleh_synchronous_patcher: Not ldr Wn, [x19], opcode:");
        print_register(*opcode_stream);
        return false;
    }

    /* if we're still here, we found where we need to write the branch */
    xnu_pf_disable_patch(patch);

    /* we're gonna put our replacement code inside of the empty space right
     * before the end of __TEXT_EXEC that forces it to be page aligned
     */
    struct segment_command_64 *__TEXT_EXEC = macho_get_segment(mh_execute_header,
            "__TEXT_EXEC");

    struct section_64 *last_TEXT_EXEC_sect = (struct section_64 *)(__TEXT_EXEC + 1);

    /* go to last section */
    for(uint32_t i=0; i<__TEXT_EXEC->nsects-1; i++)
        last_TEXT_EXEC_sect++;

    puts(last_TEXT_EXEC_sect->sectname);

    uint64_t last_TEXT_EXEC_sect_end = last_TEXT_EXEC_sect->addr +
        last_TEXT_EXEC_sect->size;
    uint64_t __TEXT_EXEC_end = __TEXT_EXEC->vmaddr + __TEXT_EXEC->vmsize;

    uint64_t num_free_instrs = (__TEXT_EXEC_end - last_TEXT_EXEC_sect_end) / sizeof(uint32_t);
    print_register(num_free_instrs);

    // TODO check if free instrs can satify the amount of instrs in the handle_svc replacement


    return true;
}

static void stalker_apply_patches(const char *cmd, char *args){
    puts("inside stalker_apply_patches");

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

    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    /* xnu_pf_maskmatch(patchset, sleh_synchronous_patcher_match, */
    /*         sleh_synchronous_patcher_masks, num_matches, true, sleh_synchronous_patcher); */
    // XXX so failures aren't fatal while testing
    xnu_pf_maskmatch(patchset, sleh_synchronous_patcher_match,
            sleh_synchronous_patcher_masks, num_matches, false, sleh_synchronous_patcher);
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
