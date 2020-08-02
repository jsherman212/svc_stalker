#include "handle_svc_patches.h"
#include "pongo.h"

static void (*next_preboot_hook)(void);

static uint64_t bits(uint64_t number, uint64_t start, uint64_t end){
    uint64_t amount = (end - start) + 1;
    uint64_t mask = (((uint64_t)1 << amount) - 1) << start;

    return (number & mask) >> start;
}

static uint64_t sign_extend(uint64_t number, uint32_t numbits){
    if(number & ((uint64_t)1 << (numbits - 1)))
        return number | ~(((uint64_t)1 << numbits) - 1);

    return number;
}

static struct mach_header_64 *mh_execute_header;
static uint64_t kernel_slide;


static void stalker_fatal(void){
    /* puts("failed: spinning forever"); */
    /* for(;;); */
    panic("stalker: fatal error\n");
}

static void write_blr(uint32_t reg, uint64_t from, uint64_t to){
    uint32_t *cur = (uint32_t *)from;

    /* movz */
    *(cur++) = (uint32_t)(0xd2800000 | ((to & 0xffff) << 5) | reg);
    /* movk */
    *(cur++) = (uint32_t)(0xf2800000 | (1 << 21) | (((to >> 16) & 0xffff) << 5) | reg);
    /* movk */
    *(cur++) = (uint32_t)(0xf2800000 | (2 << 21) | (((to >> 32) & 0xffff) << 5) | reg);
    /* movk */
    *(cur++) = (uint32_t)(0xf2800000 | (3 << 21) | (((to >> 48) & 0xffff) << 5) | reg);
    /* blr */
    *(cur++) = (uint32_t)(0xd63f0000 | (reg << 5));
}

#define IS_B_NE(opcode) ((opcode & 0xff000001) == 0x54000001)

static uint64_t g_proc_pid_addr = 0;

static bool proc_pid_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* adrp/add pair will be 2 instrs after */
    uint32_t adrp = opcode_stream[2];
    uint32_t add = opcode_stream[3];
    
    uint32_t immlo = bits(adrp, 29, 30);
    uint32_t immhi = bits(adrp, 5, 23);

    uint64_t imm = sign_extend(((immhi << 2) | immlo) << 12, 32) +
        (xnu_ptr_to_va(opcode_stream + 2) & ~0xfffuLL) +
        bits(add, 10, 21);

    char *string = xnu_va_to_ptr(imm);

    /* there's three of these in the function we're targetting, but all
     * use proc_pid's return value as the first and only format string
     * argument, so any one of the three works
     */
    const char *match = "AMFI: hook..execve() killing pid %u:";
    size_t matchlen = strlen(match);

    if(!memmem(string, strlen(string), match, matchlen))
        return false;

    /* at this point, we've hit one of those three strings, so the branch
     * to proc_pid should be at most five instructions above where we are
     * currently
     */
    uint32_t instr_limit = 5;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0){
            puts("svc_stalker: proc_pid_finder: couldn't find proc_pid");
            return false;
        }

        opcode_stream--;
    }

    int32_t imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28);
    g_proc_pid_addr = imm26 + xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found proc_pid");
    /* print_register(g_proc_pid_addr); */

    xnu_pf_disable_patch(patch);

    return true;
}

static bool sleh_synchronous_patcher(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* so far, we've matched these successfully:
     *  LDR Wn, [X19, #0x88]
     *  MRS Xn, TPIDR_EL1
     *  MOV Wn, 0xFFFFFFFF
     *  
     * these will be an entrypoint to finding where we need to write the
     * branch to our handle_svc hook. If we're in the right place,
     * we should find
     *  LDR Wn, [X19]
     *  CMP Wn, 0x15
     *  B.NE xxx
     *  LDRB Wn, [X19, n]
     *  TST Wn, 0xc
     *  B.NE xxx
     *
     * right above where opcode_stream points. LDR Wn, [X19] is where we'll
     * write the branch to our hook. These instructions serve as sanity checks
     * that don't ever seem to hold.
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

    /* don't need anymore */
    xnu_pf_disable_patch(patch);

    uint64_t branch_from = (uint64_t)opcode_stream;

    /* find current_proc, it will be extremely close to the second
     * MRS Xn, TPIDR_EL1 we find from this point on,
     * and the first branch after it as well
     */
    uint32_t instr_limit = 1000;
    uint32_t num_mrs_xn_tpidr_el1 = 0;

    for(;;){
        if(instr_limit-- == 0){
            puts("svc_stalker: sleh_synchronous_patcher: couldn't find"
                    " two MRS Xn, TPIDR_EL1 instrs");
            return false;
        }

        if((*opcode_stream & 0xffffffe0) == 0xd538d080){
            num_mrs_xn_tpidr_el1++;

            if(num_mrs_xn_tpidr_el1 == 2)
                break;
        }

        opcode_stream++;
    }

    /* the first BL from this point on should be branching to current_proc */
    instr_limit = 10;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0){
            puts("svc_stalker: sleh_synchronous_patcher: couldn't find"
                    " current_proc");
            return false;
        }

        opcode_stream++;
    }

    /* print_register(*opcode_stream); */

    int32_t imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28);
    uint64_t current_proc_addr = imm26 + xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found current_proc");
    /* print_register(current_proc_addr); */
    /* print_register(xnu_ptr_to_va(mh_execute_header)); */
    /* print_register(kernel_slide); */
    /* print_register(current_proc_addr - kernel_slide); */

    /* for(int i=0; i<10; i++){ */
    /*     uint32_t *p = (uint32_t *)xnu_va_to_ptr(current_proc_addr); */
    /*     print_register(p[i]); */
    /* } */

    /* now we need to find exception_triage. We can do this by going forward
     * until we hit a BRK, as it's right after the call to exception_triage
     * and it's the only BRK in sleh_synchronous.
     */
    instr_limit = 1000;

    while((*opcode_stream & 0xffe0001f) != 0xd4200000){
        if(instr_limit-- == 0){
            puts("svc_stalker: sleh_synchronous_patcher: couldn't find exception_triage");
            return false;
        }

        opcode_stream++;
    }

    opcode_stream--;

    imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28);
    uint64_t exception_triage_addr = imm26 + xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found exception_triage");
    /* print_register(exception_triage_addr); */
    /* print_register(exception_triage_addr - kernel_slide); */
    /* for(int i=0; i<10; i++){ */
    /*     uint32_t *p = (uint32_t *)xnu_va_to_ptr(exception_triage_addr); */
    /*     print_register(p[i]); */
    /* } */
    
    /* we're gonna put our handle_svc hook inside of the empty space right
     * before the end of __TEXT_EXEC that forces it to be page aligned
     */
    struct segment_command_64 *__TEXT_EXEC = macho_get_segment(mh_execute_header,
            "__TEXT_EXEC");
    struct section_64 *last_TEXT_EXEC_sect = (struct section_64 *)(__TEXT_EXEC + 1);

    /* go to last section */
    for(uint32_t i=0; i<__TEXT_EXEC->nsects-1; i++)
        last_TEXT_EXEC_sect++;

    uint64_t last_TEXT_EXEC_sect_end = last_TEXT_EXEC_sect->addr + last_TEXT_EXEC_sect->size;
    uint64_t __TEXT_EXEC_end = __TEXT_EXEC->vmaddr + __TEXT_EXEC->vmsize;
    uint64_t num_free_instrs = (__TEXT_EXEC_end - last_TEXT_EXEC_sect_end) / sizeof(uint32_t);

    uint32_t *scratch_space = xnu_va_to_ptr(last_TEXT_EXEC_sect_end);

    uint64_t cache_size = 0;

#define WRITE_QWORD(qword) \
    if(num_free_instrs < 2){ \
        puts("svc_stalker: sleh_synchronous_patcher: ran out of space for hook"); \
        return false; \
    } \
    *(uint64_t *)scratch_space = (qword); \
    scratch_space += 2; \
    num_free_instrs -= 2; \
    cache_size += 8; \

#define WRITE_INSTR(opcode) \
    do { \
        if(num_free_instrs == 0){ \
            puts("svc_stalker: sleh_synchronous_patcher: ran out of space for hook"); \
            return false; \
        } \
        *scratch_space = (opcode); \
        scratch_space++; \
        num_free_instrs--; \
    } while (0) \

    /* stash exception_triage_addr */
    WRITE_QWORD(exception_triage_addr);

    /* autogenerated by hookgen.pl, see handle_svc_patches.h */
    DO_HANDLE_SVC_PATCHES;

    /* write the branch to our handle_svc hook */
    // XXX commenting out for testing
    write_blr(8, branch_from, last_TEXT_EXEC_sect_end + cache_size);
    /* there's an extra B.NE after the five instrs we overwrote, so NOP it out */
    *(uint32_t *)(branch_from + (4*5)) = 0xd503201f;

    /* uint64_t addr = ptr_for_sa(0xFFFFFFF008023218); */
    /* *(uint32_t*)addr = 0xd4200000; */


    return true;
}

static void stalker_apply_patches(const char *cmd, char *args){
    puts("inside stalker_apply_patches");

    uint64_t proc_pid_patcher_match[] = {
        0x94000000,     /* BL n (_proc_pid) */
        0xf90003e0,     /* STR X0, [SP] (store _proc_pid return value) */
        0x90000000,     /* ADRP X0, n (X0 = format string which uses return value) */
        0x91000000,     /* ADD X0, X0, n */
    };

    const size_t num_proc_pid_matches = sizeof(proc_pid_patcher_match) /
        sizeof(*proc_pid_patcher_match);

    uint64_t proc_pid_patcher_masks[] = {
        0xfc000000,     /* ignore BL immediate */
        0xffffffff,
        0x9f00001f,
        0xffc003ff,
    };

    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    xnu_pf_maskmatch(patchset, proc_pid_patcher_match, proc_pid_patcher_masks,
            num_proc_pid_matches, false, // XXX for testing,
            proc_pid_finder);

    struct mach_header_64 *AMFI = xnu_pf_get_kext_header(mh_execute_header,
            "com.apple.driver.AppleMobileFileIntegrity");
    xnu_pf_range_t *AMFI___TEXT_EXEC = xnu_pf_segment(AMFI, "__TEXT_EXEC");
    xnu_pf_apply(AMFI___TEXT_EXEC, patchset);
    
    uint64_t sleh_synchronous_patcher_match[] = {
        0xb9408a60,     /* LDR Wn, [X19, #0x88] (trap_no = state->__x[16] */
        0xd538d080,     /* MRS Xn, TPIDR_EL1    (Xn = current_thread()) */
        0x12800000,     /* MOV Wn, 0xFFFFFFFF   (Wn = THROTTLE_LEVEL_NONE) */
    };

    const size_t num_ss_matches = sizeof(sleh_synchronous_patcher_match) / 
        sizeof(*sleh_synchronous_patcher_match);

    uint64_t sleh_synchronous_patcher_masks[] = {
        0xffffffe0,     /* ignore Wn in LDR */
        0xffffffe0,     /* ignore Xn in MRS */
        0xffffffe0,     /* ignore Wn in MOV */
    };

    // XXX so failures aren't fatal while testing
    xnu_pf_maskmatch(patchset, sleh_synchronous_patcher_match,
            sleh_synchronous_patcher_masks, num_ss_matches, false, // XXX for testing
            sleh_synchronous_patcher);

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");
    xnu_pf_apply(__TEXT_EXEC, patchset);
    xnu_pf_emit(patchset);
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
