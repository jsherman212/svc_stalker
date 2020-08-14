#include "handle_svc_hook_patches.h"
#include "hook_system_check_sysctlbyname_hook_patches.h"
#include "pongo.h"
#include "svc_stalker_ctl_patches.h"

#define PAGE_SIZE (0x4000)

#undef strcpy
#define strcpy strcpy_
static char *strcpy(char *dest, const char *src){
    char *src0 = (char *)src;
    while((*dest++ = *src0++));
    *dest = '\0';
    /* who cares about strcpy return value */
    return dest;
}

static uint64_t bits(uint64_t number, uint64_t start, uint64_t end){
    uint64_t amount = (end - start) + 1;
    uint64_t mask = (((uint64_t)1 << amount) - 1) << start;

    return (number & mask) >> start;
}

static uint64_t sign_extend(uint64_t number, uint32_t numbits /* signbit */){
    if(number & ((uint64_t)1 << (numbits - 1)))
        return number | ~(((uint64_t)1 << numbits) - 1);

    return number;
}

static struct mach_header_64 *mh_execute_header;
static uint64_t kernel_slide;

/* XXX do not panic so user can see what screen says */
__attribute__ ((noreturn)) static void stalker_fatal_error(void){
    puts("svc_stalker: fatal error.");
    puts("     Please file an issue");
    puts("     on Github. Include");
    puts("     output up to this");
    puts("     point and device/iOS");
    puts("     version.");
    puts("Spinning forever.");

    for(;;);
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

static uint64_t get_adrp_add_va_target(uint32_t *adrpp){
    uint32_t adrp = *adrpp;
    uint32_t add = *(adrpp + 1);

    uint32_t immlo = bits(adrp, 29, 30);
    uint32_t immhi = bits(adrp, 5, 23);

    return sign_extend(((immhi << 2) | immlo) << 12, 32) +
        (xnu_ptr_to_va(adrpp) & ~0xfffuLL) + bits(add, 10, 21);
}

static uint64_t get_adr_va_target(uint32_t *adrp){
    uint32_t immlo = bits(*adrp, 29, 30);
    uint32_t immhi = bits(*adrp, 5, 23);

    return sign_extend((immhi << 2) | immlo, 21) + xnu_ptr_to_va(adrp);
}

#define IS_B_NE(opcode) ((opcode & 0xff000001) == 0x54000001)

static uint64_t g_proc_pid_addr = 0;
static uint64_t g_sysent_addr = 0;
static uint64_t g_kalloc_canblock_addr = 0;
static uint64_t g_kfree_addr_addr = 0;

static uint64_t g_exec_scratch_space_addr = 0;
/* don't count the first opcode */
static uint64_t g_exec_scratch_space_size = -sizeof(uint32_t);

static uint64_t g_sysctl__kern_children_addr = 0;
static uint64_t g_sysctl_register_oid_addr = 0;
static uint64_t g_sysctl_handle_long_addr = 0;

static bool g_patched_mach_syscall = false;

/* confirmed working on all kernels 13.0-13.6.1 */
static bool proc_pid_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* we've landed inside proc_check_inherit_ipc_ports,
     * the first BL from this point on is branching to proc_pid
     */
    uint32_t instr_limit = 20;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    int32_t imm26 = sign_extend((*opcode_stream & 0x3ffffff) << 2, 26);
    uint32_t *proc_pid = (uint32_t *)((intptr_t)opcode_stream + imm26);

    g_proc_pid_addr = xnu_ptr_to_va(proc_pid);

    puts("svc_stalker: found proc_pid");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool sysent_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* if we're in the right place, sysent will be the first ADRP/ADD
     * pair we find when we go forward
     */
    uint32_t instr_limit = 10;

    while((*opcode_stream & 0x9f000000) != 0x90000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    /* make sure this is actually sysent. to do this, we can check if
     * the first entry is the indirect system call
     */
    uint64_t addr_va = 0;

    if(bits(*opcode_stream, 31, 31) == 0)
        addr_va = get_adr_va_target(opcode_stream);
    else
        addr_va = get_adrp_add_va_target(opcode_stream);

    uint64_t maybe_sysent = (uint64_t)xnu_va_to_ptr(addr_va);

    if(*(uint64_t *)maybe_sysent != 0 &&
            *(uint64_t *)(maybe_sysent + 0x8) == 0 &&
            *(uint32_t *)(maybe_sysent + 0x10) == 1 &&
            *(uint16_t *)(maybe_sysent + 0x14) == 0 &&
            *(uint16_t *)(maybe_sysent + 0x16) == 0){
        xnu_pf_disable_patch(patch);

        g_sysent_addr = addr_va;

        puts("svc_stalker: found sysent");

        return true;
    }

    return false;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool kalloc_canblock_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* if we're in the right place, we should find kalloc_canblock's prologue
     * no more than 10 instructions before
     *
     * looking for sub sp, sp, n
     */
    uint32_t instr_limit = 10;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    xnu_pf_disable_patch(patch);

    g_kalloc_canblock_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found kalloc_canblock");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool kfree_addr_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* we should have landed inside kfree_addr, but just to make sure,
     * look for "kfree on an address not in the kernel" from this point on
     */
    uint32_t instr_limit = 200;
    bool inside_kfree_addr = 0;

    while(instr_limit-- != 0){
        /* ADRP/ADD or ADR/NOP */
        if((*opcode_stream & 0x1f000000) == 0x10000000){
            uint64_t addr_va = 0;

            if(bits(*opcode_stream, 31, 31) == 0)
                addr_va = get_adr_va_target(opcode_stream);
            else
                addr_va = get_adrp_add_va_target(opcode_stream);

            char *string = xnu_va_to_ptr(addr_va);

            const char *match = "kfree on an address not in the kernel";
            size_t matchlen = strlen(match);

            if(memmem(string, matchlen + 1, match, matchlen)){
                inside_kfree_addr = true;
                break;
            }
        }

        opcode_stream++;
    }

    if(!inside_kfree_addr)
        return false;

    xnu_pf_disable_patch(patch);

    /* find kfree_addr's prologue
     *
     * looking for sub sp, sp, n
     */
    instr_limit = 200;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_kfree_addr_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found kfree_addr");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool mach_syscall_patcher(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* we've landed inside of mach_syscall
     *
     * since we're patching exception_triage_thread to return to caller
     * on EXC_SYSCALL & EXC_MACH_SYSCALL, we need to patch out the call
     * to exception_triage and the panic about returning from it on a bad
     * Mach trap number (who even uses this functionality anyway?)
     *
     * go forward and check ADRP,ADD/ADR,NOP pairs
     */
    uint32_t instr_limit = 300;
    bool inside_mach_syscall = false;

    while(instr_limit-- != 0){
        if((*opcode_stream & 0x1f000000) == 0x10000000){
            uint64_t addr_va = 0;

            if(bits(*opcode_stream, 31, 31) == 0)
                addr_va = get_adr_va_target(opcode_stream);
            else
                addr_va = get_adrp_add_va_target(opcode_stream);

            char *string = xnu_va_to_ptr(addr_va);

            const char *match = "Returned from exception_triage()?";
            size_t matchlen = strlen(match);

            if(memmem(string, matchlen + 1, match, matchlen)){
                inside_mach_syscall = true;
                break;
            }
        }

        opcode_stream++;
    }

    if(!inside_mach_syscall)
        return false;

    xnu_pf_disable_patch(patch);

    /* sitting on the ADRP or ADR right after bl exception_triage, go back one */
    opcode_stream--;

    /* bl exception_triage/adrp/add or bl exception_triage/adr/nop --> nop/nop/nop
     *
     * don't need to set return value
     */
    opcode_stream[0] = 0xd503201f;
    opcode_stream[1] = 0xd503201f;
    opcode_stream[2] = 0xd503201f;

    /* those are patched out, but we can't just return from this function
     * without fixing up the stack, so find mach_syscall's epilogue
     *
     * search up, looking for ldp x29, x30, [sp, n]
     */
    uint32_t *branch_from = opcode_stream + 3;

    instr_limit = 200;

    while((*opcode_stream & 0xffc07fff) != 0xa9407bfd){
        if(instr_limit-- == 0){
            puts("svc_stalker: mach_syscall_patcher:");
            puts("     couldn't find epilogue");
            puts("     for mach_syscall");
            return false;
        }

        opcode_stream--;
    }

    uint32_t *epilogue = opcode_stream;

    uint32_t imm26 = (epilogue - branch_from) & 0x3ffffff;
    uint32_t epilogue_branch = (5 << 26) | imm26;

    /* bl _panic --> branch to mach_syscall epilogue */
    *branch_from = epilogue_branch;
    g_patched_mach_syscall = true;

    puts("svc_stalker: patched mach_syscall");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool ExceptionVectorsBase_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* According to XNU source, _ExceptionVectorsBase is page aligned. We're
     * going to abuse that fact and use the executable free space before
     * it to write the handle_svc hook and svc_stalker_ctl.
     *
     * For all the devices I've tested this with, the free space before
     * _ExceptionVectorsBase is filled with NOPs, but I don't want to assume
     * that will be the case for all kernels. The exc_vectors_table will be
     * before _ExceptionVectorsBase, so I'll search up until I hit something
     * which looks like a kernel pointer.
     *
     * see osfmk/arm64/locore.s inside XNU source
     */
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    xnu_pf_disable_patch(patch);

    uint32_t limit = PAGE_SIZE / 4;
    bool got_exc_vectors_table = false;

    while(limit-- != 0){
        uint32_t cur = *opcode_stream;

        /* in case of tagged pointers */
        cur |= (0xffff << 16);

        if(cur == 0xfffffff0){
            got_exc_vectors_table = true;
            break;
        }

        g_exec_scratch_space_size += sizeof(uint32_t);
        opcode_stream--;
    }

    if(!got_exc_vectors_table){
        puts("svc_stalker: didn't find");
        puts("     exc_vectors_table?");
        stalker_fatal_error();
    }

    /* we're currently at the upper 32 bits of the last pointer in
     * exc_vectors_table
     */
    opcode_stream++;
    g_exec_scratch_space_size -= sizeof(uint32_t);

    puts("svc_stalker: found unused executable code");
    g_exec_scratch_space_addr = xnu_ptr_to_va(opcode_stream);
    
    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool sysctl__kern_children_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* we should have landed right inside _kmeminit.
     *
     * The ADRP X20, n or ADR X20, n will lead us to sysctl__kern_children.
     */
    /* advance to the ADRP X20, n or ADR X20 */
    opcode_stream += 2;

    uint64_t addr_va = 0;

    if(bits(*opcode_stream, 31, 31) == 0)
        addr_va = get_adr_va_target(opcode_stream);
    else
        addr_va = get_adrp_add_va_target(opcode_stream);

    g_sysctl__kern_children_addr = *(uint64_t *)xnu_va_to_ptr(addr_va);

    /* tagged pointer */
    if((g_sysctl__kern_children_addr & 0xffff000000000000) != 0xffff000000000000){
        /* untag and slide */
        g_sysctl__kern_children_addr |= ((uint64_t)0xffff << 48);
        g_sysctl__kern_children_addr += kernel_slide;
    }

    puts("svc_stalker: found sysctl__kern_children");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool sysctl_register_oid_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* the BL we matched is guarenteed to be sysctl_register_oid */
    int32_t imm26 = sign_extend((opcode_stream[5] & 0x3ffffff) << 2, 26);
    uint32_t *sysctl_register_oid = (uint32_t *)((intptr_t)(opcode_stream + 5) + imm26);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);

    puts("svc_stalker: found sysctl_register_oid");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool sysctl_handle_long_finder(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* the patchfinder landed us at sysctl_handle_long or sysctl_handle_quad,
     * whichever came first in the kernelcache, because these functions are
     * pretty much identical. Both of them can act as sysctl_handle_long and
     * be fine.
     */
    g_sysctl_handle_long_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found sysctl_handle_long");

    return true;
}

/* confirmed working on all kernels 13.0-13.6.1 */
static bool patch_exception_triage_thread(uint32_t *opcode_stream){
    /* patch exception_triage_thread to return to its caller on EXC_SYSCALL and
     * EXC_MACH_SYSCALL
     *
     * we're using exception_triage as an entrypoint. The unconditional
     * branch to exception_triage_thread should be no more than five instructions
     * in front of us. Then we can calculate where the branch goes and set
     * opcode stream accordingly.
     */
    uint32_t instr_limit = 5;

    while((*opcode_stream & 0xfc000000) != 0x14000000){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    int32_t imm26 = sign_extend((*opcode_stream & 0x3ffffff) << 2, 26);

    /* opcode_stream points to beginning of exception_triage_thread */
    opcode_stream = (uint32_t *)((intptr_t)opcode_stream + imm26);

    /* We're looking for two clusters of instructions:
     *
     *  CMP             Wn, #4
     *  B.CS            xxx
     *
     *  and
     *
     *  CMP             Wn, #4
     *  B.CC            xxx
     *
     * Searching linearly will work fine.
     */
    uint32_t *cmp_wn_4_first = NULL;
    uint32_t *b_cs = NULL;

    uint32_t *cmp_wn_4_second = NULL;
    uint32_t *b_cc = NULL;

    instr_limit = 500;

    while(instr_limit-- != 0){
        /* found a cmp Wn, 4 */
        if((*opcode_stream & 0xfffffc1f) == 0x7100101f){
            /* next instruction is a conditional branch? */
            if((opcode_stream[1] & 0xff000000) == 0x54000000){
                /* this branch's condition code is cs or cc? */
                if(((opcode_stream[1] & 0xe) >> 1) == 1){
                    /* condition code is cs? */
                    if((opcode_stream[1] & 1) == 0){
                        cmp_wn_4_first = opcode_stream;
                        b_cs = opcode_stream + 1;
                    }
                    /* condition code is cc? */
                    else{
                        cmp_wn_4_second = opcode_stream;
                        b_cc = opcode_stream + 1;
                    }
                }
            }
        }

        if(cmp_wn_4_first && cmp_wn_4_second && b_cs && b_cc)
            break;

        opcode_stream++;
    }
    
    if(!cmp_wn_4_first || !cmp_wn_4_second || !b_cs || !b_cc){
        if(!cmp_wn_4_first)
            puts("cmp_wn_4_first not found");

        if(!cmp_wn_4_second)
            puts("cmp_wn_4_second not found");

        if(!b_cs)
            puts("b_cs not found");

        if(!b_cc)
            puts("b_cc not found");

        /* return back so we can print what happened */
        return false;
    }

    uint32_t cmn_w0_negative_3 = 0x31000c1f;

    /* both cmp Wn, 4 --> cmn Wn, -3 */
    *cmp_wn_4_first = cmn_w0_negative_3 | (*cmp_wn_4_first & 0x3e0);
    *cmp_wn_4_second = cmn_w0_negative_3 | (*cmp_wn_4_second & 0x3e0);

    /* b.cs --> b.lt */
    *b_cs = (*b_cs & ~0xf) | 0xb;

    /* b.cc --> b.ge */
    *b_cc = (*b_cc & ~0xf) | 0xa;

    puts("svc_stalker: patched exception_triage_thread");

    return true;
}

/* confirmed working on all kernels 13.0-13.6 */
static bool sleh_synchronous_patcher(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    if(g_proc_pid_addr == 0 || g_sysent_addr == 0 ||
            g_kalloc_canblock_addr == 0 || g_kfree_addr_addr == 0 ||
            !g_patched_mach_syscall || g_sysctl__kern_children_addr == 0 ||
            g_sysctl_register_oid_addr == 0 || g_sysctl_handle_long_addr == 0){
        puts("svc_stalker: error(s) before");
        puts("     we patch sleh_synchronous:");
        
        if(g_proc_pid_addr == 0)
            puts("   proc_pid not found");

        if(g_sysent_addr == 0)
            puts("   sysent not found");

        if(g_kalloc_canblock_addr == 0){
            puts("   kalloc_canblock");
            puts("     not found");
        }
            
        if(g_kfree_addr_addr == 0){
            puts("   kfree_addr");
            puts("     not found");
        }

        if(!g_patched_mach_syscall){
            puts("   did not patch");
            puts("     mach_syscall");
        }

        if(g_sysctl__kern_children_addr == 0){
            puts("   sysctl__kern_children");
            puts("     not found");
        }

        if(g_sysctl_register_oid_addr == 0){
            puts("   sysctl_register_oid");
            puts("     not found");
        }

        if(g_sysctl_handle_long_addr == 0){
            puts("   sysctl_handle_long");
            puts("     not found");
        }

        stalker_fatal_error();
    }

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
        stalker_fatal_error();
    }

    opcode_stream--;

    /* not TST Wn, 0xc? */
    if((*opcode_stream & 0xfffffc1f) != 0x721e041f){
        puts("sleh_synchronous_patcher: Not tst Wn, 0xc, opcode:");
        print_register(*opcode_stream);
        stalker_fatal_error();
    }

    opcode_stream--;

    /* not LDRB Wn, [X19, n]? */
    if((*opcode_stream & 0xffc003e0) != 0x39400260){
        puts("sleh_synchronous_patcher: Not ldrb Wn, [x19, n], opcode:");
        print_register(*opcode_stream);
        stalker_fatal_error();
    }

    opcode_stream--;

    /* not B.NE xxx? */
    if(!IS_B_NE(*opcode_stream)){
        puts("sleh_synchronous_patcher: Not b.ne, opcode:");
        print_register(*opcode_stream);
        stalker_fatal_error();
    }

    opcode_stream--;

    /* not CMP Wn, 0x15? */
    if((*opcode_stream & 0xfffffc1f) != 0x7100541f){
        puts("sleh_synchronous_patcher: Not cmp Wn, 0x15, opcode:");
        print_register(*opcode_stream);
        stalker_fatal_error();
    }

    opcode_stream--;

    /* not LDR Wn, [X19]? */
    if((*opcode_stream & 0xffffffe0) != 0xb9400260){
        puts("sleh_synchronous_patcher: Not ldr Wn, [x19], opcode:");
        print_register(*opcode_stream);
        stalker_fatal_error();
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
            puts("svc_stalker: didn't");
            puts("     find two");
            puts("     MRS Xn, TPIDR_EL1's");
            stalker_fatal_error();
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
            puts("svc_stalker: couldn't find");
            puts("     current_proc");
            stalker_fatal_error();
        }

        opcode_stream++;
    }

    int32_t imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28);
    uint64_t current_proc_addr = imm26 + xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found current_proc");

    /* now we need to find exception_triage. We can do this by going forward
     * until we hit a BRK, as it's right after the call to exception_triage
     * and it's the only BRK in sleh_synchronous.
     */
    instr_limit = 1000;

    while((*opcode_stream & 0xffe0001f) != 0xd4200000){
        if(instr_limit-- == 0){
            puts("svc_stalker: couldn't");
            puts("     find exception_triage");
            stalker_fatal_error();
        }

        opcode_stream++;
    }

    /* we're at BRK n, go up one for the branch to exception_triage */
    opcode_stream--;

    imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28);
    uint64_t exception_triage_addr = imm26 + xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found exception_triage");

    if(!patch_exception_triage_thread(xnu_va_to_ptr(exception_triage_addr))){
        puts("svc_stalker: failed");
        puts("     patching");
        puts("     exception_triage_thread");
        stalker_fatal_error();
    }

    uint64_t handle_svc_hook_cache_size = 11 * sizeof(uint64_t);
    uint64_t svc_stalker_ctl_cache_size = 3 * sizeof(uint64_t);
    
    /* both defined in handle_svc_hook_patches.h & svc_stalker_ctl_patches.h */
    size_t needed_sz =
        /* instructions */
        ((g_handle_svc_hook_num_instrs + g_svc_stalker_ctl_num_instrs) * 4) +
        /* cache space */
        handle_svc_hook_cache_size + svc_stalker_ctl_cache_size;

    /* if there's not enough space between the end of exc_vectors_table
     * and _ExceptionVectorsBase, maybe there's enough space at the last
     * section of __TEXT_EXEC?
     * 
     * I don't think this will ever happen but just in case
     */
    if(needed_sz > g_exec_scratch_space_size){
        puts("svc_stalker: not enough space");
        puts("     between exc_vectors_table");
        puts("     and _ExceptionVectorsBase,");
        puts("     falling back to end of");
        puts("     last section in __TEXT_EXEC");

        struct segment_command_64 *__TEXT_EXEC = macho_get_segment(mh_execute_header,
                "__TEXT_EXEC");
        struct section_64 *last_TEXT_EXEC_sect =
            &((struct section_64 *)(__TEXT_EXEC + 1))[__TEXT_EXEC->nsects - 1];

        uint64_t last_sect_end = last_TEXT_EXEC_sect->addr + last_TEXT_EXEC_sect->size;

        g_exec_scratch_space_addr = last_sect_end;

        uint64_t seg_end = __TEXT_EXEC->vmaddr + __TEXT_EXEC->vmsize;

        g_exec_scratch_space_size = seg_end - last_sect_end;

        /* still too little space? Incompatible kernel */
        if(needed_sz > g_exec_scratch_space_size){
            puts("svc_stalker: this kernel is");
            puts("     incompatible! couldn't");
            puts("     find a suitable place");
            puts("     to put our code!");
            puts("Spinning forever.");

            for(;;);
            __builtin_unreachable();
        }
    }

    uint64_t num_free_instrs = g_exec_scratch_space_size / sizeof(uint32_t);
    uint32_t *scratch_space = xnu_va_to_ptr(g_exec_scratch_space_addr);

    /* don't merge the next two macros because this is better for readability */
#define WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(qword) \
    do { \
        if(num_free_instrs < 2){ \
            puts("svc_stalker: ran out"); \
            puts("     of space for hook"); \
            stalker_fatal_error(); \
        } \
        *(uint64_t *)scratch_space = (qword); \
        scratch_space += 2; \
        num_free_instrs -= 2; \
    } while (0) \

#define WRITE_QWORD_TO_SVC_STALKER_CTL_CACHE(qword) \
    do { \
        if(num_free_instrs < 2){ \
            puts("svc_stalker: ran out"); \
            puts("     of space for hook"); \
            stalker_fatal_error(); \
        } \
        *(uint64_t *)scratch_space = (qword); \
        scratch_space += 2; \
        num_free_instrs -= 2; \
    } while (0) \

#define WRITE_INSTR(opcode) \
    do { \
        if(num_free_instrs == 0){ \
            puts("svc_stalker: ran out"); \
            puts("     of space for hook"); \
            stalker_fatal_error(); \
        } \
        *scratch_space = (opcode); \
        scratch_space++; \
        num_free_instrs--; \
    } while (0) \

    /* struct stalker_ctl {
     *       is this entry not being used?
     *     uint32_t free;
     *
     *       what pid this entry belongs to
     *     int32_t pid;
     *
     *       list of system call numbers to intercept & send to userland
     *     int64_t *call_list;
     * };
     *
     * Empty spots in the call list are represented by PAGE_SIZE 
     * because it doesn't represent any system call or mach trap.
     *
     * sizeof(struct stalker_ctl) = 0x10
     */
    const size_t sizeof_struct_stalker_ctl = 0x10;
    size_t stalker_table_capacity = 1024;
    size_t stalker_table_sz = stalker_table_capacity * sizeof_struct_stalker_ctl;
    uint8_t *stalker_table = alloc_static(stalker_table_sz);

    if(!stalker_table){
        puts("svc_stalker: alloc_static");
        puts("     returned NULL when");
        puts("     allocating mem for");
        puts("     stalker table");
        stalker_fatal_error();
    }

    const uint8_t *stalker_table_end = stalker_table + stalker_table_sz;

    /* the first uint64_t will hold the number of stalker structs that
     * are currently in the table
     */
    *(uint64_t *)stalker_table = 0;

    /* the second uint64_t represents if we've added the new sysctl
     * which gives us svc_stalker_ctl's system call number
     */
    *(uint64_t *)(stalker_table + 0x8) = 0;

    uint8_t *cursor = stalker_table + sizeof_struct_stalker_ctl;

    while(cursor < stalker_table_end){
        /* all initial stalker_ctl structs are free */
        *(uint32_t *)cursor = 1;
        /* free stalker_ctl structs belong to no one */
        *(int32_t *)(cursor + 0x4) = 0;
        /* free stalker_ctl structs have no call list */
        *(uintptr_t *)(cursor + 0x8) = 0;

        cursor += sizeof_struct_stalker_ctl;
    }

    /* stash these pointers so we have them after xnu boot */
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(exception_triage_addr);
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(current_proc_addr);
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(g_proc_pid_addr);
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(xnu_ptr_to_va(stalker_table));

    /* we also need to stash the patched system call number, but we don't
     * know it yet, so just reserve space for it and set it later
     */
    uint64_t reserved = 0;
    uint64_t *patched_syscall_num_cache_ptr = (uint64_t *)scratch_space;
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(reserved);

    char *string_space = alloc_static(PAGE_SIZE);

    if(!string_space){
        puts("svc_stalker: alloc_static");
        puts("     returned NULL when");
        puts("     allocating mem for");
        puts("     sysctl strings");
        stalker_fatal_error();
    }

    /* sysctl name for the system call number */
    const char *sysctl_name = "svc_stalker_ctl_callnum";
    strcpy(string_space, sysctl_name);

    const char *sysctl_descr = "query for svc_stalker_ctl's system call number";
    size_t sysctl_name_len = strlen(sysctl_name);
    char *sysctl_descr_loc = string_space + sysctl_name_len + 1;
    strcpy(sysctl_descr_loc, sysctl_descr);

    /* how sysctl should format the call number, long */
    size_t sysctl_descr_len = strlen(sysctl_descr);
    char *sysctl_fmt_loc = sysctl_descr_loc + strlen(sysctl_descr) + 1;
    strcpy(sysctl_fmt_loc, "L");
    
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(xnu_ptr_to_va(string_space));
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(xnu_ptr_to_va(sysctl_descr_loc));
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(xnu_ptr_to_va(sysctl_fmt_loc));
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(g_sysctl__kern_children_addr);
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(g_sysctl_register_oid_addr);
    WRITE_QWORD_TO_HANDLE_SVC_HOOK_CACHE(g_sysctl_handle_long_addr);

    /* autogenerated by hookgen.pl, see handle_svc_patches.h */
    /* Needs to be done before we patch the sysent entry so scratch_space lies
     * right after the end of the handle_svc hook.
     */
    DO_HANDLE_SVC_HOOK_PATCHES;

    /* write the stalker table pointer so the patched syscall can get it easily
     *
     * needs to be here so scratch_space points after this when we go
     * to patch the sysent entry
     */
    WRITE_QWORD_TO_SVC_STALKER_CTL_CACHE(xnu_ptr_to_va(stalker_table));
    WRITE_QWORD_TO_SVC_STALKER_CTL_CACHE(g_kalloc_canblock_addr);
    WRITE_QWORD_TO_SVC_STALKER_CTL_CACHE(g_kfree_addr_addr);

    /* now we need to find the first enosys entry in sysent to patch
     * our syscall in.
     *
     * enosys literally just returns ENOSYS, so it will be pretty easy
     * to find.
     */
    uint8_t *sysent_stream = (uint8_t *)xnu_va_to_ptr(g_sysent_addr);
    size_t sizeof_struct_sysent = 0x18;

    uint32_t patched_syscall_num = 0;
    uint8_t *sysent_to_patch = NULL;

    bool tagged_ptr = false;
    uint16_t old_tag = 0;

    uint32_t limit = 1000;

    for(uint32_t i=0; ; i++){
        if(limit-- == 0){
            puts("svc_stalker: didn't");
            puts("     find a sysent entry");
            puts("     with enosys?");
            stalker_fatal_error();
        }

        uint64_t sy_call = *(uint64_t *)sysent_stream;

        /* tagged pointer */
        if((sy_call & 0xffff000000000000) != 0xffff000000000000){
            old_tag = (sy_call >> 48);

            sy_call |= 0xffff000000000000;
            sy_call += kernel_slide;

            tagged_ptr = true;
        }

        /* mov w0, ENOSYS; ret */
        if(*(uint64_t *)xnu_va_to_ptr(sy_call) == 0xd65f03c0528009c0){
            sysent_to_patch = sysent_stream;
            patched_syscall_num = i;

            *(uint64_t *)patched_syscall_num_cache_ptr = (uint64_t)i;

            /* sy_call */
            if(!tagged_ptr)
                *(uint64_t *)sysent_to_patch = xnu_ptr_to_va(scratch_space);
            else{
                uint64_t untagged = (xnu_ptr_to_va(scratch_space) &
                    0xffffffffffff) - kernel_slide;

                /* re-tag */
                uint64_t new_sy_call = untagged | ((uint64_t)old_tag << 48);

                *(uint64_t *)sysent_to_patch = new_sy_call;
            }

            /* no 32 bit processes on iOS 11+, so no argument munger */
            *(uint64_t *)(sysent_to_patch + 0x8) = 0;

            /* this syscall will return an integer */
            *(int32_t *)(sysent_to_patch + 0x10) = 1; /* _SYSCALL_RET_INT_T */

            /* this syscall has four arguments */
            *(int16_t *)(sysent_to_patch + 0x14) = 4;

            /* four 32 bit arguments, so arguments total 16 bytes */
            *(uint16_t *)(sysent_to_patch + 0x16) = 0x10;

            break;
        }

        sysent_stream += sizeof_struct_sysent;
    }

    /* autogenerated by hookgen.pl, see svc_stalker_ctl_patches.h */
    DO_SVC_STALKER_CTL_PATCHES;

    uint64_t branch_to = g_exec_scratch_space_addr + handle_svc_hook_cache_size;

    write_blr(8, branch_from, branch_to);

    /* there's an extra B.NE after the five instrs we overwrote, so NOP it out */
    *(uint32_t *)(branch_from + (sizeof(uint32_t) * 5)) = 0xd503201f;

    puts("svc_stalker: patched sleh_synchronous");

    /* allow querying of kern.svc_stalker_ctl_callnum in sandboxed processes
     *
     * I install a hook in hook_system_check_sysctlbyname which checks if the
     * third parameter, the MIB array for the sysctl, and the fourth parameter,
     * the length of that MIB array, matches the MIB array of the
     * kern.svc_stalker_ctl_callnum and return back to its caller if it does.
     *
     * Originally I was going to strcmp the first parameter, the sysctl name
     * string, against kern.svc_stalker_ctl_callnum, but this function is
     * called constantly and I don't want to cause noticable slowdowns.
     *
     * Unfortunately, there's no sanity checks for me to overwrite, but there
     * is a lot of "parameter moving" after the prologue, so I can use that
     * space. I'll save the instructions we overwrote and restore them after
     * I pop the callee-saved registers from the stack but before I return
     * back to hook_system_check_sysctlbyname in the event the MIB array doesn't
     * match that of kern.svc_stalker_ctl_callnum's.
     */

    /* XXX hardcoded for iphone 8 13.6.1 */
    // XXX how do I separate this functionality without creating more globals
    // this depends on scratch_space sitting after the end of svc_stalker_ctl
    // maybe rename this function to stalker_main_patcher...

    branch_to = xnu_ptr_to_va(scratch_space);

    /* autogenerated by hookgen.pl, see hook_system_check_sysctlbyname_hook_patches.h */
    DO_HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK_PATCHES;

    /* calling write_blr overwrites five instructions */
    /* uint32_t saved_instrs[5]; */
    branch_from = (uint64_t)xnu_va_to_ptr(0xFFFFFFF008C77D40 + kernel_slide);

    /* saved_instrs[0] = *(uint32_t *)branch_from; */
    /* saved_instrs[1] = *(uint32_t *)(branch_from + 0x4); */
    /* saved_instrs[2] = *(uint32_t *)(branch_from + 0x8); */
    /* saved_instrs[3] = *(uint32_t *)(branch_from + 0xc); */
    /* saved_instrs[4] = *(uint32_t *)(branch_from + 0x10); */

    /* for(int i=0; i<5; i++){ */
    /*     print_register(saved_instrs[i]); */
    /* } */
    /* for(;;); */

    /* restore the five instructions we overwrote at the end of
     * system_check_sysctlbyname_hook to the end of `notours`
     * in hook_system_check_sysctlbyname_hook.s
     */
    WRITE_INSTR(*(uint32_t *)branch_from);
    WRITE_INSTR(*(uint32_t *)(branch_from + 0x4));
    WRITE_INSTR(*(uint32_t *)(branch_from + 0x8));
    WRITE_INSTR(*(uint32_t *)(branch_from + 0xc));
    WRITE_INSTR(*(uint32_t *)(branch_from + 0x10));
    WRITE_INSTR(0xd65f03c0);    /* ret */

    write_blr(8, branch_from, branch_to);

#define IMPORTANT_MSG(x) \
    putchar('*'); \
    putchar(' '); \
    puts(x); \

    puts("***** IMPORTANT *****");
    IMPORTANT_MSG("System call ");
    /* printf doesn't print this correctly? */
    print_register(patched_syscall_num);
    IMPORTANT_MSG("has been patched.");
    IMPORTANT_MSG("It is your way");
    IMPORTANT_MSG("of controlling what");
    IMPORTANT_MSG("processes you intercept");
    IMPORTANT_MSG("system calls for.");
    IMPORTANT_MSG("Please refer back to the");
    IMPORTANT_MSG("README for info about");
    IMPORTANT_MSG("this patched system call.");
    IMPORTANT_MSG("You can also use");
    IMPORTANT_MSG("sysctlbyname to query");
    IMPORTANT_MSG("for the patched system");
    IMPORTANT_MSG("call.");
    puts("*********************");



    return true;
}

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

    xnu_pf_maskmatch(patchset, proc_pid_finder_match, proc_pid_finder_masks,
            num_proc_pid_matches, false, proc_pid_finder);

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

    xnu_pf_maskmatch(patchset, sysent_finder_match, sysent_finder_masks,
            num_sysent_matches, false, sysent_finder);

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

    xnu_pf_maskmatch(patchset, kalloc_canblock_match, kalloc_canblock_masks,
            num_kalloc_canblock_matches, false, kalloc_canblock_finder);

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

    xnu_pf_maskmatch(patchset, kfree_addr_match, kfree_addr_masks,
            num_kfree_addr_matches, false, kfree_addr_finder);

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

    xnu_pf_maskmatch(patchset, mach_syscall_patcher_match, mach_syscall_patcher_masks,
            num_mach_syscall_matches, false, mach_syscall_patcher);

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

    xnu_pf_maskmatch(patchset, ExceptionVectorsBase_finder_match,
            ExceptionVectorsBase_finder_masks, num_ExceptionVectorsBase_matches,
            false, ExceptionVectorsBase_finder);

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

    xnu_pf_maskmatch(patchset, sysctl__kern_children_finder_matches,
            sysctl__kern_children_finder_masks,
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

    xnu_pf_maskmatch(patchset, sysctl_register_oid_finder_matches,
            sysctl_register_oid_finder_masks,
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

    xnu_pf_maskmatch(patchset, sysctl_handle_long_finder_matches,
            sysctl_handle_long_finder_masks,
            num_sysctl_handle_long_finder_matches, false,
            sysctl_handle_long_finder);

    /* AMFI for proc_pid */
    struct mach_header_64 *AMFI = xnu_pf_get_kext_header(mh_execute_header,
            "com.apple.driver.AppleMobileFileIntegrity");
    xnu_pf_range_t *AMFI___TEXT_EXEC = xnu_pf_segment(AMFI, "__TEXT_EXEC");
    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");

    xnu_pf_emit(patchset);
    xnu_pf_apply(AMFI___TEXT_EXEC, patchset);
    xnu_pf_apply(__TEXT_EXEC, patchset);
    xnu_pf_patchset_destroy(patchset);
}

/* static void patch_sleh_synchronous_without_booting(const char *cmd, char *args){ */
/*     uint64_t sleh_synchronous_patcher_match[] = { */
/*         0xb9408a60,     /1* LDR Wn, [X19, #0x88] (trap_no = state->__x[16]) *1/ */
/*         0xd538d080,     /1* MRS Xn, TPIDR_EL1    (Xn = current_thread()) *1/ */
/*         0x12800000,     /1* MOV Wn, 0xFFFFFFFF   (Wn = THROTTLE_LEVEL_NONE) *1/ */
/*     }; */

/*     const size_t num_ss_matches = sizeof(sleh_synchronous_patcher_match) / */ 
/*         sizeof(*sleh_synchronous_patcher_match); */

/*     uint64_t sleh_synchronous_patcher_masks[] = { */
/*         0xffffffe0,     /1* ignore Wn in LDR *1/ */
/*         0xffffffe0,     /1* ignore Xn in MRS *1/ */
/*         0xffffffe0,     /1* ignore Wn in MOV *1/ */
/*     }; */

/*     xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC"); */

/*     xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT); */
/*     xnu_pf_maskmatch(patchset, sleh_synchronous_patcher_match, */
/*             sleh_synchronous_patcher_masks, num_ss_matches, false, */
/*             sleh_synchronous_patcher); */
/*     xnu_pf_emit(patchset); */
/*     xnu_pf_apply(__TEXT_EXEC, patchset); */

/*     xnu_pf_patchset_destroy(patchset); */
/* } */

static void (*next_preboot_hook)(void);

static void stalker_preboot_hook(void){
    uint64_t sleh_synchronous_patcher_match[] = {
        0xb9408a60,     /* LDR Wn, [X19, #0x88] (trap_no = state->__x[16]) */
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

    xnu_pf_range_t *__TEXT_EXEC = xnu_pf_segment(mh_execute_header, "__TEXT_EXEC");

    xnu_pf_patchset_t *patchset = xnu_pf_patchset_create(XNU_PF_ACCESS_32BIT);
    xnu_pf_maskmatch(patchset, sleh_synchronous_patcher_match,
            sleh_synchronous_patcher_masks, num_ss_matches, false,
            sleh_synchronous_patcher);
    xnu_pf_emit(patchset);
    xnu_pf_apply(__TEXT_EXEC, patchset);

    xnu_pf_patchset_destroy(patchset);

    if(next_preboot_hook)
        next_preboot_hook();
}

void module_entry(void){
    puts("svc_stalker: loaded!");

    mh_execute_header = xnu_header();
    kernel_slide = xnu_slide_value(mh_execute_header);

    next_preboot_hook = preboot_hook;
    preboot_hook = stalker_preboot_hook;

    command_register("stalker-prep", "prep to patch sleh_synchronous", stalker_prep);
    /* command_register("stalker-patch", */
    /*         "patch sleh_synchronous without booting", */
    /*         patch_sleh_synchronous_without_booting); */
}

const char *module_name = "svc_stalker";

struct pongo_exports exported_symbols[] = {
    { .name = 0, .value = 0 }
};
