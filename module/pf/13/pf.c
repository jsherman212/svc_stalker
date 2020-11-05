#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/sysctl.h>

#include "../disas.h"
#include "../macho.h"
#include "../offsets.h"
#include "../pf_common.h"

#include "../../common/common.h"
#include "../../common/pongo.h"
#include "../../common/stalker_table.h"

/* this function scans opcode_stream for calls to thread_exception_return */
static void scan_for_ter_13(uint32_t *opcode_stream, uint64_t fxn_len,
        uint32_t **ter_calls_out){
    uint32_t cur_ter_calls_idx = 0;

    for(int i=0; i<fxn_len; i++){
        uint32_t instr = opcode_stream[i];

        /* b or bl? */
        if((instr & 0x7c000000) == 0x14000000){
            uint32_t *dst = get_branch_dst_ptr(instr, opcode_stream + i);

            /* first instr in this function is mov x0, TPIDR_EL1? */
            if(*dst == 0xd538d080){
                ter_calls_out[cur_ter_calls_idx] = opcode_stream + i;
                cur_ter_calls_idx++;
            }
        }
    }
}

static void scan_for_ter_14(uint32_t *opcode_stream, uint64_t fxn_len,
        uint32_t **ter_calls_out){
    uint32_t cur_ter_calls_idx = 0;

    /* 1000 == fxn_len in svc_stalker.c */
    for(int i=0; i<fxn_len; i++){
        uint32_t instr = opcode_stream[i];

        /* On iOS 14, thread_exception_return does some kdebug stuff and then
         * calls arm64_thread_exception_return. So now it has a normal function
         * prologue, which is such a pia because I have to check every single
         * B/BL and need to make sure the function matches the format of
         * thread_exception_return
         */
        /* b or bl? */
        if((instr & 0x7c000000) == 0x14000000){
            uint32_t *dst = get_branch_dst_ptr(instr, opcode_stream + i);

            /* okay, we got a branch. thread_exception_return starts with
             * stp,stp,add,[mrs x19, tpidr_el1],ldrh, so lets match that first
             *
             * Trying to match:
             * stp xn, xn, [sp, n]!
             * stp xn, xn, [sp, n]
             * add x29, sp, n
             * mrs x19, TPIDR_EL1
             * ldrh w8, [x19, n]
             */
            if((*dst & 0xffc003e0) == 0xa98003e0 &&
                    (dst[1] & 0xffc003e0) == 0xa90003e0 &&
                    (dst[2] & 0xffc003ff) == 0x910003fd &&
                    dst[3] == 0xd538d093 && (dst[4] & 0xffc003ff) == 0x79400268){
                /* This may be thread_exception_return, but to make sure,
                 * try and match the strh,[bl arm64_thread_exception_return]
                 * at the end
                 *
                 * Trying to match:
                 * strh wzr, [x19, n]
                 * bl _arm64_thread_exception_return
                 */
                uint32_t instr_limit = 30;
                uint32_t is_thread_exception_return = 1;

                while((*dst & 0xffc003ff) != 0x7900027f &&
                        (dst[1] & 0xfc000000) != 0x94000000){
                    if(instr_limit-- == 0){
                        is_thread_exception_return = 0;
                        break;
                    }

                    dst++;
                }

                if(is_thread_exception_return){
                    ter_calls_out[cur_ter_calls_idx] = opcode_stream + i;
                    cur_ter_calls_idx++;
                }
            }
        }
    }
}

static void scan_for_ter(uint32_t *opcode_stream, uint64_t fxn_len,
        uint32_t **ter_calls_out){
    if(g_kern_version_major == iOS_13)
        scan_for_ter_13(opcode_stream, fxn_len, ter_calls_out);
    else
        scan_for_ter_14(opcode_stream, fxn_len, ter_calls_out);
}

#define IS_B_NE(opcode) ((opcode & 0xff000001) == 0x54000001)

uint64_t g_proc_pid_addr = 0;
uint64_t g_sysent_addr = 0;
uint64_t g_kalloc_canblock_addr = 0;
uint64_t g_kfree_addr_addr = 0;
uint64_t g_sysctl__kern_children_addr = 0;
uint64_t g_sysctl_register_oid_addr = 0;
uint64_t g_sysctl_handle_long_addr = 0;
uint64_t g_name2oid_addr = 0;
uint64_t g_sysctl_geometry_lock_addr = 0;
uint64_t g_lck_rw_lock_shared_addr = 0;
uint64_t g_lck_rw_done_addr = 0;
uint64_t g_h_s_c_sbn_branch_addr = 0;
uint64_t g_h_s_c_sbn_epilogue_addr = 0;
uint64_t g_mach_syscall_addr = 0;
uint32_t g_offsetof_act_context = 0;
uint64_t g_thread_exception_return_addr = 0;
uint64_t g_platform_syscall_start_addr = 0;
uint64_t g_platform_syscall_end_addr = 0;
uint64_t g_thread_syscall_return_start_addr = 0;
uint64_t g_thread_syscall_return_end_addr = 0;
uint64_t g_unix_syscall_return_start_addr = 0;
uint64_t g_unix_syscall_return_end_addr = 0;
uint64_t g_lck_grp_alloc_init_addr = 0;
uint64_t g_lck_rw_alloc_init_addr = 0;
uint64_t g_current_proc_addr = 0;
uint64_t g_exception_triage_addr = 0;
uint64_t g_common_fxns_get_stalker_cache_addr = 0;
uint64_t g_stalker_ctl_from_table_addr = 0;
uint64_t g_should_intercept_call_addr = 0;
uint64_t g_get_next_free_stalker_ctl_addr = 0;
uint64_t g_is_sysctl_registered_addr = 0;
uint64_t g_send_exception_msg_addr = 0;
uint64_t g_get_flag_ptr_for_call_num_addr = 0;
uint64_t g_stalker_table_ptr = 0;
uint64_t g_svc_stalker_sysctl_name_ptr = 0;
uint64_t g_svc_stalker_sysctl_descr_ptr = 0;
uint64_t g_svc_stalker_sysctl_fmt_ptr = 0;
uint64_t g_svc_stalker_sysctl_mib_ptr = 0;
uint64_t g_svc_stalker_sysctl_mib_count_ptr = 0;
uint64_t g_handle_svc_hook_addr = 0;
uint64_t g_svc_stalker_ctl_callnum = 0;
uint64_t g_sleh_synchronous_addr = 0;
uint64_t g_return_interceptor_addr = 0;

uint32_t *g_platform_syscall_ter_calls[g_max_ter_calls];
uint32_t *g_thread_syscall_return_ter_calls[g_max_ter_calls];
uint32_t *g_unix_syscall_return_ter_calls[g_max_ter_calls];

bool g_patched_mach_syscall = false;

uint64_t g_exec_scratch_space_addr = 0;
/* don't count the first opcode */
uint64_t g_exec_scratch_space_size = -sizeof(uint32_t);

/* confirmed working on all kernels 13.0-14.1 */
bool proc_pid_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
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

    uint32_t *proc_pid = get_branch_dst_ptr(*opcode_stream, opcode_stream);

    g_proc_pid_addr = xnu_ptr_to_va(proc_pid);

    puts("svc_stalker: found proc_pid");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool sysent_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
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

/* confirmed working on all kernels 13.0-14.1 */
bool kalloc_canblock_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
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

/* confirmed working on all kernels 13.0-14.1 */
bool kfree_addr_finder_13(xnu_pf_patch_t *patch, void *cacheable_stream){
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

/* confirmed working on all kernels 13.0-14.1 */
bool mach_syscall_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* we've landed inside of mach_syscall
     *
     * first, find its prologue, search up, looking for sub sp, sp, n
     */
    uint32_t instr_limit = 300;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_mach_syscall_addr = xnu_ptr_to_va(opcode_stream);

    /* since we're patching exception_triage_thread to return to caller
     * on EXC_SYSCALL & EXC_MACH_SYSCALL, we need to patch out the call
     * to exception_triage and the panic about returning from it on a bad
     * Mach trap number (who even uses this functionality anyway?)
     *
     * go forward and check ADRP,ADD/ADR,NOP pairs
     */
    instr_limit = 500;
    bool found = false;

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
                found = true;
                break;
            }
        }

        opcode_stream++;
    }

    if(!found)
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
    uint32_t epilogue_branch = assemble_b((uint64_t)branch_from,
            (uint64_t)epilogue);

    /* bl _panic --> branch to mach_syscall epilogue */
    *branch_from = epilogue_branch;

    g_patched_mach_syscall = true;

    puts("svc_stalker: patched mach_syscall");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool ExceptionVectorsBase_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* What I'd really like to do is generate executable pages now and
     * write the code for all the stuff there... but page tables have not
     * been set up yet (TTBR1_EL1 is zeroed out). Also, unless I neuter KTRR
     * and AMCC, I cannot make the memory from alloc_static executable
     * during runtime by modding page tables. And I really want to keep KTRR
     * and AMCC going, so I'll have to make do with existing r-x pages.
     *
     * According to XNU source, _ExceptionVectorsBase is page aligned. We're
     * going to abuse that fact and use the executable free space before
     * it to write our code.
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
    g_exec_scratch_space_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found unused executable code");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool sysctl__kern_children_finder_13(xnu_pf_patch_t *patch,
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

/* confirmed working on all kernels 13.0-14.1 */
bool sysctl_register_oid_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* the BL we matched is guarenteed to be sysctl_register_oid */
    uint32_t *sysctl_register_oid = get_branch_dst_ptr(opcode_stream[5],
            opcode_stream + 5);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);

    puts("svc_stalker: found sysctl_register_oid");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool sysctl_handle_long_finder_13(xnu_pf_patch_t *patch,
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

/* confirmed working on all kernels 13.0-14.1 */
bool name2oid_and_its_dependencies_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* This finds name2oid and three other things:
     *      sysctl_geometry_lock (needs to be held when we call name2oid)
     *      lck_rw_lock_shared
     *      lck_rw_done
     *
     * I can only do a maskmatch with 8 matches/masks, but I need 10.
     * Those last two matches differentiate the right/wrong place because
     * the first 8 matches/masks match two places in the kernel. I'll just
     * manually check if the two instrs after the 8 we just matched are LDR/BL
     */
    uint32_t eigth = opcode_stream[8];
    uint32_t ninth = opcode_stream[9];

    if((eigth & 0xffc0001f) != 0xf9400000 && (ninth & 0xfc000000) != 0x94000000)
        return false;

    xnu_pf_disable_patch(patch);

    g_sysctl_geometry_lock_addr = get_adrp_ldr_va_target(opcode_stream);

    uint32_t *lck_rw_lock_shared = get_branch_dst_ptr(opcode_stream[2],
            opcode_stream + 2);

    g_lck_rw_lock_shared_addr = xnu_ptr_to_va(lck_rw_lock_shared);

    uint32_t *name2oid = get_branch_dst_ptr(opcode_stream[6], opcode_stream + 6);

    g_name2oid_addr = xnu_ptr_to_va(name2oid);

    uint32_t *lck_rw_done = get_branch_dst_ptr(opcode_stream[9],
            opcode_stream + 9);

    g_lck_rw_done_addr = xnu_ptr_to_va(lck_rw_done);

    puts("svc_stalker: found sysctl_geometry_lock");
    puts("svc_stalker: found lck_rw_lock_shared");
    puts("svc_stalker: found name2oid");
    puts("svc_stalker: found lck_rw_done");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool hook_system_check_sysctlbyname_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    xnu_pf_disable_patch(patch);

    /* we've landed inside hook_system_check_sysctlbyname, find the first
     * instruction after its prologue and the beginning of its epilogue
     *
     * search up, looking for sub sp, sp, n or add x29, sp, n
     */
    uint32_t instr_limit = 300;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff &&
            (*opcode_stream & 0xffc003ff) != 0x910003fd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    /* advance to the first instruction after the prologue */
    opcode_stream++;

    g_h_s_c_sbn_branch_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found h_s_c_sbn branch addr");

    /* now we need to find the beginning of its epilogue
     *
     * search down, looking for add sp, sp, n or ldp x29, x30, [sp, n]
     */
    instr_limit = 300;

    while((*opcode_stream & 0xffc003ff) != 0x910003ff &&
            (*opcode_stream & 0xffc07fff) != 0xa9407bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream++;
    }

    g_h_s_c_sbn_epilogue_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found h_s_c_sbn epilogue");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool thread_exception_return_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* we're guarenteed to have landed in thread_exception_return */
    xnu_pf_disable_patch(patch);

    g_thread_exception_return_addr = xnu_ptr_to_va(cacheable_stream);

    uint32_t add_x21_x0_n = ((uint32_t *)cacheable_stream)[1];

    g_offsetof_act_context = get_add_imm(add_x21_x0_n);

    if(g_kern_version_major == iOS_13)
        puts("svc_stalker: found thread_exception_return");
    else
        puts("svc_stalker: found arm64_thread_exception_return");

    puts("svc_stalker: found offsetof ACT_CONTEXT");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool thread_syscall_return_scanner_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    /* The purpose of this is to scan thread_syscall_return for all
     * thread_exception_return calls so we can replace them with a call
     * to return_interceptor in stalker_main_patcher.
     */

    /* we're guarenteed to have landed in thread_syscall_return */
    xnu_pf_disable_patch(patch);

    g_thread_syscall_return_start_addr = xnu_ptr_to_va(cacheable_stream);

    uint64_t thread_syscall_return_len =
        get_function_len(g_thread_syscall_return_start_addr);

    if(!thread_syscall_return_len){
        puts("svc_stalker: failed to");
        puts("   find len of");
        puts("   thread_syscall_return?");
        return false;
    }

    uint32_t *opcode_stream = cacheable_stream;

    g_thread_syscall_return_end_addr =
        xnu_ptr_to_va(opcode_stream + thread_syscall_return_len);

    thread_syscall_return_len /= sizeof(uint32_t);

    scan_for_ter(opcode_stream, thread_syscall_return_len,
            g_thread_syscall_return_ter_calls);

    puts("svc_stalker: finished scanning thread_syscall_return");

    return true;
}

/* confirmed working in all kernels 13.0-14.1 */
bool platform_syscall_scanner_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* purpose is the same as the above function */

    /* we're guarenteed to have landed in platform_syscall */
    xnu_pf_disable_patch(patch);

    /* find platform_syscall's prologue and search from there
     *
     * looking for sub sp, sp, n
     */
    uint32_t instr_limit = 150;
    uint32_t *opcode_stream = cacheable_stream;

    while((*opcode_stream & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0)
            return 0;

        opcode_stream--;
    }

    /* now we're at the start of platform_syscall, so get its size */
    g_platform_syscall_start_addr = xnu_ptr_to_va(opcode_stream);

    uint64_t platform_syscall_fxn_len =
        get_function_len(g_platform_syscall_start_addr);

    if(!platform_syscall_fxn_len){
        puts("svc_stalker: failed to");
        puts("   find len of");
        puts("   platform_syscall?");
        return false;
    }

    g_platform_syscall_end_addr = g_platform_syscall_start_addr +
        platform_syscall_fxn_len;

    /* opcode_stream still points to beginning of platform_syscall */
    platform_syscall_fxn_len /= sizeof(uint32_t);

    scan_for_ter(opcode_stream, platform_syscall_fxn_len,
            g_platform_syscall_ter_calls);

    puts("svc_stalker: finished scanning platform_syscall");

    return true;
}

/* confirmed working in all kernels 13.0-14.1 */
bool unix_syscall_return_scanner_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* purpose is the same as the above function */

    /* find unix_syscall_return's prologue
     *
     * whatever compiles these kernels decided to not begin the prologue with
     * sub sp, sp, n, but instead, a pre-index stp, so search for
     * stp rt1, rt2, [sp, n]!
     */
    uint32_t *opcode_stream = cacheable_stream;
    uint32_t instr_limit = 50;

    while((*opcode_stream & 0xffc003e0) != 0xa98003e0){
        if(instr_limit-- == 0){
            puts("svc_stalker: didn't find");
            puts("   prologue for");
            puts("   unix_syscall_return?");
            return false;
        }

        opcode_stream--;
    }

    g_unix_syscall_return_start_addr = xnu_ptr_to_va(opcode_stream);

    uint64_t unix_syscall_return_fxn_len =
        get_function_len(g_unix_syscall_return_start_addr);

    if(!unix_syscall_return_fxn_len){
        puts("svc_stalker: failed to");
        puts("   find len of");
        puts("   unix_syscall_return?");
        return false;
    }

    g_unix_syscall_return_end_addr = g_unix_syscall_return_start_addr +
        unix_syscall_return_fxn_len;

    /* opcode_stream still points to beginning of unix_syscall_return */
    unix_syscall_return_fxn_len /= sizeof(uint32_t);

    scan_for_ter(opcode_stream, unix_syscall_return_fxn_len,
            g_unix_syscall_return_ter_calls);

    puts("svc_stalker: finished scanning unix_syscall_return");

    return true;
}

/* confirmed working in all kernels 13.0-14.1 */
bool lck_grp_alloc_init_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* the BL we matched is guarenteed to be branching to lck_grp_alloc_init */
    uint32_t *blp = ((uint32_t *)cacheable_stream) + 2;

    uint32_t *lck_grp_alloc_init = get_branch_dst_ptr(*blp, blp);

    g_lck_grp_alloc_init_addr = xnu_ptr_to_va(lck_grp_alloc_init);

    puts("svc_stalker: found lck_grp_alloc_init");

    return true;
}

/* confirmed working in all kernels 13.0-14.1 */
bool lck_rw_alloc_init_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    /* the second BL we matched is branching to lck_rw_alloc_init */
    uint32_t instr_limit = 25;
    uint32_t bl_cnt = 0;

    for(;;){
        if(instr_limit-- == 0){
            puts("svc_stalker:");
            puts("   lck_rw_alloc_init_finder:");
            puts("   no BLs?");
            return false;
        }

        if((*opcode_stream & 0xfc000000) == 0x94000000){
            bl_cnt++;

            if(bl_cnt == 2)
                break;
        }

        opcode_stream++;
    }

    uint32_t *lck_rw_alloc_init = get_branch_dst_ptr(*opcode_stream,
            opcode_stream);

    g_lck_rw_alloc_init_addr = xnu_ptr_to_va(lck_rw_alloc_init);

    puts("svc_stalker: found lck_rw_alloc_init");

    return true;
}

/* confirmed working on all kernels 13.0-14.1 */
bool unix_syscall_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    /* handle_svc_hook OR's a unique 32 bit value into the upper 32 bits
     * of the calling userspace thread's X16. This works because system
     * call numbers are 32 bits in XNU. But it breaks indirect system calls
     * because the code which checks if X16 == 0 compares all 64 bits of
     * the register.
     *
     * So we change
     *
     * LDR X26, [X20, 0x88]             ; get userspace thread's X16, aka call num
     * CBNZ X26, n                      ; non-zero? if so, not indirect
     *
     * to
     *
     * LDR W26, [X20, 0x88]
     * CBNZ W26, n
     *
     * And we change
     *
     * LDR X24, [X20, 0x88]
     * CMP X24, 0
     *
     * to
     *
     * LDR W24, [X20, 0x88]
     * CMP W24, 0
     */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;

    uint32_t *ldr = opcode_stream;
    uint32_t *cbnz = opcode_stream + 1;

    /* turn off bit 30, changing size from 3 to 2 */
    *ldr &= ~0x40000000;
    /* ...and because we changed the size, we need to double the immediate */
    uint32_t imm12 = bits(*ldr, 10, 21) << 1;
    /* zero imm12 */
    *ldr &= ~0x3ffc00;
    /* replace */
    *ldr |= (imm12 << 10);

    /* turn off bit 31, changing sf to 0 */
    *cbnz &= ~0x80000000;

    /* now look for the ldr,cmp pair
     *
     * First match: LDR Xn, [X20, 0x88]
     * Second match: CMP Xn, 0
     */
    uint32_t instr_limit = 500;

    uint32_t *cmp = NULL;

    for(;;){
        if(instr_limit-- == 0){
            puts("svc_stalker: failed to");
            puts("   find ldr/cmp pair");
            puts("   in unix_syscall");

            stalker_fatal_error();
        }

        if((*opcode_stream & 0xffffffe0) == 0xF9404680 &&
                (opcode_stream[1] & 0xfffffc1f) == 0xF100001F){
            ldr = opcode_stream;
            cmp = opcode_stream + 1;

            break;
        }

        opcode_stream++;
    }

    /* doing the whole ldr thing again */
    *ldr &= ~0x40000000;
    imm12 = bits(*ldr, 10, 21) << 1;
    *ldr &= ~0x3ffc00;
    *ldr |= (imm12 << 10);

    /* turn off bit 31, now it's the 32 bit variant */
    *cmp &= ~0x80000000;

    puts("svc_stalker: patched unix_syscall");

    return true;
}
