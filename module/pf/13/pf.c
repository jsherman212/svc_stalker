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

#include "../../el1/common_functions_instrs.h"
#include "../../el1/handle_svc_hook_instrs.h"
#include "../../el1/hook_system_check_sysctlbyname_hook_instrs.h"
#include "../../el1/return_interceptor_instrs.h"
#include "../../el1/sleh_synchronous_hijacker_instrs.h"
#include "../../el1/svc_stalker_ctl_instrs.h"

/* this function scans opcode_stream for calls to thread_exception_return */
static void scan_for_ter(uint32_t *opcode_stream, uint64_t fxn_len,
        uint32_t **ter_calls_out){
    uint32_t cur_ter_calls_idx = 0;

    for(int i=0; i<fxn_len; i++){
        uint32_t instr = opcode_stream[i];

        /* b or bl? */
        if((instr & 0x7c000000) == 0x14000000){
            /* int32_t imm26 = sign_extend(bits(instr, 0, 25) << 2, 28); */
            /* uint32_t *dst = (uint32_t *)((intptr_t)(opcode_stream + i) + imm26); */

            uint32_t *dst = get_branch_dst_ptr(instr, opcode_stream + i);

            /* first instr in this function is mov x0, TPIDR_EL1? */
            if(*dst == 0xd538d080){
                ter_calls_out[cur_ter_calls_idx] = opcode_stream + i;
                cur_ter_calls_idx++;
            }
        }
    }
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

/* this limit is safe */
enum { g_max_ter_calls = 50 };
static uint32_t *g_platform_syscall_ter_calls[g_max_ter_calls];
static uint32_t *g_thread_syscall_return_ter_calls[g_max_ter_calls];
static uint32_t *g_unix_syscall_return_ter_calls[g_max_ter_calls];

static bool g_patched_mach_syscall = false;

uint64_t g_exec_scratch_space_addr = 0;
/* don't count the first opcode */
uint64_t g_exec_scratch_space_size = -sizeof(uint32_t);

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

    /* uint32_t imm26 = (epilogue - branch_from) & 0x3ffffff; */
    /* uint32_t epilogue_branch = (5 << 26) | imm26; */

    uint32_t epilogue_branch = assemble_b((uint64_t)branch_from,
            (uint64_t)epilogue);

    /* bl _panic --> branch to mach_syscall epilogue */
    *branch_from = epilogue_branch;

    g_patched_mach_syscall = true;

    puts("svc_stalker: patched mach_syscall");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
bool sysctl_register_oid_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* the BL we matched is guarenteed to be sysctl_register_oid */
    /* int32_t imm26 = sign_extend((opcode_stream[5] & 0x3ffffff) << 2, 26); */
    /* uint32_t *sysctl_register_oid = (uint32_t *)((intptr_t)(opcode_stream + 5) + imm26); */

    uint32_t *sysctl_register_oid = get_branch_dst_ptr(opcode_stream[5],
            opcode_stream + 5);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);

    puts("svc_stalker: found sysctl_register_oid");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

    /* int32_t imm26 = sign_extend((opcode_stream[2] & 0x3ffffff) << 2, 26); */
    /* uint32_t *lck_rw_lock_shared = (uint32_t *)((intptr_t)(opcode_stream + 2) + imm26); */

    uint32_t *lck_rw_lock_shared = get_branch_dst_ptr(opcode_stream[2],
            opcode_stream + 2);

    g_lck_rw_lock_shared_addr = xnu_ptr_to_va(lck_rw_lock_shared);

    /* imm26 = sign_extend((opcode_stream[6] & 0x3ffffff) << 2, 26); */ 
    /* uint32_t *name2oid = (uint32_t *)((intptr_t)(opcode_stream + 6) + imm26); */

    uint32_t *name2oid = get_branch_dst_ptr(opcode_stream[6], opcode_stream + 6);

    g_name2oid_addr = xnu_ptr_to_va(name2oid);

    /* imm26 = sign_extend((opcode_stream[9] & 0x3ffffff) << 2, 26); */ 
    /* uint32_t *lck_rw_done = (uint32_t *)((intptr_t)(opcode_stream + 9) + imm26); */

    uint32_t *lck_rw_done = get_branch_dst_ptr(opcode_stream[9],
            opcode_stream + 9);

    g_lck_rw_done_addr = xnu_ptr_to_va(lck_rw_done);

    puts("svc_stalker: found sysctl_geometry_lock");
    puts("svc_stalker: found lck_rw_lock_shared");
    puts("svc_stalker: found name2oid");
    puts("svc_stalker: found lck_rw_done");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working in all kernels 13.0-13.7 */
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

/* confirmed working in all kernels 13.0-13.7 */
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

/* confirmed working in all kernels 13.0-13.7 */
bool lck_grp_alloc_init_finder_13(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    xnu_pf_disable_patch(patch);

    /* the BL we matched is guarenteed to be branching to lck_grp_alloc_init */
    uint32_t *blp = ((uint32_t *)cacheable_stream) + 2;
    /* int32_t imm26 = sign_extend((*blp & 0x3ffffff) << 2, 26); */

    /* uint32_t *lck_grp_alloc_init = (uint32_t *)((intptr_t)blp + imm26); */

    uint32_t *lck_grp_alloc_init = get_branch_dst_ptr(*blp, blp);

    g_lck_grp_alloc_init_addr = xnu_ptr_to_va(lck_grp_alloc_init);

    puts("svc_stalker: found lck_grp_alloc_init");

    return true;
}

/* confirmed working in all kernels 13.0-13.7 */
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

    /* int32_t imm26 = sign_extend((*opcode_stream & 0x3ffffff) << 2, 26); */

    /* uint32_t *lck_rw_alloc_init = (uint32_t *)((intptr_t)opcode_stream + imm26); */

    uint32_t *lck_rw_alloc_init = get_branch_dst_ptr(*opcode_stream,
            opcode_stream);

    g_lck_rw_alloc_init_addr = xnu_ptr_to_va(lck_rw_alloc_init);

    puts("svc_stalker: found lck_rw_alloc_init");

    return true;
}

/* confirmed working on all kernels 13.0-13.7 */
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

/* confirmed working on all kernels 13.0-13.7 */
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

    /* int32_t imm26 = sign_extend((*opcode_stream & 0x3ffffff) << 2, 26); */

    /* opcode_stream points to beginning of exception_triage_thread */
    /* opcode_stream = (uint32_t *)((intptr_t)opcode_stream + imm26); */

    /* opcode_stream points to beginning of exception_triage_thread */
    opcode_stream = get_branch_dst_ptr(*opcode_stream, opcode_stream);

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

/* these functions are so stalker_main_patcher doesn't
 * explode in size upon macro expansion
 * 
 * macros autogenerated by hookgen.pl
 */
static uint32_t *write_common_functions_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_COMMON_FUNCTIONS_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static uint32_t *write_handle_svc_hook_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_HANDLE_SVC_HOOK_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static uint32_t *write_svc_stalker_ctl_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_SVC_STALKER_CTL_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static uint32_t *write_h_s_c_sbn_h_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static uint32_t *write_sleh_synchronous_hijacker_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_SLEH_SYNCHRONOUS_HIJACKER_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static uint32_t *write_return_interceptor_instrs(uint32_t *scratch_space,
        uint64_t *num_free_instrsp){
    uint64_t num_free_instrs = *num_free_instrsp;
    WRITE_RETURN_INTERCEPTOR_INSTRS;
    *num_free_instrsp = num_free_instrs;
    return scratch_space;
}

static void anything_missing(void){
    static int printed_err_hdr = 0;

#define chk(expression, msg) \
    do { \
        if(expression){ \
            if(!printed_err_hdr){ \
                printf("svc_stalker: error(s) before\n" \
                        "  we continue:\n"); \
                printed_err_hdr = 1; \
            } \
            printf("  "msg); \
        } \
    } while (0) \

    chk(!g_proc_pid_addr, "proc_pid not found\n");
    chk(!g_sysent_addr, "sysent not found\n");
    chk(!g_kalloc_canblock_addr, "kalloc_canblock not found\n");
    chk(!g_kfree_addr_addr, "kfree_addr not found\n");
    chk(!g_patched_mach_syscall, "did not patch mach_syscall\n");
    chk(!g_sysctl__kern_children_addr, "sysctl__kern_children\n"
                                        "  not found\n");
    chk(!g_sysctl_register_oid_addr, "sysctl_register_oid not found\n");
    chk(!g_sysctl_handle_long_addr, "sysctl_handle_long not found\n");
    chk(!g_name2oid_addr, "name2oid not found\n");
    chk(!g_sysctl_geometry_lock_addr, "sysctl_geometry_lock not found\n");
    chk(!g_lck_rw_lock_shared_addr, "lck_rw_lock_shared not found\n");
    chk(!g_lck_rw_done_addr, "lck_rw_done not found\n");
    chk(!g_h_s_c_sbn_branch_addr, "did not find hscsbn branch addr\n");
    chk(!g_h_s_c_sbn_epilogue_addr, "hscsbn epilogue not found\n");
    chk(!g_mach_syscall_addr, "mach_syscall not found\n");
    chk(!g_offsetof_act_context, "ACT_CONTEXT offset not found\n");
    chk(!g_thread_exception_return_addr, "thread_exception_return not found\n");
    chk(!g_thread_syscall_return_start_addr || !g_thread_syscall_return_end_addr,
            "thread_syscall_return not scanned\n");
    chk(!g_platform_syscall_start_addr|| !g_platform_syscall_end_addr,
            "platform_syscall not scanned\n");
    chk(!g_unix_syscall_return_start_addr || !g_unix_syscall_return_end_addr,
            "unix_syscall not scanned\n");
    chk(!g_lck_grp_alloc_init_addr, "lck_grp_alloc_init not found\n");
    chk(!g_lck_rw_alloc_init_addr, "lck_rw_alloc_init not found\n");

    /* if we printed the error header, something is missing */
    if(printed_err_hdr)
        stalker_fatal_error();
}

/* create and initialize the stalker cache with what we've got now. The
 * stalker cache contains offsets found by svc_stalker's patchfinder, as well
 * as a few other misc. things.
 *
 * Returns a pointer to the next unused uint64_t in the stalker cache 
 */
/* static uint64_t *create_stalker_cache(uint64_t **stalker_cache_base_out){ */
/*     uint64_t *stalker_cache = alloc_static(PAGE_SIZE); */

/*     if(!stalker_cache){ */
/*         puts("svc_stalker: alloc_static"); */
/*         puts("   returned NULL while"); */
/*         puts("   allocating for stalker"); */
/*         puts("   cache"); */

/*         stalker_fatal_error(); */
/*     } */

/*     *stalker_cache_base_out = stalker_cache; */

/*     uint64_t *cursor = stalker_cache; */

/*     STALKER_CACHE_WRITE(cursor, g_proc_pid_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_kalloc_canblock_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_kfree_addr_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_sysctl__kern_children_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_sysctl_register_oid_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_sysctl_handle_long_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_name2oid_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_sysctl_geometry_lock_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_lck_rw_lock_shared_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_lck_rw_done_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_h_s_c_sbn_epilogue_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_mach_syscall_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_offsetof_act_context); */
/*     STALKER_CACHE_WRITE(cursor, g_thread_exception_return_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_platform_syscall_start_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_platform_syscall_end_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_thread_syscall_return_start_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_thread_syscall_return_end_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_unix_syscall_return_start_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_unix_syscall_return_end_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_lck_grp_alloc_init_addr); */
/*     STALKER_CACHE_WRITE(cursor, g_lck_rw_alloc_init_addr); */

/*     return cursor; */
/* } */

static bool hijack_sleh_synchronous(uint32_t **scratch_space_out,
        uint64_t *num_free_instrs_out, uint64_t *stalker_cache_base,
        uint64_t **stalker_cache_cursor_out, uint64_t sleh_synchronous_hijacker_addr,
        uint64_t sleh_synchronous_addr){
    uint32_t *scratch_space = *scratch_space_out;
    uint64_t num_free_instrs = *num_free_instrs_out;
    uint64_t *stalker_cache_cursor = *stalker_cache_cursor_out;

    uint32_t *curaddr = xnu_va_to_ptr(sleh_synchronous_addr);
    uint32_t replaced_instr = *curaddr;

    *curaddr = assemble_b((uint64_t)curaddr, sleh_synchronous_hijacker_addr);

    WRITE_INSTR_TO_SCRATCH_SPACE(replaced_instr);
    WRITE_INSTR_TO_SCRATCH_SPACE(0xd61f0060);   /* br x3 */

    *scratch_space_out = scratch_space;
    *num_free_instrs_out = num_free_instrs;
    *stalker_cache_cursor_out = stalker_cache_cursor;

    return true;
}

static void patch_thread_exception_return_calls(uint32_t ***all_ter_call_arrays,
        size_t n_ter_call_arrays, uint64_t return_interceptor_addr){
    for(int i=0; i<n_ter_call_arrays; i++){
        /* this array is NULL terminated */
        uint32_t **ter_calls = all_ter_call_arrays[i];

        while(*ter_calls){
            **ter_calls = assemble_bl((uint64_t)(*ter_calls), return_interceptor_addr);
            ter_calls++;
        }
    }
}

/* confirmed working on all kernels 13.0-13.7 */
bool stalker_main_patcher_13(xnu_pf_patch_t *patch, void *cacheable_stream){
    anything_missing();

    /* uint64_t *stalker_cache_base = NULL; */
    /* uint64_t *stalker_cache_cursor = create_stalker_cache(&stalker_cache_base); */

    stalker_cache_base = alloc_static(PAGE_SIZE);

    if(!stalker_cache_base){
        puts("svc_stalker: alloc_static");
        puts("   returned NULL while");
        puts("   allocating for stalker");
        puts("   cache");

        stalker_fatal_error();
    }

    /* This function performs all the patches to enable call interception
     * functionality. In this order:
     *  - It finds current_proc.
     *  - It finds exception_triage_thread and patches it to return to its
     *      caller on EXC_SYSCALL & EXC_MACH_SYSCALL exceptions.
     *  - It writes the code from common_functions.s into the executable
     *      scratch space.
     *  - It writes the code from handle_svc_hook.s into the executable
     *      scratch space.
     *  - It writes the branch from inlined handle_svc inside sleh_synchronous
     *      to handle_svc_hook.
     *  - It finds the first enosys system call and patches it to instead point
     *      to where the code from svc_stalker_ctl.s will be inside the
     *      executable scratch space.
     *  - It writes the code from svc_stalker_ctl.s into the executable
     *      scratch space.
     *  - It writes the code from hook_system_check_sysctlbyname_hook.s into
     *      the executable scratch space, and restores the five instrs
     *      it overwrote in doing so.
     *  - It writes the branch from hook_system_check_sysctlbyname to
     *      hook_system_check_sysctlbyname_hook.
     *  - It writes the code from sleh_synchronous_hijacker and changes
     *      sleh_synchronous's first instruction to branch to it.
     *  - It writes the code from return_interceptor.s into the executable
     *      scratch space.
     *  - Finally, it patches all the BL _thread_exception_return instrs
     *      we found earlier to be BL _return_interceptor.
     */
    xnu_pf_disable_patch(patch);

    uint32_t *opcode_stream = cacheable_stream;
    uint32_t *temp = opcode_stream;

    /* get sleh_synchronous's addr
     *
     * search up, looking for sub sp, sp, n
     */
    uint32_t instr_limit = 1000;

    while((*temp & 0xffc003ff) != 0xd10003ff){
        if(instr_limit-- == 0){
            puts("svc_stalker: didn't");
            puts("      find sleh_synchronous");
            puts("      prologue?");

            stalker_fatal_error();
        }

        temp--;
    }

    /* uint64_t sleh_synchronous_addr = xnu_ptr_to_va(temp); */

    g_sleh_synchronous_addr = xnu_ptr_to_va(temp);

    uint64_t branch_from = (uint64_t)opcode_stream;

    /* the first BL after the b.eq we followed will be branching to
     * current_proc
     */
    instr_limit = 10;

    while((*opcode_stream & 0xfc000000) != 0x94000000){
        if(instr_limit-- == 0){
            puts("svc_stalker: couldn't find");
            puts("     current_proc");
            return 0;
        }

        opcode_stream++;
    }

    /* int32_t imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28); */
    /* uint64_t current_proc_addr = imm26 + xnu_ptr_to_va(opcode_stream); */

    uint32_t *current_proc = get_branch_dst_ptr(*opcode_stream, opcode_stream);
    g_current_proc_addr = xnu_ptr_to_va(current_proc);

    puts("svc_stalker: found current_proc");

    /* STALKER_CACHE_WRITE(stalker_cache_cursor, current_proc_addr); */

    /* now we need to find exception_triage. We can do this by going forward
     * until we hit a BRK, as it's right after the call to exception_triage
     * and it's the only BRK in sleh_synchronous.
     */
    instr_limit = 2000;

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

    /* imm26 = sign_extend(bits(*opcode_stream, 0, 25) << 2, 28); */
    /* uint64_t exception_triage_addr = imm26 + xnu_ptr_to_va(opcode_stream); */

    uint32_t *exception_triage = get_branch_dst_ptr(*opcode_stream,
            opcode_stream);
    g_exception_triage_addr = xnu_ptr_to_va(exception_triage);

    puts("svc_stalker: found exception_triage");

    /* STALKER_CACHE_WRITE(stalker_cache_cursor, exception_triage_addr); */

    if(!patch_exception_triage_thread(exception_triage)){
        puts("svc_stalker: failed");
        puts("     patching");
        puts("     exception_triage_thread");

        stalker_fatal_error();
    }

    /* defined in *_instrs.h, autogenerated by hookgen.pl
     *
     * Additionally, we'll be writing the pointer to the stalker cache
     * for each asm file in this repo
     */
    size_t needed_sz =
        /* instructions */
        ((g_handle_svc_hook_num_instrs + g_svc_stalker_ctl_num_instrs +
          g_hook_system_check_sysctlbyname_hook_num_instrs +
          g_common_functions_num_instrs + g_sleh_synchronous_hijacker_num_instrs +
          g_return_interceptor_num_instrs) * sizeof(uint32_t)) +
        /* number of times we write stalker cache pointer to scratch space */
        5 * sizeof(uint64_t);

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

            stalker_fatal_error();
        }
    }

    uint64_t num_free_instrs = g_exec_scratch_space_size / sizeof(uint32_t);
    uint32_t *scratch_space = xnu_va_to_ptr(g_exec_scratch_space_addr);

    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(stalker_cache_base));

    /* first, write the common functions */
    uint8_t *common_functions_base = (uint8_t *)scratch_space;

    scratch_space = write_common_functions_instrs(scratch_space, &num_free_instrs);

    /* now, add the offset of each common function to the stalker cache */
    for(int i=0; i<g_num_common_functions_function_starts; i++){
        uint32_t cur_fxn_start = g_common_functions_function_starts[i];
        uint64_t va_ptr = xnu_ptr_to_va(common_functions_base + cur_fxn_start);

        if(i == 0)
            g_common_fxns_get_stalker_cache_addr = va_ptr;
        else if(i == 1)
            g_stalker_ctl_from_table_addr = va_ptr;
        else if(i == 2)
            g_should_intercept_call_addr = va_ptr;
        else if(i == 3)
            g_get_next_free_stalker_ctl_addr = va_ptr;
        else if(i == 4)
            g_is_sysctl_registered_addr = va_ptr;
        else if(i == 5)
            g_send_exception_msg_addr = va_ptr;
        else if(i == 6)
            g_get_flag_ptr_for_call_num_addr = va_ptr;

        /* STALKER_CACHE_WRITE(stalker_cache_cursor, va_ptr); */
    }

    /* Please see stalker_table.h
     *
     * The stalker table itself takes up a page (0x4000) bytes of memory.
     *
     * The first 16 bytes of the stalker table will hold information about it.
     * Of that 16 bytes, the first 8 will be the number of non-free stalker_ctl
     * structs, and the last 8 represent a boolean which tells us if our sysctl,
     * kern.svc_stalker_ctl_callnum, has been registered.
     *
     * The other 0x3ff0 bytes are dedicated to housing up to and including 1023
     * stalker_ctl structs, which are created/freed whenever the user decides to
     * intercept/stop intercepting calls for a given process.
     */
    size_t stalker_table_sz = (STALKER_TABLE_MAX + 1) * SIZEOF_STRUCT_STALKER_CTL;
    uint8_t *stalker_table = alloc_static(stalker_table_sz);

    if(!stalker_table){
        puts("svc_stalker: alloc_static");
        puts("     returned NULL when");
        puts("     allocating mem for");
        puts("     stalker table");

        stalker_fatal_error();
    }

    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(stalker_table)); */
    g_stalker_table_ptr = xnu_ptr_to_va(stalker_table);

    const uint8_t *stalker_table_end = stalker_table + stalker_table_sz;

    *(uint64_t *)(stalker_table + STALKER_TABLE_NUM_PIDS_OFF) = 0;
    *(uint64_t *)(stalker_table + STALKER_TABLE_REGISTERED_SYSCTL_OFF) = 0;

    uint8_t *cur_stalker_ctl = stalker_table + SIZEOF_STRUCT_STALKER_CTL;

    while(cur_stalker_ctl < stalker_table_end){
        /* all initial stalker_ctl structs are free */
        *(uint32_t *)(cur_stalker_ctl + STALKER_CTL_FREE_OFF) = 1;
        /* free stalker_ctl structs belong to no one */
        *(uint32_t *)(cur_stalker_ctl + STALKER_CTL_PID_OFF) = 0;
        /* free stalker_ctl structs have no call list */
        *(uint64_t *)(cur_stalker_ctl + STALKER_CTL_CALL_LIST_OFF) = 0;

        cur_stalker_ctl += SIZEOF_STRUCT_STALKER_CTL;
    }

    /* I need to manually list stalker cache offsets inside of stalker_cache.h
     * and it's very easy when I'm only dealing with numbers and nothing else.
     * If I decide to add or remove numbers from the stalker cache, that's
     * fine, I just adjust everything in stalker_cache.h by plus-or-minus-
     * sizeof(number). I can't imagine how *annoying* and easy to screw up
     * that would get if I decided to store C strings/arrays before/after
     * numbers.
     *
     * I'll stash these C strings and the to-be-initialized MIB array/MIB count
     * far, far away from the numbers in the stalker cache and write
     * pointers to them. alloc_static gave me a page of memory so I'll have
     * more than enough space to do this.
     */
    uint8_t *sysctl_stuff = (uint8_t *)stalker_cache_base + (PAGE_SIZE / 2);

    /* sysctl name for the system call number */
    const char *sysctl_name = "kern.svc_stalker_ctl_callnum";
    strcpy((char *)sysctl_stuff, sysctl_name);

    char *sysctl_namep = (char *)sysctl_stuff;

    const char *sysctl_descr = "query for svc_stalker_ctl's system call number";
    size_t sysctl_name_len = strlen(sysctl_name);
    char *sysctl_descrp = (char *)(sysctl_stuff + sysctl_name_len + 1);
    strcpy(sysctl_descrp, sysctl_descr);

    /* how sysctl should format the call number, long */
    size_t sysctl_descr_len = strlen(sysctl_descr);
    char *sysctl_fmtp = sysctl_descrp + strlen(sysctl_descr) + 1;
    strcpy(sysctl_fmtp, "L");

    uint32_t *sysctl_mibp = (uint32_t *)((uint64_t)(sysctl_fmtp + 8) & ~7);
    uint32_t *sysctl_mib_countp = (uint32_t *)(sysctl_mibp + CTL_MAXNAME);

    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(sysctl_namep)); */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(sysctl_descrp)); */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(sysctl_fmtp)); */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(sysctl_mibp)); */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(sysctl_mib_countp)); */

    g_svc_stalker_sysctl_name_ptr = xnu_ptr_to_va(sysctl_namep);
    g_svc_stalker_sysctl_descr_ptr = xnu_ptr_to_va(sysctl_descrp);
    g_svc_stalker_sysctl_fmt_ptr = xnu_ptr_to_va(sysctl_fmtp);
    g_svc_stalker_sysctl_mib_ptr = xnu_ptr_to_va(sysctl_mibp);
    g_svc_stalker_sysctl_mib_count_ptr = xnu_ptr_to_va(sysctl_mib_countp);

    /* allow handle_svc_hook access to stalker cache */
    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(stalker_cache_base));

    /* write handle_svc_hook kva so sleh_synchronous_hijacker can call it */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, xnu_ptr_to_va(scratch_space)); */
    g_handle_svc_hook_addr = xnu_ptr_to_va(scratch_space);

    /* Needs to be done before we patch the sysent entry so scratch_space lies
     * right after the end of handle_svc_hook.
     */
    scratch_space = write_handle_svc_hook_instrs(scratch_space, &num_free_instrs);

    /* now scratch_space points right after the end of handle_svc_hook,
     * so we're ready to write the instructions for svc_stalker_ctl.
     *
     * First, allow svc_stalker_ctl access to the stalker cache. This needs
     * to be done before we patch sy_call so scratch space points to the
     * beginning of svc_stalker_ctl.
     */
    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(stalker_cache_base));

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

    /* STALKER_CACHE_WRITE(stalker_cache_cursor, (uint64_t)patched_syscall_num); */

    g_svc_stalker_ctl_callnum = (uint64_t)patched_syscall_num;

    scratch_space = write_svc_stalker_ctl_instrs(scratch_space, &num_free_instrs);

    /* allow querying of kern.svc_stalker_ctl_callnum in sandboxed processes
     *
     * I install a hook in hook_system_check_sysctlbyname which checks if the
     * third parameter, the MIB array for the sysctl, and the fourth parameter,
     * the length of that MIB array, matches the MIB array of the
     * kern.svc_stalker_ctl_callnum and return back to its caller if it does.
     *
     * Originally I was going to strcmp the first parameter, the sysctl name
     * string, against "kern.svc_stalker_ctl_callnum", but this function is
     * called constantly and I don't want to cause noticable slowdowns.
     *
     * Unfortunately, there's no sanity checks for me to overwrite, but there
     * is a lot of "parameter moving" after the prologue, so I can use that
     * space. I'll save the instructions we overwrote and restore them after
     * I pop the callee-saved registers from the stack but before I return
     * back to hook_system_check_sysctlbyname in the event the MIB array doesn't
     * match that of kern.svc_stalker_ctl_callnum's.
     */

    /* allow hook_system_check_sysctlbyname_hook access to stalker cache */
    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(stalker_cache_base));

    uint64_t branch_to = xnu_ptr_to_va(scratch_space);

    scratch_space = write_h_s_c_sbn_h_instrs(scratch_space, &num_free_instrs);

    branch_from = (uint64_t)xnu_va_to_ptr(g_h_s_c_sbn_branch_addr);

    /* restore the five instructions we overwrote at the end of
     * system_check_sysctlbyname_hook to the end of `not_ours`
     * in hook_system_check_sysctlbyname_hook.s
     */
    WRITE_INSTR_TO_SCRATCH_SPACE(*(uint32_t *)branch_from);
    WRITE_INSTR_TO_SCRATCH_SPACE(*(uint32_t *)(branch_from + 0x4));
    WRITE_INSTR_TO_SCRATCH_SPACE(*(uint32_t *)(branch_from + 0x8));
    WRITE_INSTR_TO_SCRATCH_SPACE(*(uint32_t *)(branch_from + 0xc));
    WRITE_INSTR_TO_SCRATCH_SPACE(*(uint32_t *)(branch_from + 0x10));
    WRITE_INSTR_TO_SCRATCH_SPACE(0xd65f03c0);    /* ret */

    /* TODO: assemble_bl */
    write_blr(8, branch_from, branch_to);

    /* allow sleh_synchronous_hijacker access to stalker cache */
    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(stalker_cache_base));

    uint64_t sleh_synchronous_hijacker_addr = (uint64_t)scratch_space;

    scratch_space = write_sleh_synchronous_hijacker_instrs(scratch_space,
            &num_free_instrs);

    if(!hijack_sleh_synchronous(&scratch_space, &num_free_instrs,
                stalker_cache_base, &stalker_cache_cursor,
                sleh_synchronous_hijacker_addr, g_sleh_synchronous_addr)){
        puts("svc_stalker: failed to");
        puts("   write sleh_synchronous");
        puts("   branch to its hijacker");

        stalker_fatal_error();
    }

    puts("svc_stalker: patched sleh_synchronous");

    /* so sleh_synchronous_hijacker knows where to branch back to */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, sleh_synchronous_addr); */

    /* allow return_interceptor access to stalker cache */
    WRITE_QWORD_TO_SCRATCH_SPACE(xnu_ptr_to_va(stalker_cache_base));

    uint64_t return_interceptor_addr = (uint64_t)scratch_space;

    /* virtual addr of return_interceptor */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, */
            /* xnu_ptr_to_va((void *)return_interceptor_addr)); */

    g_return_interceptor_addr = xnu_ptr_to_va((void *)return_interceptor_addr);

    scratch_space = write_return_interceptor_instrs(scratch_space, &num_free_instrs);

    uint32_t **all_ter_call_arrays[] = {
        g_platform_syscall_ter_calls,
        g_thread_syscall_return_ter_calls,
        g_unix_syscall_return_ter_calls,
    };

    size_t n_ter_call_arrays = sizeof(all_ter_call_arrays) /
        sizeof(*all_ter_call_arrays);

    patch_thread_exception_return_calls(all_ter_call_arrays, n_ter_call_arrays,
            return_interceptor_addr);

    puts("svc_stalker: patched platform_syscall");
    puts("svc_stalker: patched thread_syscall_return");
    puts("svc_stalker: patched unix_syscall_return");

    /* reserve stalker cache space for stalker lock and current call ID
     *
     * Current call ID is used by mini_strace to know when a system call
     * has completed.
     */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, 0); */
    /* STALKER_CACHE_WRITE(stalker_cache_cursor, 0); */

    printf( "****** IMPORTANT *****\n"
            "* System call #%d has\n"
            "* been patched to\n"
            "* svc_stalker_ctl.\n"
            "* Please refer to the\n"
            "* README for more info\n"
            "* about this system call.\n"
            "* You can also use\n"
            "* sysctlbyname to retrieve\n"
            "* svc_stalker_ctl's call\n"
            "* number.\n"
            "**********************\n",
            patched_syscall_num);

    return true;
}
