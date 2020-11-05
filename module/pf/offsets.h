#ifndef OFFSETS
#define OFFSETS

extern uint64_t *stalker_cache_base;

/* This file contains offsets which will be written to the stalker cache
 * as well as offsets needed before XNU boots.
 *
 * Offsets that are not present for a given iOS version are not written
 * to the stalker cache.
 */

extern uint64_t g_proc_pid_addr;
extern uint64_t g_sysent_addr;

/* iOS 13.x: kalloc_canblock
 * iOS 14.x: kalloc_external
 */
extern uint64_t g_kalloc_canblock_addr;
extern uint64_t g_kalloc_external_addr;

/* iOS 13.x: kfree_addr
 * iOS 14.x: kfree_ext
 */
extern uint64_t g_kfree_addr_addr;
extern uint64_t g_kfree_ext_addr;

extern uint64_t g_sysctl__kern_children_addr;
extern uint64_t g_sysctl_register_oid_addr;
extern uint64_t g_sysctl_handle_long_addr;
extern uint64_t g_name2oid_addr;
extern uint64_t g_sysctl_geometry_lock_addr;
extern uint64_t g_lck_rw_lock_shared_addr;
extern uint64_t g_lck_rw_done_addr;
extern uint64_t g_h_s_c_sbn_branch_addr;
extern uint64_t g_h_s_c_sbn_epilogue_addr;
extern uint64_t g_mach_syscall_addr;
extern uint32_t g_offsetof_act_context;
extern uint64_t g_thread_exception_return_addr;
extern uint64_t g_platform_syscall_start_addr;
extern uint64_t g_platform_syscall_end_addr;
extern uint64_t g_thread_syscall_return_start_addr;
extern uint64_t g_thread_syscall_return_end_addr;
extern uint64_t g_unix_syscall_return_start_addr;
extern uint64_t g_unix_syscall_return_end_addr;
extern uint64_t g_lck_grp_alloc_init_addr;
extern uint64_t g_lck_rw_alloc_init_addr;
extern uint32_t g_kern_version_major;
/* XXX start the things written inside sleh_synchronous_patcher */
extern uint64_t g_current_proc_addr;
extern uint64_t g_exception_triage_addr;
/* XXX start common function - ORDER CANNOT CHANGE */
extern uint64_t g_common_fxns_get_stalker_cache_addr;
extern uint64_t g_stalker_ctl_from_table_addr;
extern uint64_t g_should_intercept_call_addr;
extern uint64_t g_get_next_free_stalker_ctl_addr;
extern uint64_t g_is_sysctl_registered_addr;
extern uint64_t g_send_exception_msg_addr;
extern uint64_t g_get_flag_ptr_for_call_num_addr;
/* XXX end common functions */
extern uint64_t g_stalker_table_ptr;
extern uint64_t g_svc_stalker_sysctl_name_ptr;
extern uint64_t g_svc_stalker_sysctl_descr_ptr;
extern uint64_t g_svc_stalker_sysctl_fmt_ptr;
extern uint64_t g_svc_stalker_sysctl_mib_ptr;
extern uint64_t g_svc_stalker_sysctl_mib_count_ptr;
extern uint64_t g_handle_svc_hook_addr;
extern uint64_t g_svc_stalker_ctl_callnum;
extern uint64_t g_sleh_synchronous_addr;
extern uint64_t g_return_interceptor_addr;

/* stalker lock and current call ID are initialized inside of module/el1/ */

/* START offsets not added to stalker cache */
extern uint64_t g_exec_scratch_space_addr;
extern uint64_t g_exec_scratch_space_size;

extern bool g_patched_mach_syscall;

/* this limit is safe */
enum { g_max_ter_calls = 50 };
extern uint32_t *g_platform_syscall_ter_calls[g_max_ter_calls];
extern uint32_t *g_thread_syscall_return_ter_calls[g_max_ter_calls];
extern uint32_t *g_unix_syscall_return_ter_calls[g_max_ter_calls];


#endif
