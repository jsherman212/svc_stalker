#ifndef PF_13
#define PF_13

#include <stdbool.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

/* all patchfinder functions, so we can build the list of pfs */
bool proc_pid_finder_13(xnu_pf_patch_t *, void *);
bool sysent_finder_13(xnu_pf_patch_t *, void *);
bool kalloc_canblock_finder_13(xnu_pf_patch_t *, void *);
bool kfree_addr_finder_13(xnu_pf_patch_t *, void *);
bool mach_syscall_patcher_13(xnu_pf_patch_t *, void *);
bool ExceptionVectorsBase_finder_13(xnu_pf_patch_t *, void *);
bool sysctl__kern_children_finder_13(xnu_pf_patch_t *, void *);
bool sysctl_register_oid_finder_13(xnu_pf_patch_t *, void *);
bool sysctl_handle_long_finder_13(xnu_pf_patch_t *, void *);
bool name2oid_and_its_dependencies_finder_13(xnu_pf_patch_t *, void *);
bool hook_system_check_sysctlbyname_finder_13(xnu_pf_patch_t *, void *);
bool thread_exception_return_finder_13(xnu_pf_patch_t *, void *);
bool thread_syscall_return_scanner_13(xnu_pf_patch_t *, void *);
bool platform_syscall_scanner_13(xnu_pf_patch_t *, void *);
bool unix_syscall_return_scanner_13(xnu_pf_patch_t *, void *);
bool lck_grp_alloc_init_finder_13(xnu_pf_patch_t *, void *);
bool lck_rw_alloc_init_finder_13(xnu_pf_patch_t *, void *);
bool unix_syscall_patcher_13(xnu_pf_patch_t *, void *);

/* Always the last patchfinder in the array */
bool stalker_main_patcher_13(xnu_pf_patch_t *, void *);

#endif
