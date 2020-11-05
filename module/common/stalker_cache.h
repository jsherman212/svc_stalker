#ifndef STALKER_CACHE
#define STALKER_CACHE

/* offsets for stuff within the stalker cache */

#define PROC_PID                                        (0x0)

/* for kalloc/kfree, one of these will written to the cache depending
 * on iOS version
 */
#define KALLOC_CANBLOCK                                 (0x8)
#define KALLOC_EXTERNAL                                 (0x8)

#define KFREE_ADDR                                      (0x10)
#define KFREE_EXT                                       (0x10)

#define SYSCTL__KERN_CHILDREN_PTR                       (0x18)
#define SYSCTL_REGISTER_OID                             (0x20)
#define SYSCTL_HANDLE_LONG                              (0x28)
#define NAME2OID                                        (0x30)
#define SYSCTL_GEOMETRY_LOCK_PTR                        (0x38)
#define LCK_RW_LOCK_SHARED                              (0x40)
#define LCK_RW_DONE                                     (0x48)
#define H_S_C_SBN_EPILOGUE_ADDR                         (0x50)
#define MACH_SYSCALL                                    (0x58)
#define OFFSETOF_ACT_CONTEXT                            (0x60)
#define THREAD_EXCEPTION_RETURN                         (0x68)
#define PLATFORM_SYSCALL_START                          (0x70)
#define PLATFORM_SYSCALL_END                            (0x78)
#define THREAD_SYSCALL_RETURN_START                     (0x80)
#define THREAD_SYSCALL_RETURN_END                       (0x88)
#define UNIX_SYSCALL_RETURN_START                       (0x90)
#define UNIX_SYSCALL_RETURN_END                         (0x98)
#define LCK_GRP_ALLOC_INIT                              (0xa0)
#define LCK_RW_ALLOC_INIT                               (0xa8)
#define SLEH_SYNCHRONOUS                                (0xb0)
#define CURRENT_PROC                                    (0xb8)
#define EXCEPTION_TRIAGE                                (0xc0)
/* XXX start common functions */
#define COMMON_FXNS_GET_STALKER_CACHE                   (0xc8)
#define STALKER_CTL_FROM_TABLE                          (0xd0)
#define SHOULD_INTERCEPT_CALL                           (0xd8)
#define GET_NEXT_FREE_STALKER_CTL                       (0xe0)
#define IS_SYSCTL_REGISTERED                            (0xe8)
#define SEND_EXCEPTION_MSG                              (0xf0)
#define GET_FLAG_PTR_FOR_CALL_NUM                       (0xf8)
/* XXX end common functions */
#define STALKER_TABLE_PTR                               (0x100)
#define SVC_STALKER_SYSCTL_NAME_PTR                     (0x108)
#define SVC_STALKER_SYSCTL_DESCR_PTR                    (0x110)
#define SVC_STALKER_SYSCTL_FMT_PTR                      (0x118)
#define SVC_STALKER_SYSCTL_MIB_PTR                      (0x120)
#define SVC_STALKER_SYSCTL_MIB_COUNT_PTR                (0x128)
#define HANDLE_SVC_HOOK                                 (0x130)
#define SVC_STALKER_CTL_CALLNUM                         (0x138)
#define RETURN_INTERCEPTOR                              (0x140)
#define STALKER_LOCK                                    (0x148)
#define CUR_CALL_ID                                     (0x150)

/* $0: stalker cache pointer
 * $1: register to store function pointer
 *
 * This macro is for svc_stalker_ctl syscall because by the time we
 * can SSH in there is no way it isn't NULL
 */
.macro TAKE_STALKER_LOCK
ldr x0, [$0, STALKER_LOCK]
ldr $1, [$0, LCK_RW_LOCK_SHARED]
blr $1
.endmacro

/* $0: stalker cache pointer
 * $1: register to store function pointer
 * $2: label to branch to if lock is NULL
 *
 * This macro is for anything that isn't svc_stalker_ctl.
 */
.macro TAKE_STALKER_LOCK_CHK
ldr x0, [$0, STALKER_LOCK]
cbz x0, $2
ldr $1, [$0, LCK_RW_LOCK_SHARED]
blr $1
.endmacro

/* $0: stalker cache pointer
 * $1: register to store function pointer
 */
.macro RELEASE_STALKER_LOCK
ldr x0, [$0, STALKER_LOCK]
ldr $1, [$0, LCK_RW_DONE]
blr $1
.endmacro

#endif
