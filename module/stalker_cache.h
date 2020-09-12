#ifndef STALKER_CACHE
#define STALKER_CACHE

/* offsets for stuff within the stalker cache */

#define PROC_PID                                        (0x0)
#define KALLOC_CANBLOCK                                 (0x8)
#define KFREE_ADDR                                      (0x10)
#define SYSCTL__KERN_CHILDREN_PTR                       (0x18)
#define SYSCTL_REGISTER_OID                             (0x20)
#define SYSCTL_HANDLE_LONG                              (0x28)
#define NAME2OID                                        (0x30)
#define SYSCTL_GEOMETRY_LOCK_PTR                        (0x38)
#define LCK_RW_LOCK_SHARED                              (0x40)
#define LCK_RW_DONE                                     (0x48)
#define H_S_C_SBN_EPILOGUE_ADDR                         (0x50)
#define CURRENT_PROC                                    (0x58)
#define EXCEPTION_TRIAGE                                (0x60)
/* next one only to be called inside common_functions.s */
#define COMMON_FXNS_GET_STALKER_CACHE                   (0x68)
#define STALKER_CTL_FROM_TABLE                          (0x70)
#define SHOULD_INTERCEPT_CALL                           (0x78)
#define GET_NEXT_FREE_STALKER_CTL                       (0x80)
#define GET_CALL_LIST_FREE_SLOT                         (0x88)
#define GET_CALL_LIST_SLOT                              (0x90)
#define IS_SYSCTL_REGISTERED                            (0x98)
#define STALKER_TABLE_PTR                               (0xa0)
#define SVC_STALKER_SYSCTL_NAME_PTR                     (0xa8)
#define SVC_STALKER_SYSCTL_DESCR_PTR                    (0xb0)
#define SVC_STALKER_SYSCTL_FMT_PTR                      (0xb8)
#define SVC_STALKER_SYSCTL_MIB_PTR                      (0xc0)
#define SVC_STALKER_SYSCTL_MIB_COUNT_PTR                (0xc8)
#define SVC_STALKER_CTL_CALLNUM                         (0xd0)
#define ARM_PREPARE_SYSCALL_RETURN_FAKESTK_LR           (0xd8)
#define ARM_PREPARE_SYSCALL_RETURN_HOOK                 (0xe0)

#endif
