#ifndef HANDLE_SVC_HOOK
#define HANDLE_SVC_HOOK

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (17)
#define NUM_INSTRS_BEFORE_CACHE     (9)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

/* cache offsets */
#define EXCEPTION_TRIAGE_CACHEOFF               (0x0)
#define CURRENT_PROC_CACHEOFF                   (0x8)
#define PROC_PID_CACHEOFF                       (0x10)
#define STALKER_TABLE_CACHEOFF                  (0x18)
#define PATCHED_SYSCALL_NUM_CACHEOFF            (0x20)
#define SYSCTL_NAME_CACHEOFF                    (0x28)
#define SYSCTL_DESCR_CACHEOFF                   (0x30)
#define SYSCTL_FMT_CACHEOFF                     (0x38)
#define SYSCTL__KERN_CHILDREN_CACHEOFF          (0x40)
#define SYSCTL_REGISTER_OID_FPTR_CACHEOFF       (0x48)
#define SYSCTL_HANDLE_LONG_CACHEOFF             (0x50)
#define NAME2OID_FPTR_CACHEOFF                  (0x58)
#define SYSCTL_GEOMETRY_LOCK_PTR_CACHEOFF       (0x60)
#define LCK_RW_LOCK_SHARED_FPTR_CACHEOFF        (0x68)
#define LCK_RW_DONE_FPTR_CACHEOFF               (0x70)
#define NEW_SYSCTL_MIB_PTR_CACHEOFF             (0x78)
#define NEW_SYSCTL_MIB_COUNT_PTR_CACHEOFF       (0x80)

/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define EXCEPTION_TRIAGE_FPTR       (STACK-0x78)
#define CURRENT_PROC_FPTR           (STACK-0x80)
#define PROC_PID_FPTR               (STACK-0x88)
#define STALKER_TABLE_PTR           (STACK-0x90)
#define SAVED_STATE_PTR             (STACK-0x98)
#define EXC_CODES                   (STACK-0xa0)    /* XXX array of 2 uint64_t */
#define CUR_PID                     (STACK-0xb0)
#define PATCHED_SYSCALL_NUM         (STACK-0xb8)
#define SYSCTL_NAME                 (STACK-0xc0)
#define SYSCTL_DESCR                (STACK-0xc8)
#define SYSCTL_FMT                  (STACK-0xd0)
#define SYSCTL__KERN_CHILDREN_PTR   (STACK-0xd8)
#define SYSCTL_REGISTER_OID_FPTR    (STACK-0xe0)
#define SYSCTL_HANDLE_LONG_FPTR     (STACK-0xe8)
#define SYSCTL_OID_STRUCT           (STACK-0x140)  /* XXX sizeof(sysctl_oid) == 0x50 */
#define NAME2OID_FPTR               (STACK-0x148)
#define SYSCTL_GEOMETRY_LOCK_PTR    (STACK-0x150)
#define LCK_RW_LOCK_SHARED_FPTR     (STACK-0x158)
#define LCK_RW_DONE_FPTR            (STACK-0x160)
#define NEW_SYSCTL_MIB_PTR          (STACK-0x168)
#define NEW_SYSCTL_MIB_COUNT_PTR    (STACK-0x170)

/* sysctl stuff */
#define OID_AUTO                    (-1)

#define CTLTYPE_INT                 (2)
#define CTLFLAG_RD                  (0x80000000)
#define CTLFLAG_ANYBODY             (0x10000000)

#define SYSCTL_OID_VERSION          (1)

/* exception stuff */
#define EXC_SYSCALL                 (7)
#define EXC_MACH_SYSCALL            (8)

/* stalker table stuff */
#define STALKER_TABLE_MAX           (1023)
#define STALKER_TABLE_FREE_SLOT     (0x0)
#define STALKER_TABLE_NUM_PIDS_OFF  (0x0)
#define STALKER_TABLE_REGISTERED_SYSCTL_OFF (0x8)

#define STALKER_CTL_FREE_OFF        (0x0)
#define STALKER_CTL_PID_OFF         (0x4)
#define STALKER_CTL_CALL_LIST_OFF   (0x8)

#define CALL_LIST_MAX               (1000)
#define CALL_LIST_FREE_SLOT         (0x4000)

#endif
