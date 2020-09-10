#ifndef HANDLE_SVC_HOOK
#define HANDLE_SVC_HOOK

#define STACK                       (0x200)

#define NUM_INSTRS_BEFORE_CACHE     (9)
#define STALKER_CACHE_PTR_PTR       (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

/* local variables */
#define SAVED_STATE_PTR             (STACK-0x70)
#define EXC_CODES                   (STACK-0x78)    /* XXX array of 2 uint64_t */
#define CUR_PID                     (STACK-0x88)
#define SYSCTL_OID_STRUCT           (STACK-0xe0)    /* XXX sizeof(sysctl_oid) == 0x50 */

/* sysctl stuff */
#define OID_AUTO                    (-1)

#define CTLTYPE_INT                 (2)
#define CTLFLAG_RD                  (0x80000000)
#define CTLFLAG_ANYBODY             (0x10000000)

#define SYSCTL_OID_VERSION          (1)

/* exception stuff */
#define EXC_SYSCALL                 (7)
#define EXC_MACH_SYSCALL            (8)

#define BEFORE_CALL                 (0)
#define CALL_COMPLETED              (1)

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
