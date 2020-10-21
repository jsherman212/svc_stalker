#ifndef HANDLE_SVC_HOOK_
#define HANDLE_SVC_HOOK_

#define STACK                       (0x200)

#define NUM_INSTRS_BEFORE_CACHE     (9)
#define STALKER_CACHE_PTR_PTR       (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

/* local variables */
#define SAVED_STATE_PTR             (STACK-0x70)
#define EXC_CODES                   (STACK-0x78)    /* XXX array of 2 uint64_t */
#define CUR_PID                     (STACK-0x88)
#define SYSCTL_OID_STRUCT           (STACK-0xe0)    /* XXX sizeof(sysctl_oid) == 0x50 */
#define STALKER_LOCK_GROUP_NAME     (STACK-0xe8)

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

#endif
