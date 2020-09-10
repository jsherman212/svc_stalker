#ifndef SVC_STALKER_CTL
#define SVC_STALKER_CTL

#define STACK                       (0x200)

#define NUM_INSTRS_BEFORE_CACHE     (11)
#define STALKER_CACHE_PTR_PTR       (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

/* parameters */
#define PID_ARG                     (0x0)
#define FLAVOR_ARG                  (0x8)
#define ARG2                        (0x10)
#define ARG3                        (0x18)

#define PID_MANAGE                  (0)
#define CALL_LIST_MANAGE            (1)

/* local variables */
#define CALL_LIST_KALLOC_SZ         (STACK-0x78)
#define CUR_STALKER_CTL             (STACK-0x80)

/* stalker table stuff */
#define STALKER_TABLE_MAX           (1023)
#define STALKER_TABLE_FREE_SLOT     (0x0)
#define STALKER_TABLE_NUM_PIDS_OFF  (0x0)

/* struct stalker_ctl {
 *       is this entry not being used?
 *     uint32_t free;
 *
 *       what pid this entry belongs to
 *     int32_t pid;
 *
 *       list of call numbers to intercept & send to userland
 *     int64_t *call_list;
 * };
 *
 * Empty spots in the call list are represented by 0x4000 because that
 * doesn't represent any system call or mach trap.
 *
 * sizeof(struct stalker_ctl) = 0x10
 */
#define STALKER_CTL_FREE_OFF        (0x0)
#define STALKER_CTL_PID_OFF         (0x4)
#define STALKER_CTL_CALL_LIST_OFF   (0x8)

#define CALL_LIST_MAX               (1000)
#define CALL_LIST_FREE_SLOT         (0x4000)

#endif
