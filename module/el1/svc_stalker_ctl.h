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

#endif
