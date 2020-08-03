#ifndef SVC_STALKER_CTL
#define SVC_STALKER_CTL

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (1)
#define NUM_INSTRS_BEFORE_CACHE     (11)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

#define PID_TABLE_CACHEOFF          (0x0)

/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define PID_TABLE_PTR               (STACK-0x78)

/* constants */
#define MAX_SIMULTANEOUS_PIDS       (4095)

#endif
