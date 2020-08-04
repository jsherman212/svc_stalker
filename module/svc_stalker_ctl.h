#ifndef SVC_STALKER_CTL
#define SVC_STALKER_CTL

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (3)
#define NUM_INSTRS_BEFORE_CACHE     (11)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

#define PID_TABLE_CACHEOFF          (0x0)
#define IOLOG_FPTR_CACHEOFF         (0x8)
#define IOMALLOC_FPTR_CACHEOFF      (0x10)

/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define PID_TABLE_PTR               (STACK-0x78)
#define CUR_PID_SLOT                (STACK-0x80)
#define IOLOG_FPTR                  (STACK-0x88)
#define IOMALLOC_FPTR               (STACK-0x90)

/* pid table stuff */
#define MAX_SIMULTANEOUS_PIDS       (4095)
#define OPEN_SLOT                   (-1)
#define PID_TABLE_NUM_PIDS_OFF      (0x0)

#endif
