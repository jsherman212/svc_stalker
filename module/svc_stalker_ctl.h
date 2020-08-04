#ifndef SVC_STALKER_CTL
#define SVC_STALKER_CTL

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (3)
#define NUM_INSTRS_BEFORE_CACHE     (11)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

#define STALKER_TABLE_CACHEOFF      (0x0)
#define IOLOG_FPTR_CACHEOFF         (0x8)
#define IOMALLOC_FPTR_CACHEOFF      (0x10)

/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define STALKER_TABLE_PTR           (STACK-0x78)
#define CUR_PID_SLOT                (STACK-0x80)
#define IOLOG_FPTR                  (STACK-0x88)
#define IOMALLOC_FPTR               (STACK-0x90)

/* stalker table stuff */
#define STALKER_TABLE_MAX           (1023)
#define STALKER_TABLE_FREE_SLOT     (0x0)
#define STALKER_TABLE_NUM_PIDS_OFF  (0x0)

#define STALKER_CTL_FREE_OFF        (0x0)
#define STALKER_CTL_PID_OFF         (0x4)
#define STALKER_CTL_CALL_LIST_OFF   (0x8)

#define CALL_LIST_MAX               (1000)
#define CALL_LIST_FREE_SLOT         (-0xffff)

#endif
