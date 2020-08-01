#ifndef HANDLE_SVC_HOOK
#define HANDLE_SVC_HOOK

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (1)
#define NUM_INSTRS_BEFORE_CACHE     (9)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((NUM_INSTRS_BEFORE_CACHE*4)+(8*NUM_CACHED_PTRS)))
/* cache offsets */
#define EXCEPTION_TRIAGE_CACHEOFF   (0x0)


/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define EXCEPTION_TRIAGE_FPTR       (STACK-0x78)
#define SAVED_STATE_PTR             (STACK-0x80)

/* exception stuff */
#define EXC_SYSCALL                 (7)


#endif
