#ifndef HANDLE_SVC_HOOK
#define HANDLE_SVC_HOOK

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (1)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-(0x20+(8*NUM_CACHED_PTRS)))
/* cache offsets */
#define EXCEPTION_TRIAGE_CACHEOFF   (0x0)


/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define EXCEPTION_TRIAGE_FPTR       (STACK-0x78)


#endif
