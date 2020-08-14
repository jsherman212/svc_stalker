#ifndef HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK
#define HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (0)
#define NUM_INSTRS_BEFORE_CACHE     (0)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))


#endif
