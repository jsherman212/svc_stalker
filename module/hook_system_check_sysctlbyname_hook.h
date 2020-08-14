#ifndef HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK
#define HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (7)
#define NUM_INSTRS_BEFORE_CACHE     (12)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

/* cache offsets */
#define SYSCTL_GEOMETRY_LOCK_PTR_CACHEOFF       (0x0)
#define LCK_RW_LOCK_SHARED_FPTR_CACHEOFF        (0x8)
#define LCK_RW_DONE_FPTR_CACHEOFF               (0x10)
#define NEW_SYSCTL_MIB_PTR_CACHEOFF             (0x18)
#define NEW_SYSCTL_MIB_COUNT_PTR_CACHEOFF       (0x20)
#define STALKER_TABLE_CACHEOFF                  (0x28)
#define H_S_C_SBN_EPILOGUE_BEGIN_CACHEOFF       (0x30)

/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0xb0)
#define SYSCTL_GEOMETRY_LOCK_PTR    (STACK-0xb8)
#define LCK_RW_LOCK_SHARED_FPTR     (STACK-0xc0)
#define LCK_RW_DONE_FPTR            (STACK-0xc8)
#define NEW_SYSCTL_MIB_PTR          (STACK-0xd0)
#define NEW_SYSCTL_MIB_COUNT_PTR    (STACK-0xd8)
#define STALKER_TABLE_PTR           (STACK-0xe0)
#define H_S_C_SBN_EPILOGUE_ADDR     (STACK-0xe8)

/* stalker table stuff */
#define STALKER_TABLE_REGISTERED_SYSCTL_OFF     (0x8)

/* sysctl stuff */
#define CTL_MAXNAME                 (12)

#endif
