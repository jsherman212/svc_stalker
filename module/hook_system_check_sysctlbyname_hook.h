#ifndef HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK
#define HOOK_SYSTEM_CHECK_SYSCTLBYNAME_HOOK

#define STACK                       (0x200)

#define NUM_INSTRS_BEFORE_CACHE     (12)
#define STALKER_CACHE_PTR_PTR       (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

/* stalker table stuff */
#define STALKER_TABLE_REGISTERED_SYSCTL_OFF     (0x8)

/* sysctl stuff */
#define CTL_MAXNAME                 (12)

#endif
