#ifndef COMMON_FUNCTIONS
#define COMMON_FUNCTIONS

/* the one instruction is the udf #0xffff */
#define NUM_INSTRS_BEFORE_CACHE     (1)
#define STALKER_CACHE_PTR_PTR       (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

#endif
