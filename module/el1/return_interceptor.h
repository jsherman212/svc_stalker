#ifndef RETURN_INTERCEPTOR_
#define RETURN_INTERCEPTOR_

#define STACK                       (0x200)

#define NUM_INSTRS_BEFORE_CACHE     (6)
#define STALKER_CACHE_PTR_PTR       (-((4*NUM_INSTRS_BEFORE_CACHE)+8))

/* local variables */
#define EXC_CODES                   (STACK-0x78)    /* XXX array of 2 uint64_t */
#define CALL_NUM                    (STACK-0x88)

/* exception stuff */
#define EXC_SYSCALL                 (7)
#define EXC_MACH_SYSCALL            (8)

#define CALL_COMPLETED              (1)

#endif
