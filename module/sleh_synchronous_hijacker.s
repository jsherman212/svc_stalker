    .globl _main
    .align 4

#include "sleh_synchronous_hijacker.h"
#include "stalker_cache.h"

; This will back up the original stack frame and set LR to return_interceptor
; if the current exception is ESR_EC_SVC_64.
;
; We've come from sleh_synchronous, it has three arguments, second being ESR_EL1.
; (because of that we can clobber x3, x4, x5, x6, and x7)

_main:
    adr x3, STALKER_CACHE_PTR_PTR
    ldr x3, [x3]

    ; leave sleh_synchronous alone if this exception isn't a supervisor call
    ; from userland
    lsr w4, w1, 0x1a
    cmp w4, ESR_EC_SVC_64
    b.ne done

    ; save original stack frame
    stp x29, x30, [sp, -0x10]!
    mov x29, sp

    ; call handle_svc_hook to send the BEFORE_CALL exception message
    sub sp, sp, 0x20
    stp x0, x1, [sp]
    stp x2, x3, [sp, 0x10]
    ldr x3, [x3, HANDLE_SVC_HOOK]
    blr x3
    ldp x2, x3, [sp, 0x10]
    ldp x0, x1, [sp]
    add sp, sp, 0x20

    ; set LR to return_interceptor
    ldr x30, [x3, RETURN_INTERCEPTOR]

done:
    ldr x3, [x3, SLEH_SYNCHRONOUS]
    ; we overwrote one instruction to branch to here
    add x3, x3, 0x4
    ; hijack_sleh_synchronous writes back the instr we overwrote
    ; and br x3 here
