    .align 4
    .globl _main

#include "hook_system_check_sysctlbyname_hook.h"

_main:
    sub sp, sp, STACK
    stp x28, x27, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    b notours

ours:

    ret

; in the case our sysctl wasn't being dealt with, return back to
; hook_system_check_sysctlbyname to carry out its normal operation
notours:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ; this is missing a RET so svc_stalker can write back the instructions
    ; we overwrote to branch to this code
    ; XXX because of this, NOTHING CAN BE AFTER THIS POINT
