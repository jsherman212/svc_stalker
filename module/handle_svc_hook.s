    .globl _main
    .align 4

#include "handle_svc_hook.h"

_main:
    sub sp, sp, STACK
    stp x27, x28, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    ; XXX do not move this adr
    adr x19, CACHE_START
    str x19, [sp, OFFSET_CACHE_PTR]
    ldr x20, [x19, EXCEPTION_TRIAGE_CACHEOFF]
    str x20, [sp, EXCEPTION_TRIAGE_FPTR]

    ; TODO re-implement the sanity checks we overwrote


    ; XXX for testing
    ;ldr x9, [sp, OFFSET_CACHE_PTR]
    ;ldr x9, [x9, EXCEPTION_TRIAGE_CACHEOFF]
    ;ldr x10, [sp, EXCEPTION_TRIAGE_FPTR]




    ;brk 0


    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret
