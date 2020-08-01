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

    str x19, [sp, SAVED_STATE_PTR]

    ; XXX when I move or add anything before this adr, update NUM_INSTRS_BEFORE_CACHE
    adr x19, CACHE_START
    str x19, [sp, OFFSET_CACHE_PTR]
    ldr x20, [x19, EXCEPTION_TRIAGE_CACHEOFF]
    str x20, [sp, EXCEPTION_TRIAGE_FPTR]

    ; TODO re-implement the sanity checks we overwrote

    ; XXX for testing
    ;ldr x9, [sp, OFFSET_CACHE_PTR]
    ;ldr x9, [x9, EXCEPTION_TRIAGE_CACHEOFF]
    ;ldr x0, [sp, EXCEPTION_TRIAGE_FPTR]
    ;ldr x1, [sp, SAVED_STATE_PTR]
    ;ldr x1, [x1, 0x88]                      ; X16, system call number

    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x19, [x19, 0x88]
    cmp x19, 0
    b.eq done

    brk 0


done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret
