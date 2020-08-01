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

    ; b dump_saved_state

    ; ldr x19, [sp, SAVED_STATE_PTR]
    ; ldr x19, [x19, 0x88]
    ; cmp x19, 0
    ; b.eq done

    ;brk 0

    ; TODO how to know if the device is done booting?

    ; call exception_triage
    mov x0, EXC_SYSCALL                     ; exception
    ldr x1, [sp, SAVED_STATE_PTR]
    ldr x1, [x1, 0x88]                      ; X16, system call number
    str x1, [sp, EXC_CODES]
    str xzr, [sp, EXC_CODES+8]
    add x1, sp, EXC_CODES                   ; code
    mov w2, 2                               ; codeCnt
    ldr x8, [sp, EXCEPTION_TRIAGE_FPTR]
    blr x8

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

dump_saved_state:
    ldr x18, [sp, SAVED_STATE_PTR]
    add x18, x18, 8
    ldp x0, x1, [x18]
    ldp x2, x3, [x18, 0x10]
    ldp x4, x5, [x18, 0x20]
    ldp x6, x7, [x18, 0x30]
    ldp x8, x9, [x18, 0x40]
    ldp x10, x11, [x18, 0x50]
    ldp x12, x13, [x18, 0x60]
    ldp x14, x15, [x18, 0x70]
    ldp x16, x17, [x18, 0x80]
    ldr x19, [x18, 0x98]
    ldp x20, x21, [x18, 0xa0]
    ldp x22, x23, [x18, 0xb0]
    ldp x24, x25, [x18, 0xc0]
    ldp x26, x27, [x18, 0xd0]
    ldp x28, x29, [x18, 0xe0]
    ldr x30, [x18, 0xf0]
    ldr x18, [x18, 0x100]       ; pc
    brk 0
