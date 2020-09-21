    .globl _main
    .align 4

#include "return_interceptor.h"
#include "stalker_cache.h"

; Intercept calls upon return

_main:
    sub sp, sp, STACK
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    adr x24, STALKER_CACHE_PTR_PTR
    ldr x24, [x24]

    ldr x19, [x24, IS_SYSCTL_REGISTERED]
    blr x19
    cbz x0, done

    mrs x19, TPIDR_EL1
    ; iphone 8 13.6.1, ACT_CONTEXT
    ldr x0, [x19, 0x448]
    ldr w0, [x0, 0x88]
    str w0, [sp, CALL_NUM]
    ldr x19, [x24, SHOULD_INTERCEPT_CALL]
    blr x19
    cbz x0, done
    ldr x19, [x24, CURRENT_PROC]
    blr x19
    ldr x19, [x24, PROC_PID]
    blr x19
    mov w1, w0
    mov x0, EXC_SYSCALL
    mov x3, EXC_MACH_SYSCALL
    ldr w2, [sp, CALL_NUM]
    cmp w2, wzr
    csel x0, x3, x0, lt
    mov w2, CALL_COMPLETED
    ldr x19, [x24, SEND_EXCEPTION_MSG]
    blr x19

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    add sp, sp, STACK

    ; restore original stack frame, see tail_call_init.s
    ldp x29, x30, [sp], 0x10
    ret
