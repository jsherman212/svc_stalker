    .globl _main
    .align 4

#include "arm_prepare_syscall_return_hook.h"
#include "stalker_cache.h"
#include "stalker_table.h"

; This is where we intercept Unix syscalls upon their return. This code
; is executed when arm_prepare_syscall_return returns.

_main:
    sub sp, sp, STACK
    stp x28, x27, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    ; TODO mov x20, x1, can stomp out a few instrs that way
    str x1, [sp, SAVED_STATE_PTR]

    adr x19, STALKER_CACHE_PTR_PTR
    ; XXX from now on, X28 == stalker cache pointer, do not modify X28
    ldr x28, [x19]

    ; don't do anything until the svc_stalker_ctl_callnum sysctl is registered.
    ; My gut is telling me that if we've reached here, we've executed the code
    ; in handle_svc_hook and registered the sysctl, but just in case
    ldr x19, [x28, IS_SYSCTL_REGISTERED]
    blr x19
    ; no sysctl?
    cbz x0, done

    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x0, [x19, 0x88]
    ldr x19, [x28, SHOULD_INTERCEPT_CALL]
    blr x19
    cbz x0, done

    ldr x19, [x28, CURRENT_PROC]
    blr x19
    ldr x19, [x28, PROC_PID]
    blr x19
    mov w1, w0
    mov x0, EXC_SYSCALL                     ; only Unix syscalls are handled here
    mov w2, CALL_COMPLETED                  ; if we're here, this call has completed
    ldr x19, [x28, SEND_EXCEPTION_MSG]
    blr x19

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK

    ; arm_prepare_syscall_return's original stack frame, restore it
    ; so we return to its caller
    ldp x29, x30, [sp], 0x10
    ret
