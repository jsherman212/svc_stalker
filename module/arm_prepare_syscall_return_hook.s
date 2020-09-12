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

    str x1, [sp, SAVED_STATE_PTR]

    adr x19, STALKER_CACHE_PTR_PTR
    ; XXX from now on, X28 == stalker cache pointer, do not modify X28
    ldr x28, [x19]

    ; don't do anything until the svc_stalker_ctl_callnum sysctl is registered.
    ; My gut is telling me that if we've reached here, we've executed the code
    ; in handle_svc_hook and registered the sysctl, but just in case
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_LOCK_SHARED]
    blr x19
    ldr x19, [x28, STALKER_TABLE_PTR]
    ldr x20, [x19, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19
    ; no sysctl?
    cbz x20, done

    ; XXX code duplication! Move this into common_functions

    ; figure out if the system call made by this PID should be
    ; reported back to userland
    ldr x19, [x28, CURRENT_PROC]
    blr x19
    ldr x19, [x28, PROC_PID]
    blr x19
    str w0, [sp, CUR_PID]
    mov w1, w0
    ldr x0, [x28, STALKER_TABLE_PTR]
    ldr x19, [x28, STALKER_CTL_FROM_TABLE]
    blr x19
    ; user doesn't want to intercept any system calls from this pid, bail
    cbz x0, done
    ; does the user want this system call to be intercepted?
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x1, [x19, 0x88]
    ; X0 = pointer to stalker_ctl struct for proc_pid(current_proc())
    ldr x19, [x28, SHOULD_INTERCEPT_CALL]
    blr x19
    ; if user does not want this system call intercepted, we're done
    cbz x0, done

    ; XXX more code duplication

    mov x0, EXC_SYSCALL                     ; only Unix syscalls are handled here
    ldr w2, [sp, CUR_PID]
    str x2, [sp, EXC_CODES]                 ; pid which made the call
    mov w2, CALL_COMPLETED                  ; if we're here, this call has completed
    str x2, [sp, EXC_CODES+0x8]
    add x1, sp, EXC_CODES                   ; code
    mov w2, 2                               ; codeCnt
    ldr x19, [x28, EXCEPTION_TRIAGE]
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
