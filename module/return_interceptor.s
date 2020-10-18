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
    cbz x0, almost_done

    mrs x19, TPIDR_EL1
    ldr x20, [x24, OFFSETOF_ACT_CONTEXT]
    ldr x0, [x19, x20]
    ldr w0, [x0, 0x88]
    str w0, [sp, CALL_NUM]
    ldr x19, [x24, SHOULD_INTERCEPT_CALL]
    blr x19
    cbz x0, almost_done
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

    ; remove the call ID from this thread's X16
    ; see handle_svc_hook.s
    mrs x19, TPIDR_EL1
    ldr x20, [x24, OFFSETOF_ACT_CONTEXT]
    ldr x21, [x19, x20]
    ldr x22, [x21, 0x88]
    cmp w22, wzr
    b.lt sign_extend_mach_trap_call_num

    ; zeroing out the top 32 bits for a syscall number works fine
    ; XXX not the culprit
    and x22, x22, 0xffffffff
    str x22, [x21, 0x88]

    b almost_done

sign_extend_mach_trap_call_num:
    sxtw x22, w22
    str x22, [x21, 0x88]

almost_done:
    ldp x29, x30, [sp, STACK-0x10]

    ; do we need to restore another stack frame? if we were called from...
    ;  ...sleh_synchronous: yes (see sleh_synchronous_hijacker.s)
    ;  ...thread_syscall_return, platform_syscall, unix_syscall_return: no,
    ;       and we just need to call thread_exception_return
maybe_called_from_thread_syscall_return:
    ldr x19, [x24, THREAD_SYSCALL_RETURN_START]
    cmp x30, x19
    b.lo maybe_called_from_platform_syscall
    ldr x19, [x24, THREAD_SYSCALL_RETURN_END]
    cmp x30, x19
    b.hi maybe_called_from_platform_syscall
    b call_thread_exception_return

maybe_called_from_platform_syscall:
    ldr x19, [x24, PLATFORM_SYSCALL_START]
    cmp x30, x19
    b.lo maybe_called_from_unix_syscall_return
    ldr x19, [x24, PLATFORM_SYSCALL_END]
    cmp x30, x19
    b.hi maybe_called_from_unix_syscall_return
    b call_thread_exception_return

maybe_called_from_unix_syscall_return:
    ldr x19, [x24, UNIX_SYSCALL_RETURN_START]
    cmp x30, x19
    b.lo called_from_sleh_synchronous
    ldr x19, [x24, UNIX_SYSCALL_RETURN_END]
    cmp x30, x19
    b.hi called_from_sleh_synchronous
    ; fall thru

call_thread_exception_return:
    ldr x19, [x24, THREAD_EXCEPTION_RETURN]
    blr x19
    ; not reached

called_from_sleh_synchronous:
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    add sp, sp, STACK

    ; restore original stack frame
    ldp x29, x30, [sp], 0x10
    ret
