    .globl _main
    .align 4

#include "stalker_cache.h"
#include "stalker_table.h"
#include "thread_exception_return_hook.h"

; thread_exception_return is hooked in order to intercept platform syscalls
; upon their return
; see also: platform_syscall_hook.s

_main:
    sub sp, sp, STACK
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    adr x20, STALKER_CACHE_PTR_PTR
    ldr x20, [x20]

    ; see platform_syscall_hook.s
    mov x19, PLATFORM_SYSCALL_HOOK_X28
    subs x19, x28, x19
    ; if we're not coming from platform_syscall, we're done
    cbnz x19, done

    ; platform syscall call num
    mov w0, 0x80000000
    ldr x19, [x20, SHOULD_INTERCEPT_CALL]
    blr x19
    cbz x0, done
    ldr x19, [x20, CURRENT_PROC]
    blr x19
    ldr x19, [x20, PROC_PID]
    blr x19
    mov w1, w0
    mov x0, EXC_SYSCALL
    mov w2, CALL_COMPLETED
    ldr x19, [x20, SEND_EXCEPTION_MSG]
    blr x19

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    add sp, sp, STACK
    ; missing a ret so patch_thread_exception_return can write back that and
    ; the instr I overwrote to branch to here
