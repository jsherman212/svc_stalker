    .globl _main
    .align 4

#include "thread_exception_return_hook.h"   /* for X28 constant */

; platform_syscall just calls thread_exception_return instead of returning, so
; to intercept platform syscalls, this code will write a special value to X28
; so thread_exception_return_hook knows to send the exception msg
; I chose X28 because that register isn't saved to the stack in platform_syscall's
; function prologue, so I can assume it's unused throughout that function

_main:
    mov x28, PLATFORM_SYSCALL_HOOK_X28

    ; missing a ret so stalker_main_patcher can write back that and the instr
    ; I overwrote to branch to this
