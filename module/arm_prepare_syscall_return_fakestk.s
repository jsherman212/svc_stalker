    .globl _main
    .align 4

#include "arm_prepare_syscall_return_fakestk.h"
#include "stalker_cache.h"

; arm_prepare_syscall_return is what we're modifying to intercept Unix syscalls upon
; return. However, the function is implemented as a switch statement and
; as a result, there are multiple places where this function returns. 
; Originally, I was just gonna overwrite all of the RET's in this function
; to tail call my code, but I felt that was "nasty". So I figured I'd overwrite
; the first instruction of its prologue to branch here so I can
; to set up a fake stack frame. That way, when arm_prepare_syscall_return returns,
; it will end up returning to arm_prepare_syscall_return_hook instead of its
; original caller.

_main:
    adr x8, STALKER_CACHE_PTR_PTR
    ldr x8, [x8]
    ldr x9, [x8, ARM_PREPARE_SYSCALL_RETURN_HOOK]

    ; arm_prepare_syscall_return's original stack frame and caller,
    ; need to save it so arm_prepare_syscall_return_hook can return
    ; back to the original caller
    stp x29, x30, [sp, -0x10]!
    mov x29, sp

    ; fake stack frame to return to arm_prepare_syscall_return_hook
    stp x29, x9, [sp, -0x10]!

    ; XXX XXX when doing patchfinder unit tests make sure that
    ; the instruction we return to is MOV X29, SP for every kernel!!!

    ; return back to where we branched from in arm_prepare_syscall_return
    ldr x8, [x8, ARM_PREPARE_SYSCALL_RETURN_FAKESTK_LR]
    br x8
