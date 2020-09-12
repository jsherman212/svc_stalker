    .globl _main
    .align 4

#include "stalker_cache.h"

; This is where we intercept Unix syscalls upon their return. This code
; is executed when arm_prepare_syscall_return returns.

_main:
    ; mov x0, 0x4141
    ; mov x1, 0x4242
    ; mov x2, 0x4343
    ; brk 0

    ; arm_prepare_syscall_return's original stack frame
    ldp x29, x30, [sp]
    add sp, sp, 0x10
    ret
