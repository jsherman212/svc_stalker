    .globl _main
    .align 4

#include "stalker_cache.h"
#include "tail_call_init.h"

; This code will back up the original stack frame and set LR to branch to
; my code.
;
; I use this for arm_prepare_syscall_return and mach_syscall. For both, they
; return to the code inside return_interceptor.s instead of their original
; callers.
;
; Having a common entrypoint to do this presents an issue, though. Because I am
; overwriting an instruction to branch to this code, how will I know which
; replaced instruction to execute? arm_prepare_syscall_return has four parameters
; and mach_syscall only has one. That means I can use X4, X5, X6, and X7.
;
; So instead of just writing a branch to this code, I'll write an instruction
; before it to set an X4. For arm_prepare_syscall_return, X4 will be zero, and
; for mach_syscall, X4 will be one.
;
; For example, on an iPhone 8 (13.6.1) kernel, these are the first two
; instructions for arm_prepare_syscall_return and mach_syscall, respectively:
;
; STP             X29, X30, [SP,#-0x10]!
; MOV             X29, SP
;
; SUB             SP, SP, #0xC0
; STP             X24, X23, [SP,#0x80]
;
; After svc_stalker patches them:
;
; MOV             X4, #0
; B               tail_call_init
;
; MOV             X4, #1
; B               tail_call_init
;
; After the assembly inside this file is written to the executable scratch space,
; svc_stalker writes back the logic for executing the replaced instructions:
;
; [ ... last instruction in this file ]
; STP             X29, X30, [SP,#-0x10]!
; MOV             X29, SP
; BR              X7       ; in this case, arm_prepare_syscall_return+0x8
; SUB             SP, SP, #0xC0
; STP             X24, X23, [SP,#0x80]
; BR              X7       ; in this case, mach_syscall+0x8
;
; Each sequence of "written back" instructions will be 12 bytes, so it'll be
; very easy to jump to the correct sequence by using X4 as an index.

_main:
    adr x5, STALKER_CACHE_PTR_PTR
    ldr x5, [x5]
    ldr x6, [x5, RETURN_INTERCEPTOR]

    ; save original stack frame
    stp x29, x30, [sp, -0x10]!
    mov x29, sp

    cmp x4, 0x1
    b.eq mach_syscall

    ldr x7, [x5, ARM_PREPARE_SYSCALL_RETURN]
    b set_up_tail_call

mach_syscall:
    ldr x7, [x5, MACH_SYSCALL]
    b set_up_tail_call

set_up_tail_call:
    ; we overwrote two instructions
    add x7, x7, 0x8
    ; set LR to return_interceptor
    mov x30, x6
    ; branch to correct return sequence
    ; get addr of instr after br x5
    adr x5, 0x10
    mov x6, 0xc
    madd x5, x6, x4, x5
    br x5
    ; from here on are instructions svc_stalker writes back
