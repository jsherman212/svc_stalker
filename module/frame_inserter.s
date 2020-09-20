    .globl _main
    .align 4

#include "frame_inserter.h"
#include "stalker_cache.h"

; This code will insert a fake stack frame in order to cause a tail call
; to my code.
;
; I use this for arm_prepare_syscall_return and mach_syscall. For both, they
; return to the code inside return_interceptor.s instead of their original
; callers.
;
; Having a common entrypoint to do this presents an issue, though. Because I am
; overwriting an instruction to branch to this code, how will I know which
; replaced instruction to execute? Eventually I realized I could manipulate
; condition flags to mimic a first parameter. I want to stay away from using
; registers to avoid clobbering one which may be used later.
;
; So instead of just writing a branch to this code, I'll write an instruction
; before it to set an appropriate flag. For arm_prepare_syscall_return,
; the zero flag will be set, and for mach_syscall, the negative flag will
; be set. I'll write the result of the calculation to XZR so it's discarded.
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
; SUBS            XZR, X30, X30
; B               frame_inserter
;
; SUBS            XZR, XZR, X30
; B               frame_inserter
;
; After the assembly inside frame_inserter is written to the executable
; scratch space, svc_stalker writes back the logic for executing the replaced
; instructions:
;
; [ ... last instruction in this file ]
; B.LT            #3       ; were we called from mach_syscall?
; STP             X29, X30, [SP,#-0x10]!
; MOV             X29, SP
; BR              X7       ; in this case, arm_prepare_syscall_return+0x8
; SUB             SP, SP, #0xC0
; STP             X24, X23, [SP,#0x80]
; BR              X7       ; in this case, mach_syscall+0x8

_main:
    ; arm64 calling convention states x0-x7 are parameter/result registers.
    ; arm_prepare_syscall_return has four params and mach_syscall has one param,
    ; so we'll clobber x5, x6, and x7
    ; save condition flags
    mrs x5, NZCV

    ; save original stack frame
    stp x29, x30, [sp, -0x10]!
    mov x29, sp

    adr x6, STALKER_CACHE_PTR_PTR
    ldr x6, [x6]


    tbnz x5, 0x1f, mach_syscall

    ; assume caller is arm_prepare_syscall_return
    ldr x7, [x6, ARM_PREPARE_SYSCALL_RETURN]
    b write_fake_stack_frame

mach_syscall:
    ; ldr x7, [x6, MACH_SYSCALL]
    ; until I write the logic to grab mach_syscall's address
    mov x7, 0x4141
    b write_fake_stack_frame

write_fake_stack_frame:
    ; we overwrote two instructions
    add x7, x7, 0x8
    stp x29, x7, [sp, -0x10]!
    mov x29, sp

    ; at this point, svc_stalker writes back the instructions we overwrote
