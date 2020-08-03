    .globl _main
    .align 4

#include "svc_stalker_ctl.h"

; This is the system call we replaced the first enosys sysent entry
; with. It manages the list of PIDs we're intercepting syscalls for.
;
; Actual return value of this function gets set to errno later.
; retval, the second parameter, is the return value of this function.
_main:
    sub sp, sp, STACK
    stp x28, x27, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    mov x19, x0
    mov x20, x1
    mov x21, x2

    ldr w22, [x20]
    cmp w22, 0
    b.lt maybebadpid

    ldr w22, [x20]
    ldr w23, [x20, 8]

    mov w24, 0
    str w24, [x21]

    mov w0, 0

    b done

maybebadpid:
    ; user may have passed -1 for pid to see if this syscall was patched
    ; successfully
    cmp w22, -1
    b.ne badpid
    mov w0, 999
    str w0, [x21]
    mov w0, 0
    b done

badpid:
    mov w0, -1
    str w0, [x21]
    mov w0, 22                              ; EINVAL
    b done

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret
