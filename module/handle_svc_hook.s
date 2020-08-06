    .globl _main
    .align 4

#include "handle_svc_hook.h"

; this iterates through the PIDs/syscalls the user has registered through the
; svc_stalker_ctl syscall and calls exception_triage if current_proc()->p_pid
; is found in that list
_main:
    sub sp, sp, STACK
    stp x28, x27, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    str x19, [sp, SAVED_STATE_PTR]

    ; XXX when I move or add anything before this adr, update NUM_INSTRS_BEFORE_CACHE
    adr x19, CACHE_START
    str x19, [sp, OFFSET_CACHE_PTR]
    ldr x20, [x19, EXCEPTION_TRIAGE_CACHEOFF]
    str x20, [sp, EXCEPTION_TRIAGE_FPTR]
    ldr x20, [x19, CURRENT_PROC_CACHEOFF]
    str x20, [sp, CURRENT_PROC_FPTR]
    ldr x20, [x19, PROC_PID_CACHEOFF]
    str x20, [sp, PROC_PID_FPTR]
    ldr x20, [x19, STALKER_TABLE_CACHEOFF]
    str x20, [sp, STALKER_TABLE_PTR]

    ; figure out if the system call made by this PID should be
    ; reported back to userland
    ldr x19, [sp, CURRENT_PROC_FPTR]
    blr x19
    ldr x19, [sp, PROC_PID_FPTR]
    blr x19
    ; W0 = proc_pid(current_proc())
    mov w1, w0
    ldr x0, [sp, STALKER_TABLE_PTR]
    bl _stalker_ctl_from_table
    ; user doesn't want to intercept any system calls from this pid, bail
    cmp x0, 0
    b.eq done
    ; does the user want this system call to be intercepted?
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x1, [x19, 0x88]
    ;cmp x1, 0
    ;b.lt send_exc_msg
    ; X0 = pointer to stalker_ctl struct for proc_pid(current_proc())
    bl _should_intercept_syscall
    cmp x0, 0
    ; if user does not want this system call intercepted, we're done
    b.eq done
    
    ; TODO re-implement the sanity checks we overwrote

    ; call exception_triage
    ; EXC_GUARD, EXC_RESOURCE exceptions cause exception_triage to return to caller
send_exc_msg:
    ;mov x0, EXC_RESOURCE
    mov x0, EXC_SYSCALL
    mov x1, EXC_MACH_SYSCALL
    ldr x2, [sp, SAVED_STATE_PTR]
    ldr x2, [x2, 0x88]                      ; X16, system call number
    cmp x2, 0
    csel x0, x1, x0, lt
    str x2, [sp, EXC_CODES]
    str xzr, [sp, EXC_CODES+8]
    add x1, sp, EXC_CODES                   ; code
    mov w2, 2                               ; codeCnt
    ldr x19, [sp, EXCEPTION_TRIAGE_FPTR]
    blr x19

    ; need to patch exception_triage to return on EXC_SYSCALL / EXC_MACH_SYSCALL
    ; XXX if I'm going to do that, I need to patch out the one place
    ; EXC_SYSCALL is used: mach_syscall @ bsd_arm64.c

    ; if it does return, don't overwrite retval and panic
    ;mov x1, 0x4141
    ;mov x2, 0x4242
    ;mov x3, 0x4343
    ;brk 0

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret

; this function figures out if a pid is in the stalker table, and returns
; a pointer to its corresponding stalker_ctl struct if it is there
;
; arguments:
;   X0 = stalker table pointer
;   W1 = pid
;
; returns: pointer if pid is in stalker table, NULL otherwise
_stalker_ctl_from_table:
    ; empty stalker table?
    ldr w9, [x0, STALKER_TABLE_NUM_PIDS_OFF]
    cmp w9, 0
    b.eq not_found0

    mov w10, 1
    add x11, x0, w10, lsl 4

search0:
    ldr w12, [x11, STALKER_CTL_PID_OFF]
    cmp w12, w1
    b.eq found0
    add w10, w10, 1
    cmp w10, STALKER_TABLE_MAX
    b.ge not_found0
    add x11, x0, w10, lsl 4
    b search0

not_found0:
    mov x0, 0
    ret

found0:
    mov x0, x11
    ret

; this function figures out if exception_triage should be called given
; a system call number
;
; parameters:
;   X0 = stalker_ctl struct pointer
;   X1 = system call number
;
; returns: 1 if system call number is present inside the stalker_ctl's call list,
;   0 otherwise
_should_intercept_syscall:
    ; empty system call list for this stalker_ctl struct pointer?
    ldr x0, [x0, STALKER_CTL_CALL_LIST_OFF]
    cmp x0, 0
    b.eq do_not_intercept

    mov w9, 0
    mov x10, x0

search1:
    ldr x11, [x10]
    cmp x11, x1
    b.eq intercept
    add w9, w9, 1
    cmp w9, CALL_LIST_MAX 
    b.ge do_not_intercept
    add x10, x0, w9, lsl 3
    b search1

do_not_intercept:
    mov x0, 0
    ret

intercept:
    mov x0, 1
    ret
