    .globl _main
    .align 4

#include "handle_svc_hook.h"

; this iterates through the PIDs the user has registered through doing
; syscall(n, pid, enabled) and calls exception_triage if current_proc()->p_pid
; is found in that list
;
; exception_triage will never be called for the patched system call
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
    ldr x20, [x19, PID_TABLE_CACHEOFF]
    str x20, [sp, PID_TABLE_PTR]
    ;mov x0, 0x4141
    ;ldr x1, [sp, PID_TABLE_PTR]
    ;str x0, [x1]
    ;brk 0

    ;ldr x0, [sp, EXCEPTION_TRIAGE_FPTR]
    ;ldr x1, [sp, CURRENT_PROC_FPTR]
    ;ldr x2, [sp, PROC_PID_FPTR]
    ;ldr x3, [sp, FILTER_MEM_PTR]

    ;brk 0

    ; figure out if the system call made by this PID should be
    ; reported back to userland
    ldr x19, [sp, CURRENT_PROC_FPTR]
    blr x19
    ldr x19, [sp, PROC_PID_FPTR]
    blr x19
    ; W0 = proc_pid(current_proc())
    str w0, [sp, CUR_PID]
    mov w1, w0
    ldr x0, [sp, PID_TABLE_PTR]
    bl _pid_in_table
    ; user doesn't want to intercept system calls from this pid, bail
    cmp x0, 0
    b.eq done
    ; make sure we only send system calls from CUR_PID when it's in
    ; the pid table
    ;ldr w0, [sp, 

    ;brk 0

    ; XXX
    ;b done

    ; TODO re-implement the sanity checks we overwrote

    ; XXX for testing
    ;ldr x9, [sp, OFFSET_CACHE_PTR]
    ;ldr x9, [x9, EXCEPTION_TRIAGE_CACHEOFF]
    ;ldr x0, [sp, EXCEPTION_TRIAGE_FPTR]
    ;ldr x1, [sp, SAVED_STATE_PTR]
    ;ldr x1, [x1, 0x88]                      ; X16, system call number

    ; b dump_saved_state

    ; ldr x19, [sp, SAVED_STATE_PTR]
    ; ldr x19, [x19, 0x88]
    ; cmp x19, 0
    ; b.eq done

    ;mov x8, 0x4141
    ;mov x9, 0x4242
    ;brk 0

    ; call exception_triage
    ; TODO distinguish between unix syscalls and mach traps and set the
    ; exception number accrodingly
    mov x0, EXC_SYSCALL                     ; exception
    ldr x1, [sp, SAVED_STATE_PTR]
    ldr x1, [x1, 0x88]                      ; X16, system call number
    str x1, [sp, EXC_CODES]
    str xzr, [sp, EXC_CODES+8]
    add x1, sp, EXC_CODES                   ; code
    mov w2, 2                               ; codeCnt
    ldr x19, [sp, EXCEPTION_TRIAGE_FPTR]
    ;brk 0
    blr x19

    ; exception_triage normally doesn't return, need to patch it

    ; if it does return, don't overwrite retval and panic
    mov x1, 0x4141
    mov x2, 0x4242
    mov x3, 0x4343
    brk 0

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret

; this function figures out if the user wants to intercept system calls
; from a given pid
;
; arguments:
;   X0 = pid table pointer
;   W1 = pid
;
; returns: 1 if user wants to intercept, 0 otherwise
_pid_in_table:
    ; empty pid table?
    ldr w9, [x0, PID_TABLE_NUM_PIDS_OFF]
    cmp w9, 0
    b.eq not_found 

    mov w10, 1
    add x11, x0, w10, lsl 2

search:
    ldr w12, [x11]
    cmp w12, w1
    b.eq found
    add w10, w10, 1
    ;cmp w10, w9
    cmp w10, MAX_SIMULTANEOUS_PIDS
    b.gt not_found
    add x11, x0, w10, lsl 2
    b search

not_found:
    mov x0, 0
    ret

found:
    mov x0, 1
    ret


;dump_saved_state:
    ;ldr x18, [sp, SAVED_STATE_PTR]
    ;add x18, x18, 8
    ;ldp x0, x1, [x18]
    ;ldp x2, x3, [x18, 0x10]
    ;ldp x4, x5, [x18, 0x20]
    ;ldp x6, x7, [x18, 0x30]
    ;ldp x8, x9, [x18, 0x40]
    ;ldp x10, x11, [x18, 0x50]
    ;ldp x12, x13, [x18, 0x60]
    ;ldp x14, x15, [x18, 0x70]
    ;ldp x16, x17, [x18, 0x80]
    ;ldr x19, [x18, 0x98]
    ;ldp x20, x21, [x18, 0xa0]
    ;ldp x22, x23, [x18, 0xb0]
    ;ldp x24, x25, [x18, 0xc0]
    ;ldp x26, x27, [x18, 0xd0]
    ;ldp x28, x29, [x18, 0xe0]
    ;ldr x30, [x18, 0xf0]
    ;ldr x18, [x18, 0x100]       ; pc
    ;brk 0
