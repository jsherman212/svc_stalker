    .globl _main
    .align 4

#include "svc_stalker_ctl.h"

; This is the system call we replaced the first enosys sysent entry
; with. It manages the list of PIDs we're intercepting syscalls for.
;
; Actual return value of this function gets set to errno later.
; retval, the second parameter, is the return value of this function.
;
; XXX XXX MUST DISABLE ANY PIDS THAT HAVE BEEN ENABLED BEFORE PROCESS EXIT
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

    adr x22, CACHE_START
    ;str x22, [sp, OFFSET_CACHE_PTR]
    ldr x23, [x22, PID_TABLE_CACHEOFF]
    str x23, [sp, PID_TABLE_PTR]
    ldr x23, [x22, IOLOG_FPTR_CACHEOFF]
    str x23, [sp, IOLOG_FPTR]
    ldr x23, [x22, IOMALLOC_FPTR_CACHEOFF]
    str x23, [sp, IOMALLOC_FPTR]

    ldr w22, [x20]
    cmp w22, 0
    b.lt maybebadpid

    ldr x22, [sp, PID_TABLE_PTR]
    ldr w23, [x22, PID_TABLE_NUM_PIDS_OFF]
    cmp w23, MAX_SIMULTANEOUS_PIDS
    b.ge fulltable
    
    ldr w23, [x20, 8]
    cbz w23, remove_pid
    b add_pid

fulltable:
    ; is the user trying to add another PID even though the table is full?
    ldr w22, [x20, 8]
    cbnz w22, out_einval

    ; they're deleting a PID. fall through

remove_pid:
    ldr x0, [sp, PID_TABLE_PTR]
    ldr w1, [x20]
    bl _get_slot_ptr_for_pid
    cmp x0, 0
    ; can't remove something that doesn't exist
    b.eq out_einval
    ; mark this slot as usable
    mov w1, OPEN_SLOT
    ;ldr x9, [sp, IOMALLOC_FPTR]
    ;mov w0, 4
    ;blr x9
    str w1, [x0]
    ;brk 0
    ; decrement table size
    ldr x22, [sp, PID_TABLE_PTR]
    ldr w23, [x22, PID_TABLE_NUM_PIDS_OFF]
    sub w23, w23, 1
    str w23, [x22, PID_TABLE_NUM_PIDS_OFF]

    b success 

add_pid:
    ldr x0, [sp, PID_TABLE_PTR]
    ldr w1, [x20]
    ;ldr w2, [x0]
    ;brk 0
    bl _get_slot_ptr_for_pid
    ; pid already exists in the table? if so, do nothing
    cmp x0, 0
    b.ne success

    ldr x0, [sp, PID_TABLE_PTR]
    bl _get_nearest_empty_slot
    ; we've already checked if the table is full

    ; pid argument now owns this slot
    ldr w22, [x20]
    str w22, [x0]

    ;brk 0
    
    ; increment table size
    ldr x22, [sp, PID_TABLE_PTR]
    ldr w23, [x22, PID_TABLE_NUM_PIDS_OFF]
    add w23, w23, 1
    str w23, [x22, PID_TABLE_NUM_PIDS_OFF]

    ;ldr x0, [sp, PID_TABLE_PTR]
    ;ldr w1, [x0]
    ;ldr w2, [x0, 4]
    ;brk 0

    b success 

maybebadpid:
    ; user may have passed -1 for pid to see if this syscall was patched
    ; successfully
    cmp w22, -1
    b.ne out_einval
    mov w0, 999
    str w0, [x21]
    mov w0, 0
    b done

out_einval:
    mov w0, -1
    str w0, [x21]
    mov w0, 22
    b done

success:
    mov w0, 0
    str w0, [x21]

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret

; this function returns a pointer to the slot a certain PID occupies
; in the PID table
; 
; arguments
;  X0, pid table pointer
;  W1, pid
;
; returns: a pointer if the PID is found, otherwise NULL
_get_slot_ptr_for_pid:
    ldr w12, [x0, PID_TABLE_NUM_PIDS_OFF]
    cmp w12, 0
    b.eq not_found 

    mov w9, 1
    add x10, x0, w9, lsl 2

slotloop:
    ldr w11, [x10]
    cmp w11, w1
    b.eq found
    add w9, w9, 1
    ;cmp w9, w12
    cmp w9, MAX_SIMULTANEOUS_PIDS
    b.gt not_found
    add x10, x0, w9, lsl 2
    b slotloop

not_found:
    mov x0, 0
    ret

found:
    mov x0, x10
    ret

; this function returns a pointer to the slot nearest to the address of
; the pid table
;
; arguments
;  X0, pid table pointer
;
; returns: pointer to nearest empty slot
;
; XXX I've already checked if the table is full before calling this function,
; so save space by not checking again
_get_nearest_empty_slot:
    mov w9, 1
    add x10, x0, w9, lsl 2

emptyslotloop:
    ldr w11, [x10]
    cmp w11, OPEN_SLOT
    b.eq foundempty
    add w9, w9, 1
    add x10, x0, w9, lsl 2
    b emptyslotloop

foundempty:
    mov x0, x10
    ret
