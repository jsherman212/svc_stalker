    .globl _main
    .align 4

#include "stalker_cache.h"
#include "stalker_table.h"
#include "svc_stalker_ctl.h"

; This is the system call we replaced the first enosys sysent entry
; with. It manages the list of PIDs we're intercepting syscalls/Mach traps for.
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

    adr x22, STALKER_CACHE_PTR_PTR
    ; XXX from now on, X28 == stalker cache pointer, do not modify X28
    ldr x28, [x22]

take_stalker_lock:
    ldr x0, [x28, STALKER_LOCK]
    cbz x0, done
    ldr x22, [x28, LCK_RW_LOCK_SHARED]
    blr x22
    ; TAKE_STALKER_LOCK x28 x22

    ldr w22, [x20, FLAVOR_ARG]
    cmp w22, PID_MANAGE
    ; first, let's see if the user wants to check if this syscall was
    ; patched correctly
    b.eq check_if_patched
    cmp w22, CALL_LIST_MANAGE
    b.eq call_manage
    ; if you're interested in checking out the stalker table in userland,
    ; uncomment this stuff and out_givetablekaddr
    ;cmp w22, 0x2
    ;b.eq out_givetablekaddr
    b out_einval

check_if_patched:
    ldr w22, [x20, PID_ARG]
    cmp w22, -1
    b.eq out_patched
    ; user doesn't want to see if this syscall was patched correctly
    ; if less than -1, pid doesn't make sense
    b.lt out_einval
    ; for this flavor, arg2 controls whether we're intercepting or not
    ; intercepting system calls for this pid
    ldr w23, [x20, ARG2]
    cbnz w23, add_pid
    b delete_pid

add_pid:
    ; figure out if the user is already intercepting system calls for this pid
    ldr x0, [x28, STALKER_TABLE_PTR]
    mov w1, w22
    ldr x22, [x28, STALKER_CTL_FROM_TABLE]
    blr x22
    ; if already added, do nothing
    cbnz x0, success
    ; otherwise, create a new stalker_ctl entry in the stalker table
    ldr x0, [x28, STALKER_TABLE_PTR]
    ldr x22, [x28, GET_NEXT_FREE_STALKER_CTL]
    blr x22
    ; table at capacity?
    cbz x0, out_einval
    ; at this point, we have a free stalker_ctl entry
    ; it's no longer free
    str wzr, [x0, STALKER_CTL_FREE_OFF]
    ; it belongs to the pid argument
    ldr w22, [x20, PID_ARG]
    str w22, [x0, STALKER_CTL_PID_OFF]

    ; call_list is freed/NULL'ed out upon deletion, no need to do anything
    ; with it until the user adds a system call to intercept

    ; increment stalker table size
    ldr x22, [x28, STALKER_TABLE_PTR]
    ldr w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]
    add w23, w23, 0x1
    str w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]

    b success

delete_pid:
    ; get stalker_ctl pointer for this pid
    ldr x0, [x28, STALKER_TABLE_PTR]
    mov w1, w22
    ldr x22, [x28, STALKER_CTL_FROM_TABLE]
    blr x22
    ; can't delete something that doesn't exist
    cbz x0, out_einval
    ; at this point we have the stalker_ctl entry that belongs to pid
    ; it's now free
    mov w22, 0x1
    str w22, [x0, STALKER_CTL_FREE_OFF]
    ; it belongs to no one
    str wzr, [x0, STALKER_CTL_PID_OFF]

    ; decrement stalker table size
    ldr x22, [x28, STALKER_TABLE_PTR]
    ldr w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]
    sub w23, w23, 0x1
    str w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]

    ; free call_list if it isn't NULL
    ldr x22, [x0, STALKER_CTL_CALL_LIST_OFF]
    cbz x22, success

    mov x24, x0
    mov w23, 0x1
    ; sub x23, x22, x23, lsl CALL_LIST_DISPLACEMENT_SHIFT
    sub x0, x22, x23, lsl CALL_LIST_DISPLACEMENT_SHIFT
    ; mov x23, x0
    ; mov x0, x22
    ldr x22, [x28, KFREE_ADDR]
    blr x22
    str xzr, [x24, STALKER_CTL_CALL_LIST_OFF]

    b success

call_manage:
    ; get stalker_ctl pointer for this pid
    ldr x0, [x28, STALKER_TABLE_PTR]
    ldr w1, [x20, PID_ARG]
    ldr x22, [x28, STALKER_CTL_FROM_TABLE]
    blr x22
    ; pid hasn't been added to stalker list?
    cbz x0, out_einval
    ; at this point we have the stalker_ctl entry that belongs to pid
    str x0, [sp, CUR_STALKER_CTL]
    ldr w22, [x20, ARG3]
    cbz w22, delete_call

    ; if non-NULL, the call list for this pid already exists
    ; ldr x0, [x0, STALKER_CTL_CALL_LIST_OFF]
    ldr x22, [x0, STALKER_CTL_CALL_LIST_OFF]
    ; in case we end up branching to add_call label
    ;mov x0, x22
    ; ldr x0, [sp, CUR_STALKER_CTL]
    ; X0 still contains a pointer to the current stalker ctl struct
    cbnz x22, add_call

    ; this stalker_ctl's call list is NULL, kalloc a new one

    ; one page
    mov x0, 0x1
    add x0, xzr, x0, lsl 0xe
    str x0, [sp, CALL_LIST_KALLOC_SZ]
    ; kalloc_canblock expects a pointer for size
    add x0, sp, CALL_LIST_KALLOC_SZ
    ; don't want to block
    mov w1, wzr
    ; no allocation site
    mov x2, xzr
    ldr x22, [x28, KALLOC_CANBLOCK]
    blr x22
    cbz x0, out_enomem

    mov x22, x0
    mov w23, 0x1
    add x23, x0, x23, lsl 0xe

    ; mov x18, 0x4141
    ; brk 0

    ; zero out this memory
zero_loop:
    stp xzr, xzr, [x22], 0x10
    subs x24, x23, x22
    cbnz x24, zero_loop

    ldr x22, [sp, CUR_STALKER_CTL]
    ; X0 still contains base pointer to kalloc'ed call list page
    ; see stalker_table.h
    mov w23, 0x1
    add x0, x0, x23, lsl CALL_LIST_DISPLACEMENT_SHIFT
    str x0, [x22, STALKER_CTL_CALL_LIST_OFF]
    ; brk 0

    mov x0, x22

add_call:
    ; X0 already contains pointer to current stalker_ctl struct
    ldr w1, [x20, ARG2]
    ldr x22, [x28, GET_FLAG_PTR_FOR_CALL_NUM]
    blr x22
    ; bad call number?
    cbz x0, out_einval

    ; we are now intercepting for this call number
    mov w22, 0x1
    strb w22, [x0]

    b success

delete_call:
    ldr x0, [sp, CUR_STALKER_CTL]
    ldr w1, [x20, ARG2]
    ldr x22, [x28, GET_FLAG_PTR_FOR_CALL_NUM]
    blr x22
    ; bad call number?
    cbz x0, out_einval

    ; no longer intercepting for this call number
    strb wzr, [x0]

    b success

out_einval:
    mov w0, 0xffffffff
    str w0, [x21]
    mov w0, 0x16
    b release_stalker_lock

out_enomem:
    mov w0, 0xffffffff
    str w0, [x21]
    mov w0, 0xc
    b release_stalker_lock

out_patched:
    mov w0, 0x3e7
    str w0, [x21]
    mov w0, wzr
    b release_stalker_lock

; out_givetablekaddr:
;     ldr x0, [x28, STALKER_TABLE]
;     str x0, [x21]
;     mov w0, wzr
;     b release_stalker_lock

success:
    mov w0, wzr
    str w0, [x21]

release_stalker_lock:
    ; back up return value
    mov x22, x0
    ldr x0, [x28, STALKER_LOCK]
    ldr x23, [x28, LCK_RW_DONE]
    blr x23
    mov x0, x22

done:
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret
