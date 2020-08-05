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
    ldr x23, [x22, STALKER_TABLE_CACHEOFF]
    str x23, [sp, STALKER_TABLE_PTR]
    ldr x23, [x22, IOLOG_FPTR_CACHEOFF]
    str x23, [sp, IOLOG_FPTR]
    ldr x23, [x22, IOMALLOC_FPTR_CACHEOFF]
    str x23, [sp, IOMALLOC_FPTR]
    ldr x23, [x22, KALLOC_CANBLOCK_FPTR_CACHEOFF]
    str x23, [sp, KALLOC_CANBLOCK_FPTR]
    ldr x23, [x22, KFREE_ADDR_FPTR_CACHEOFF]
    str x23, [sp, KFREE_ADDR_FPTR]

    ; first, let's see if the user wants to check if this syscall was
    ; patched correctly
    ldr w22, [x20, FLAVOR_ARG]
    cmp w22, PID_MANAGE
    b.eq check_if_patched
    cmp w22, SYSCALL_MANAGE
    b.eq syscall_manage
    b out_einval

check_if_patched:
    ldr w22, [x20, PID_ARG]
    cmp w22, -1
    b.eq out_patched

    ; user doesn't want to see if this syscall was patched correctly. fall thru

pid_manage:
    ; if less than -1, pid doesn't make sense
    b.lt out_einval
    ; for this flavor, arg2 controls whether we're intercepting or not
    ; intercepting system calls for this pid
    ldr w23, [x20, ARG2]
    cbnz add_pid
    b delete_pid

add_pid:
    ; figure out if the user is already intercepting system calls for this pid
    ldr x0, [sp, STALKER_TABLE_PTR]
    mov w1, w22
    bl _stalker_ctl_from_table
    ; if already added, do nothing
    cmp x0, 0
    b.ne success
    ; otherwise, create a new stalker_ctl entry in the stalker table
    ldr x0, [sp, STALKER_TABLE_PTR]
    bl _get_nearest_free_stalker_ctl
    ; table at capacity?
    cmp x0, 0
    b.eq out_einval
    ; at this point, we have a free stalker_ctl entry
    ; it's no longer free
    str wzr, [x0, STALKER_CTL_FREE_OFF]
    ; it belongs to the pid argument
    ldr w22, [x20, PID_ARG]
    str w22, [x0, STALKER_CTL_PID_OFF]

    ; call_list is freed/NULL'ed out upon deletion, no need to do anything
    ; with it until the user adds a system call to intercept

    b success

delete_pid:


    b success

syscall_manage:



out_einval:
    mov w0, -1
    str w0, [x21]
    mov w0, 22
    b done

out_patched:
    mov w0, 999
    str w0, [x21]
    mov w0, 0
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
    b.gt not_found0
    add x11, x0, w10, lsl 4
    b search0

not_found0:
    mov x0, 0
    ret

found0:
    mov x0, x11
    ret

; this function returns a pointer to the free slot nearest to the address of
; the stalker table
;
; arguments
;  X0, stalker table pointer
;
; returns: pointer to nearest free slot, or NULL if there's no free slots
_get_nearest_free_stalker_ctl:
    ; full stalker table?
    ldr w9, [x0, STALKER_TABLE_NUM_PIDS_OFF]
    cmp w9, STALKER_TABLE_MAX
    b.ge nofree

    mov w9, 1
    add x10, x0, w9, lsl 4

freeloop:
    ldr w11, [x10, STALKER_CTL_FREE_OFF]
    cmp w11, FREE
    b.eq foundfree
    add w9, w9, 1
    add x10, x0, w9, lsl 4
    b freeloop

foundfree:
    mov x0, x10
    ret

nofree:
    mov x0, 0
    ret
