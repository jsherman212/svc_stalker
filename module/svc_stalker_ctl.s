    .globl _main
    .align 4

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

    adr x22, CACHE_START
    ldr x23, [x22, STALKER_TABLE_CACHEOFF]
    str x23, [sp, STALKER_TABLE_PTR]
    ldr x23, [x22, KALLOC_CANBLOCK_FPTR_CACHEOFF]
    str x23, [sp, KALLOC_CANBLOCK_FPTR]
    ldr x23, [x22, KFREE_ADDR_FPTR_CACHEOFF]
    str x23, [sp, KFREE_ADDR_FPTR]

    ldr w22, [x20, FLAVOR_ARG]
    cmp w22, PID_MANAGE
    ; first, let's see if the user wants to check if this syscall was
    ; patched correctly
    b.eq check_if_patched
    cmp w22, SYSCALL_MANAGE
    b.eq syscall_manage
    cmp w22, 2
    b.eq out_givetablekaddr
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
    cbnz w23, add_pid
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

    ; increment stalker table size
    ldr x22, [sp, STALKER_TABLE_PTR]
    ldr w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]
    add w23, w23, 1
    str w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]

    b success

delete_pid:
    ; get stalker_ctl pointer for this pid
    ldr x0, [sp, STALKER_TABLE_PTR]
    mov w1, w22
    bl _stalker_ctl_from_table
    ; can't delete something that doesn't exist
    cmp x0, 0
    b.eq out_einval
    ; at this point we have the stalker_ctl entry that belongs to pid
    ; it's now free
    mov w22, 1
    str w22, [x0, STALKER_CTL_FREE_OFF]
    ; it belongs to no pids
    str wzr, [x0, STALKER_CTL_PID_OFF]

    ; decrement stalker table size
    ldr x22, [sp, STALKER_TABLE_PTR]
    ldr w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]
    sub w23, w23, 1
    str w23, [x22, STALKER_TABLE_NUM_PIDS_OFF]

    ; free call_list if it isn't NULL
    ldr x22, [x0, STALKER_CTL_CALL_LIST_OFF]
    cmp x22, 0
    b.eq success

    mov x23, x0
    mov x0, x22
    ldr x22, [sp, KFREE_ADDR_FPTR]
    blr x22
    str xzr, [x23, STALKER_CTL_CALL_LIST_OFF]

    b success

syscall_manage:
    ; get stalker_ctl pointer for this pid
    ldr x0, [sp, STALKER_TABLE_PTR]
    ldr w1, [x20, PID_ARG]
    bl _stalker_ctl_from_table
    ; pid hasn't been added to stalker list?
    cmp x0, 0
    b.eq out_einval
    ; at this point we have the stalker_ctl entry that belongs to pid
    str x0, [sp, CUR_STALKER_CTL]
    ldr w22, [x20, ARG3]
    cbz w22, delete_syscall

    ; if non-NULL, the call list for this pid already exists
    ldr x22, [x0, STALKER_CTL_CALL_LIST_OFF]
    cbnz x22, add_syscall

    ; this stalker_ctl's call list is NULL, kalloc a new one
    mov x0, CALL_LIST_MAX
    mov w1, 8
    mul x0, x0, x1                          ; CALL_LIST_MAX*sizeof(int64_t)
    str x0, [sp, CALL_LIST_KALLOC_SZ]
    ; kalloc_canblock expects a pointer for size
    add x0, sp, CALL_LIST_KALLOC_SZ
    ; don't want to block
    mov w1, wzr
    ; no allocation site
    mov x2, xzr
    ldr x22, [sp, KALLOC_CANBLOCK_FPTR]
    blr x22
    cmp x0, 0
    b.eq out_enomem

    ldr x22, [sp, CUR_STALKER_CTL]
    str x0, [x22, STALKER_CTL_CALL_LIST_OFF]

    mov w23, 0
    mov x24, x0
    mov x25, CALL_LIST_FREE_SLOT

    ; this new call list has all its elems free
call_list_init_loop:
    str x25, [x24]
    add w23, w23, 1
    cmp w23, CALL_LIST_MAX 
    b.ge add_syscall
    add x24, x0, w23, lsl 3
    b call_list_init_loop

add_syscall:
    ; TODO check if this system call is already present and do nothing if it is
    ldr x22, [sp, CUR_STALKER_CTL]
    ldr x0, [x22, STALKER_CTL_CALL_LIST_OFF]
    bl _get_call_list_free_slot
    ; no free slots in call list?
    cmp x0, 0
    b.eq out_einval
    ; X0 = pointer to free slot in call list

    ; user may pass an uncasted literal system call number as ARG2, which
    ; clang will interpret as a 32 bit int, so sign extend it to 64 bits here
    ; needed for negative Mach trap numbers
    ldrsw x22, [x20, ARG2]
    ; X22 = system call user wants to intercept
    str x22, [x0]

    b success

delete_syscall:
    ldr x22, [sp, CUR_STALKER_CTL]
    ldr x0, [x22, STALKER_CTL_CALL_LIST_OFF]
    ldrsw x1, [x20, ARG2]
    bl _find_call_list_slot
    ; this system call was never added?
    cmp x0, 0
    b.eq out_einval
    ; X0 = pointer to slot in call list which this system call occupies
    ; this slot is now free
    mov x22, CALL_LIST_FREE_SLOT
    str x22, [x0]

    b success

out_einval:
    mov w0, -1
    str w0, [x21]
    mov w0, 22
    b done

out_enomem:
    mov w0, -1
    str w0, [x21]
    mov w0, 12
    b done

out_patched:
    mov w0, 999
    str w0, [x21]
    mov w0, 0
    b done

out_givetablekaddr:
    ldr x0, [sp, STALKER_TABLE_PTR]
    str x0, [x21]
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
    b.ge nofree0

    mov w9, 1
    add x10, x0, w9, lsl 4

freeloop0:
    ldr w11, [x10, STALKER_CTL_FREE_OFF]
    cmp w11, 1
    b.eq foundfree0
    add w9, w9, 1
    cmp w9, STALKER_TABLE_MAX
    b.ge nofree0
    add x10, x0, w9, lsl 4
    b freeloop0

foundfree0:
    mov x0, x10
    ret

nofree0:
    mov x0, 0
    ret

; this function returns a pointer to the free slot nearest to the address
; of a stalker_ctl's call table
;
; arguments
;   X0 = call list pointer
;
; returns: a pointer if a free slot is found, NULL otherwise
_get_call_list_free_slot:
    mov w9, 0
    mov x10, x0

freeloop1:
    ldr x11, [x10]
    cmp x11, CALL_LIST_FREE_SLOT
    b.eq foundfree1
    add w9, w9, 1
    cmp w9, CALL_LIST_MAX
    b.ge nofree1
    add x10, x0, w9, lsl 3
    b freeloop1

foundfree1:
    mov x0, x10
    ret

nofree1:
    mov x0, 0
    ret

; this functions returns a pointer to the slot occupied by a system call
; number in a stalker_ctl's call table
;
; arguments
;   X0 = call list pointer
;   X1 = system call number
;
; returns: pointer if system call number is found, NULL otherwise
_find_call_list_slot:
    mov w9, 0
    mov x10, x0

slotloop:
    ldr x11, [x10]
    cmp x11, x1
    b.eq found
    add w9, w9, 1
    cmp w9, CALL_LIST_MAX
    b.ge notfound
    add x10, x0, w9, lsl 3
    b slotloop

found:
    mov x0, x10
    ret

notfound:
    mov x0, 0
    ret
