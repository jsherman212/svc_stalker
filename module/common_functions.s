    .globl _main
    .align 4

#include "stalker_table.h"

; TODO after final version of these fxns, only save used callee-saved regs

; Common functions shared across handle_svc_hook, svc_stalker_ctl,
; and hook_system_check_sysctlbyname_hook, to save space.
;
; In order to know when a function from here starts, I'll put udf 0xffff right
; before it. This is needed so hookgen.pl sees it and writes it to a
; "function starts" array in common_instrs.h. In svc_stalker.c, I'll use that
; function starts array to calculate the virtual address of each of these
; functions to store in the stalker cache. Thus, the order of these functions
; in this file cannot change, if a new one is to be added, I need to put
; it at the end.
;
; Finally, these functions don't use temp registers x9 to x15 because I can't
; know if kernel code relies on these regs not being modified after we return
; from handle_svc_hook or hook_system_check_sysctlbyname_hook.

.macro INDICATE_FUNCTION_START
    udf 0xffff
.endmacro

; this function figures out if a pid is in the stalker table, and returns
; a pointer to its corresponding stalker_ctl struct if it is there
;
; arguments:
;   X0 = stalker table pointer
;   W1 = pid
;
; returns: pointer if pid is in stalker table, NULL otherwise
INDICATE_FUNCTION_START
_stalker_ctl_from_table:
    sub sp, sp, 0x70
    stp x28, x27, [sp, 0x10]
    stp x26, x25, [sp, 0x20]
    stp x24, x23, [sp, 0x30]
    stp x22, x21, [sp, 0x40]
    stp x20, x19, [sp, 0x50]
    stp x29, x30, [sp, 0x60]
    add x29, sp, 0x60

    ; empty stalker table?
    ldr w19, [x0, STALKER_TABLE_NUM_PIDS_OFF]
    cbz w19, no_stalker_ctl

    ; search the whole table because I don't bother with moving
    ; back stalker_ctl structs when one is freed to make sure
    ; they're all adjacent. TODO
    ; first, get past the first 16 bytes, which won't ever hold a stalker_ctl
    add x19, x0, 0x10

    ; put cursor on PID field
    add x19, x19, STALKER_CTL_PID_OFF
    mov w20, STALKER_TABLE_MAX
    add x20, x19, w20, lsl 4

find_stalker_ctl:
    ldr w21, [x19], SIZEOF_STRUCT_STALKER_CTL
    cmp w21, w1
    b.eq found_stalker_ctl
    subs x21, x20, x19
    cbnz x21, find_stalker_ctl

no_stalker_ctl:
    mov x0, xzr
    b stalker_ctl_from_table_done 

found_stalker_ctl:
    ; postindex ldr varient incremented X19 by SIZEOF_STRUCT_STALKER_CTL
    sub x19, x19, SIZEOF_STRUCT_STALKER_CTL
    ; get off of PID field
    sub x0, x19, STALKER_CTL_PID_OFF
    ; fall thru

stalker_ctl_from_table_done:
    ldp x29, x30, [sp, 0x60]
    ldp x20, x19, [sp, 0x50]
    ldp x22, x21, [sp, 0x40]
    ldp x24, x23, [sp, 0x30]
    ldp x26, x25, [sp, 0x20]
    ldp x28, x27, [sp, 0x10]
    add sp, sp, 0x70
    ret

; this function figures out if exception_triage should be called given
; a call number
;
; parameters:
;   X0 = stalker_ctl struct pointer
;   X1 = call number
;
; returns: 1 if call number is present inside the stalker_ctl's call list,
;   0 otherwise
INDICATE_FUNCTION_START
_should_intercept_call:
    sub sp, sp, 0x70
    stp x28, x27, [sp, 0x10]
    stp x26, x25, [sp, 0x20]
    stp x24, x23, [sp, 0x30]
    stp x22, x21, [sp, 0x40]
    stp x20, x19, [sp, 0x50]
    stp x29, x30, [sp, 0x60]
    add x29, sp, 0x60

    ; empty system call list for this stalker_ctl struct pointer?
    ldr x19, [x0, STALKER_CTL_CALL_LIST_OFF]
    cbz x19, do_not_intercept

    ; x19 == pointer to call list (int64_t array)
    mov w20, CALL_LIST_MAX
    add x20, x19, w20, lsl 3

do_we_intercept:
    ldr x21, [x19], 0x8
    cmp x21, x1
    b.eq intercept 
    subs x22, x20, x19
    cbnz x22, do_we_intercept

do_not_intercept:
    mov w0, wzr
    b should_intercept_call_done

intercept:
    mov w0, 1
    ; fall thru

should_intercept_call_done:
    ldp x29, x30, [sp, 0x60]
    ldp x20, x19, [sp, 0x50]
    ldp x22, x21, [sp, 0x40]
    ldp x24, x23, [sp, 0x30]
    ldp x26, x25, [sp, 0x20]
    ldp x28, x27, [sp, 0x10]
    add sp, sp, 0x70
    ret

; this function returns a pointer to the next free stalker_ctl struct
;
; arguments
;  X0, stalker table pointer
;
; returns: pointer to next free stalker_ctl struct, or NULL if stalker table
; is full
INDICATE_FUNCTION_START
_get_next_free_stalker_ctl:
    sub sp, sp, 0x70
    stp x28, x27, [sp, 0x10]
    stp x26, x25, [sp, 0x20]
    stp x24, x23, [sp, 0x30]
    stp x22, x21, [sp, 0x40]
    stp x20, x19, [sp, 0x50]
    stp x29, x30, [sp, 0x60]
    add x29, sp, 0x60

    ldr w19, [x0, STALKER_TABLE_NUM_PIDS_OFF]
    cmp w19, STALKER_TABLE_MAX
    b.ge full_table

    ; first, get past the first 16 bytes, which won't ever hold a stalker_ctl
    add x19, x0, 0x10

    mov w20, STALKER_TABLE_MAX
    add x20, x19, w20, lsl 4

find_free_stalker_ctl:
    ; STALKER_CTL_FREE_OFF == 0
    ldr w21, [x19], SIZEOF_STRUCT_STALKER_CTL
    cbnz w21, found_free_stalker_ctl
    subs x21, x20, x19
    cbnz x21, find_free_stalker_ctl

full_table:
    mov x0, xzr
    b get_nearest_free_stalker_ctl_done

found_free_stalker_ctl:
    ; postindex ldr varient incremented X19 by SIZEOF_STRUCT_STALKER_CTL
    sub x0, x19, SIZEOF_STRUCT_STALKER_CTL
    ; fall thru

get_nearest_free_stalker_ctl_done:
    ldp x29, x30, [sp, 0x60]
    ldp x20, x19, [sp, 0x50]
    ldp x22, x21, [sp, 0x40]
    ldp x24, x23, [sp, 0x30]
    ldp x26, x25, [sp, 0x20]
    ldp x28, x27, [sp, 0x10]
    add sp, sp, 0x70
    ret

; this function returns a pointer to the first free slot found in a stalker_ctl's
; call list
;
; arguments
;   X0 = call list pointer
;
; returns: a pointer if a free slot is found, NULL otherwise
INDICATE_FUNCTION_START
_get_call_list_free_slot:
    sub sp, sp, 0x70
    stp x28, x27, [sp, 0x10]
    stp x26, x25, [sp, 0x20]
    stp x24, x23, [sp, 0x30]
    stp x22, x21, [sp, 0x40]
    stp x20, x19, [sp, 0x50]
    stp x29, x30, [sp, 0x60]
    add x29, sp, 0x60

    mov x19, x0
    mov w20, CALL_LIST_MAX
    add x20, x19, w20, lsl 3

find_free_call_list_slot:
    ldr x21, [x19], 0x8
    cmp x21, CALL_LIST_FREE_SLOT
    b.eq found_free_call_list_slot
    subs x21, x20, x19
    cbnz x21, find_free_call_list_slot

full_call_list:
    mov x0, xzr
    b get_call_list_free_slot_done

found_free_call_list_slot:
    ; postindex ldr varient incremented X19 by sizeof(int64_t)
    sub x0, x19, 0x8 
    ; fall thru

get_call_list_free_slot_done:
    ldp x29, x30, [sp, 0x60]
    ldp x20, x19, [sp, 0x50]
    ldp x22, x21, [sp, 0x40]
    ldp x24, x23, [sp, 0x30]
    ldp x26, x25, [sp, 0x20]
    ldp x28, x27, [sp, 0x10]
    add sp, sp, 0x70
    ret

; this function returns a pointer to the slot occupied by a call
; number in a stalker_ctl's call table
;
; arguments
;   X0 = call list pointer
;   X1 = call number
;
; returns: pointer if system call number is found, NULL otherwise
INDICATE_FUNCTION_START
_get_call_list_slot:
    sub sp, sp, 0x70
    stp x28, x27, [sp, 0x10]
    stp x26, x25, [sp, 0x20]
    stp x24, x23, [sp, 0x30]
    stp x22, x21, [sp, 0x40]
    stp x20, x19, [sp, 0x50]
    stp x29, x30, [sp, 0x60]
    add x29, sp, 0x60

    mov x19, x0
    mov w20, CALL_LIST_MAX
    add x20, x19, w20, lsl 3

find_call_list_slot:
    ldr x21, [x19], 0x8
    cmp x21, x1
    b.eq found_call_list_slot
    subs x21, x20, x19
    cbnz x21, find_call_list_slot

not_present_in_call_list:
    mov x0, xzr
    b get_call_list_slot_done

found_call_list_slot:
    ; postindex ldr varient incremented X19 by sizeof(int64_t)
    sub x0, x19, 0x8 
    ; fall thru

get_call_list_slot_done:
    ldp x29, x30, [sp, 0x60]
    ldp x20, x19, [sp, 0x50]
    ldp x22, x21, [sp, 0x40]
    ldp x24, x23, [sp, 0x30]
    ldp x26, x25, [sp, 0x20]
    ldp x28, x27, [sp, 0x10]
    add sp, sp, 0x70
    ret

    ; so clang doesn't complain when linking
_main:
    ret
