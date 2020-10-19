    .globl _main
    .align 4

#include "common_functions.h"
#include "stalker_cache.h"
#include "stalker_table.h"

; Common functions shared across all parts of this project.
;
; In order to know when a function starts, I'll put udf 0xffff right
; before it. When hookgen.pl sees it, it'll write its file offset to a
; "function starts" array in common_instrs.h. In svc_stalker.c, I'll use that
; function starts array to calculate the virtual address of each of these
; functions to store in the stalker cache. The order of these functions
; in this file cannot change. If a new one is to be added, I need to put
; it at the end.

.macro INDICATE_FUNCTION_START
    udf 0xffff
.endmacro

; XXX this needs to be the first function in this file!!!
INDICATE_FUNCTION_START
_common_fxns_get_stalker_cache:
    adr x0, STALKER_CACHE_PTR_PTR
    ldr x0, [x0]
    ret

; this function figures out if a pid is in the stalker table, and returns
; a pointer to its corresponding stalker_ctl struct if it is there
;
; arguments:
;   X0 = stalker table pointer
;   W1 = pid
;
; Locks taken: stalker lock
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

    mov x19, x0
    mov w20, w1

    bl _common_fxns_get_stalker_cache
    mov x28, x0

    TAKE_STALKER_LOCK_CHK x28, x21, no_stalker_ctl

    ; empty stalker table?
    ldr w21, [x19, STALKER_TABLE_NUM_PIDS_OFF]
    cbz w21, no_stalker_ctl_release

    ; search the whole table because I don't bother with moving
    ; back stalker_ctl structs when one is freed to make sure
    ; they're all adjacent. TODO
    ; first, get past the first 16 bytes, which won't ever hold a stalker_ctl
    add x21, x19, 0x10

    ; put cursor on PID field
    add x21, x21, STALKER_CTL_PID_OFF
    mov w22, STALKER_TABLE_MAX
    ; end
    add x22, x21, w22, lsl 0x4

find_stalker_ctl:
    ldr w23, [x21], SIZEOF_STRUCT_STALKER_CTL
    cmp w23, w20
    b.eq found_stalker_ctl
    subs x23, x22, x21
    cbnz x23, find_stalker_ctl
    ; fall thru if nothing was found

no_stalker_ctl_release:
    RELEASE_STALKER_LOCK x28, x19
    ; fall thru

no_stalker_ctl:
    mov x0, xzr
    b stalker_ctl_from_table_done 

found_stalker_ctl:
    RELEASE_STALKER_LOCK x28, x19
    ; postindex ldr variant incremented x21 by SIZEOF_STRUCT_STALKER_CTL
    sub x21, x21, SIZEOF_STRUCT_STALKER_CTL
    ; get off of PID field
    sub x0, x21, STALKER_CTL_PID_OFF
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
;   W0 = SIGNED call number
;
; Locks taken: stalker lock (for call list read)
;
; returns: boolean
INDICATE_FUNCTION_START
_should_intercept_call:
    sub sp, sp, 0x30
    stp x22, x21, [sp]
    stp x20, x19, [sp, 0x10]
    stp x29, x30, [sp, 0x20]
    add x29, sp, 0x20

    mov w19, w0
    bl _common_fxns_get_stalker_cache
    mov x20, x0

    ldr x21, [x20, CURRENT_PROC]
    blr x21
    ldr x21, [x20, PROC_PID]
    blr x21
    mov w1, w0
    ldr x0, [x20, STALKER_TABLE_PTR]
    bl _stalker_ctl_from_table
    ; no stalker_ctl struct for this process?
    cbz x0, should_intercept_call_done

    mov x22, x0

    TAKE_STALKER_LOCK_CHK x20, x21, no_call_list

    ldr x0, [x22, STALKER_CTL_CALL_LIST_OFF]
    ; no call list for this stalker_ctl struct?
    cbz x0, no_call_list_release

    RELEASE_STALKER_LOCK x20, x21

    mov x0, x22
    mov w1, w19
    bl _get_flag_ptr_for_call_num
    cbz x0, should_intercept_call_done
    ldrb w0, [x0]

    b should_intercept_call_done

no_call_list_release:
    RELEASE_STALKER_LOCK x20, x19
    ; fall thru

no_call_list:
    mov x0, xzr
    ; fall thru

should_intercept_call_done:
    ldp x29, x30, [sp, 0x20]
    ldp x20, x19, [sp, 0x10]
    ldp x22, x21, [sp]
    add sp, sp, 0x30
    ret

; this function returns a pointer to the next free stalker_ctl struct
;
; arguments
;  X0, stalker table pointer
;
; Locks taken: stalker lock
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

    mov x19, x0

    bl _common_fxns_get_stalker_cache
    mov x22, x0

    TAKE_STALKER_LOCK_CHK x22, x20, full_table

    ldr w20, [x19, STALKER_TABLE_NUM_PIDS_OFF]
    cmp w20, STALKER_TABLE_MAX
    b.ge full_table_release
    
    ; first, get past the first 16 bytes, which won't ever hold a stalker_ctl
    add x19, x19, 0x10

    mov w20, STALKER_TABLE_MAX
    add x20, x19, w20, lsl 0x4

find_free_stalker_ctl:
    ; STALKER_CTL_FREE_OFF == 0
    ldr w21, [x19], SIZEOF_STRUCT_STALKER_CTL
    cbnz w21, found_free_stalker_ctl
    subs x21, x20, x19
    cbnz x21, find_free_stalker_ctl

full_table_release:
    RELEASE_STALKER_LOCK x22, x20
    ; fall thru
    
full_table:
    mov x0, xzr
    b get_nearest_free_stalker_ctl_done

found_free_stalker_ctl:
    RELEASE_STALKER_LOCK x22, x20
    ; postindex ldr variant incremented X19 by SIZEOF_STRUCT_STALKER_CTL
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

; this function figures out if the svc_stalker_ctl_callnum sysctl
; has been registered
;
; Arguments: none
;
; Locks taken: sysctl_geometry_lock
;
; Returns: boolean
INDICATE_FUNCTION_START
_is_sysctl_registered:
    sub sp, sp, 0x30
    stp x22, x21, [sp]
    stp x20, x19, [sp, 0x10]
    stp x29, x30, [sp, 0x20]
    add x29, sp, 0x30

    bl _common_fxns_get_stalker_cache
    mov x19, x0

    ; since we set this flag while holding sysctl geometry lock,
    ; we should access it while holding that same lock
    ldr x0, [x19, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    mov x22, x0
    ldr x20, [x19, LCK_RW_LOCK_SHARED]
    blr x20
    ldr x20, [x19, STALKER_TABLE_PTR]
    ldr x21, [x20, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    mov x0, x22
    ldr x20, [x19, LCK_RW_DONE]
    blr x20

    mov x0, x21

    ldp x29, x30, [sp, 0x20]
    ldp x20, x19, [sp, 0x10]
    ldp x22, x21, [sp]
    add sp, sp, 0x30
    ret

; this function calls exception_triage
;
; Arguments
;   X0, exception type
;   W1, pid
;   W2, BEFORE_CALL or CALL_COMPLETED
;
; Locks taken: none
;
; Returns: nothing (exception_triage return value is ignored)
INDICATE_FUNCTION_START
_send_exception_msg:
    sub sp, sp, 0x30
    stp x20, x19, [sp, 0x10]
    stp x29, x30, [sp, 0x20]
    add x29, sp, 0x20

    mov x19, x0

    bl _common_fxns_get_stalker_cache

    stp x1, x2, [sp]                    ; code
    mov x1, sp
    mov w2, 0x2                         ; codeCnt
    ldr x20, [x0, EXCEPTION_TRIAGE]
    mov x0, x19                         ; exception
    blr x20

    ldp x29, x30, [sp, 0x20]
    ldp x20, x19, [sp, 0x10]
    add sp, sp, 0x30
    ret

; This function returns a pointer to the flag for a call number
;
; Arguments
;   X0, pointer to stalker_ctl struct
;   W1, SIGNED call number
;
; Locks taken: stalker lock
;
; Returns: pointer to flag on valid call number, NULL otherwise
INDICATE_FUNCTION_START
_get_flag_ptr_for_call_num:
    sub sp, sp, 0x40
    stp x22, x21, [sp]
    stp x20, x19, [sp, 0x10]
    stp x29, x30, [sp, 0x20]
    add x29, sp, 0x20

    cbz x0, get_flag_ptr_for_call_num_done

    mov x19, x0

    bl _common_fxns_get_stalker_cache
    mov x22, x0

    mov w20, CALL_NUM_MIN
    cmp w1, w20
    b.lt maybe_platform_syscall_call_num
    mov w20, CALL_NUM_MAX
    cmp w1, w20
    b.gt bad_call_num
    b got_flag_index

maybe_platform_syscall_call_num:
    mov w20, 0x1
    add w20, wzr, w20, lsl PLATFORM_SYSCALL_CALL_NUM_SHIFT
    cmp w1, w20
    b.ne bad_call_num
    mov w1, 0x1
    neg w1, w1, lsl CALL_LIST_DISPLACEMENT_SHIFT
    ; fall thru

got_flag_index:
    TAKE_STALKER_LOCK_CHK x22, x20, bad_call_num
    ldr x0, [x19, STALKER_CTL_CALL_LIST_OFF]
    cbz x0, no_call_list_release_0
    mov x19, x0
    mov w20, w1
    RELEASE_STALKER_LOCK x22, x21
    add x0, x19, w20, sxtw
    b get_flag_ptr_for_call_num_done

bad_call_num:
    mov x0, xzr
    b get_flag_ptr_for_call_num_done

no_call_list_release_0:
    RELEASE_STALKER_LOCK x22, x19
    mov x0, xzr
    ; fall thru

get_flag_ptr_for_call_num_done:
    ldp x29, x30, [sp, 0x20]
    ldp x20, x19, [sp, 0x10]
    ldp x22, x21, [sp]
    add sp, sp, 0x40
    ret

    ; so clang doesn't complain when linking
_main:
    ret
