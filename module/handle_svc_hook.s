    .globl _main
    .align 4

#include "handle_svc_hook.h"

; this iterates through the PIDs/call numbers the user has registered through the
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
    ldr x20, [x19, PATCHED_SYSCALL_NUM_CACHEOFF]
    str x20, [sp, PATCHED_SYSCALL_NUM]
    ldr x20, [x19, SYSCTL_NAME_CACHEOFF]
    str x20, [sp, SYSCTL_NAME]
    ldr x20, [x19, SYSCTL_DESCR_CACHEOFF]
    str x20, [sp, SYSCTL_DESCR]
    ldr x20, [x19, SYSCTL_FMT_CACHEOFF]
    str x20, [sp, SYSCTL_FMT]
    ldr x20, [x19, SYSCTL__KERN_CHILDREN_CACHEOFF]
    str x20, [sp, SYSCTL__KERN_CHILDREN_PTR]
    ldr x20, [x19, SYSCTL_REGISTER_OID_FPTR_CACHEOFF]
    str x20, [sp, SYSCTL_REGISTER_OID_FPTR]
    ldr x20, [x19, SYSCTL_HANDLE_LONG_CACHEOFF]
    str x20, [sp, SYSCTL_HANDLE_LONG_FPTR]
    ldr x20, [x19, NAME2OID_FPTR_CACHEOFF]
    str x20, [sp, NAME2OID_FPTR]
    ldr x20, [x19, SYSCTL_GEOMETRY_LOCK_PTR_CACHEOFF]
    str x20, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x20, [x19, LCK_RW_LOCK_SHARED_FPTR_CACHEOFF]
    str x20, [sp, LCK_RW_LOCK_SHARED_FPTR]
    ldr x20, [x19, LCK_RW_DONE_FPTR_CACHEOFF]
    str x20, [sp, LCK_RW_DONE_FPTR]
    ldr x20, [x19, NEW_SYSCTL_MIB_PTR_CACHEOFF]
    str x20, [sp, NEW_SYSCTL_MIB_PTR]
    ldr x20, [x19, NEW_SYSCTL_MIB_COUNT_PTR_CACHEOFF]
    str x20, [sp, NEW_SYSCTL_MIB_COUNT_PTR]

    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [sp, LCK_RW_LOCK_SHARED_FPTR]
    blr x19
    ldr x19, [sp, STALKER_TABLE_PTR]
    ldr x20, [x19, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [sp, LCK_RW_DONE_FPTR]
    blr x19
    ; if we've already registered the sysctl, don't do it again
    cbnz x20, maybeintercept

    ; set up the kern.svc_stalker_ctl_callnum sysctl
    ; oid_parent, _kern
    ldr x19, [sp, SYSCTL__KERN_CHILDREN_PTR]
    str x19, [sp, SYSCTL_OID_STRUCT]
    ; oid_link.sle_next
    str xzr, [sp, SYSCTL_OID_STRUCT+0x8]
    ; oid_number
    mov w19, OID_AUTO
    str w19, [sp, SYSCTL_OID_STRUCT+0x10]
    ; oid_kind, (CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_ANYBODY)
    mov w19, CTLTYPE_INT
    orr w19, w19, CTLFLAG_RD
    orr w19, w19, CTLFLAG_ANYBODY
    str w19, [sp, SYSCTL_OID_STRUCT+0x14]
    ; oid_arg1, pointer to svc_stalker_ctl call number
    ldr x19, [sp, OFFSET_CACHE_PTR]
    add x19, x19, PATCHED_SYSCALL_NUM_CACHEOFF
    str x19, [sp, SYSCTL_OID_STRUCT+0x18]
    ; oid_arg2, nothing
    str wzr, [sp, SYSCTL_OID_STRUCT+0x20]
    ; oid_name, "kern.svc_stalker_ctl_callnum"
    ldr x19, [sp, SYSCTL_NAME]
    ; skip "kern."
    add x19, x19, 5
    str x19, [sp, SYSCTL_OID_STRUCT+0x28]
    ; oid_handler
    ldr x19, [sp, SYSCTL_HANDLE_LONG_FPTR]
    str x19, [sp, SYSCTL_OID_STRUCT+0x30]
    ; oid_fmt
    ldr x19, [sp, SYSCTL_FMT]
    str x19, [sp, SYSCTL_OID_STRUCT+0x38]
    ; oid_descr
    ldr x19, [sp, SYSCTL_DESCR]
    str x19, [sp, SYSCTL_OID_STRUCT+0x40]
    ; oid_version
    mov w19, SYSCTL_OID_VERSION
    str w19, [sp, SYSCTL_OID_STRUCT+0x48]
    ; oid_refcnt
    str wzr, [sp, SYSCTL_OID_STRUCT+0x4c]

    ; register this sysctl
    add x0, sp, SYSCTL_OID_STRUCT
    ldr x19, [sp, SYSCTL_REGISTER_OID_FPTR]
    blr x19

    ; Figure out what MIB array looks like for this new sysctl.
    ; We need this so the hook_system_check_sysctlbyname_hook can check
    ; if the incoming sysctl is ours
    ;
    ; We're taking sysctl_geometry_lock because name2oid doesn't,
    ; and not giving it up until we've written a one to
    ; stalkertable+REGISTERED_SYSCTL_OFF because we're sharing this info
    ; with hook_system_check_sysctlbyname_hook.
    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [sp, LCK_RW_LOCK_SHARED_FPTR]
    blr x19
    ldr x0, [sp, SYSCTL_NAME]
    ldr x1, [sp, NEW_SYSCTL_MIB_PTR]
    ldr x2, [sp, NEW_SYSCTL_MIB_COUNT_PTR]
    ldr x19, [sp, NAME2OID_FPTR]
    blr x19
    ldr x19, [sp, STALKER_TABLE_PTR]
    mov x20, 1
    str x20, [x19, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [sp, LCK_RW_DONE_FPTR]
    blr x19

maybeintercept:
    ; figure out if the system call made by this PID should be
    ; reported back to userland
    ldr x19, [sp, CURRENT_PROC_FPTR]
    blr x19
    ldr x19, [sp, PROC_PID_FPTR]
    blr x19
    ; W0 = proc_pid(current_proc())
    str w0, [sp, CUR_PID]
    mov w1, w0
    ldr x0, [sp, STALKER_TABLE_PTR]
    bl _stalker_ctl_from_table
    ; user doesn't want to intercept any system calls from this pid, bail
    cbz x0, done
    ; does the user want this system call to be intercepted?
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x1, [x19, 0x88]
    ; X0 = pointer to stalker_ctl struct for proc_pid(current_proc())
    bl _should_intercept_syscall
    ; if user does not want this system call intercepted, we're done
    cbz x0, done

    ; TODO re-implement the sanity checks we overwrote

    mov x0, EXC_SYSCALL
    mov x1, EXC_MACH_SYSCALL
    ldr x2, [sp, SAVED_STATE_PTR]
    ldr x2, [x2, 0x88]                      ; X16, system call number
    cmp x2, 0
    csel x0, x1, x0, lt                     ; exception
    str x2, [sp, EXC_CODES]
    ldr w2, [sp, CUR_PID]
    str x2, [sp, EXC_CODES+8]
    add x1, sp, EXC_CODES                   ; code
    mov w2, 2                               ; codeCnt
    ldr x19, [sp, EXCEPTION_TRIAGE_FPTR]
    blr x19

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
