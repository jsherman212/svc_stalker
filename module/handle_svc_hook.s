    .globl _main
    .align 4

#include "handle_svc_hook.h"
#include "stalker_cache.h"
#include "stalker_table.h"

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

    adr x19, STALKER_CACHE_PTR_PTR
    ; XXX from now on, X28 == stalker cache pointer, do not modify X28
    ldr x28, [x19]

    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_LOCK_SHARED]
    blr x19
    ldr x19, [x28, STALKER_TABLE_PTR]
    ldr x20, [x19, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19
    ; if we've already registered the sysctl, don't do it again
    cbnz x20, maybeintercept

    ; set up the kern.svc_stalker_ctl_callnum sysctl
    ; oid_parent, _kern
    ldr x19, [x28, SYSCTL__KERN_CHILDREN_PTR]
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
    add x19, x28, SVC_STALKER_CTL_CALLNUM
    str x19, [sp, SYSCTL_OID_STRUCT+0x18]
    ; oid_arg2, nothing
    str wzr, [sp, SYSCTL_OID_STRUCT+0x20]
    ; oid_name, "kern.svc_stalker_ctl_callnum"
    ldr x19, [x28, SVC_STALKER_SYSCTL_NAME_PTR]
    ; skip "kern."
    add x19, x19, 5
    str x19, [sp, SYSCTL_OID_STRUCT+0x28]
    ; oid_handler
    ldr x19, [x28, SYSCTL_HANDLE_LONG]
    str x19, [sp, SYSCTL_OID_STRUCT+0x30]
    ; oid_fmt
    ldr x19, [x28, SVC_STALKER_SYSCTL_FMT_PTR]
    str x19, [sp, SYSCTL_OID_STRUCT+0x38]
    ; oid_descr
    ldr x19, [x28, SVC_STALKER_SYSCTL_DESCR_PTR]
    str x19, [sp, SYSCTL_OID_STRUCT+0x40]
    ; oid_version
    mov w19, SYSCTL_OID_VERSION
    str w19, [sp, SYSCTL_OID_STRUCT+0x48]
    ; oid_refcnt
    str wzr, [sp, SYSCTL_OID_STRUCT+0x4c]

    ; register this sysctl
    add x0, sp, SYSCTL_OID_STRUCT
    ldr x19, [x28, SYSCTL_REGISTER_OID]
    blr x19

    ; Figure out what MIB array looks like for this new sysctl.
    ; We need this so the hook_system_check_sysctlbyname_hook can check
    ; if the incoming sysctl is ours.
    ;
    ; We're taking sysctl_geometry_lock because name2oid doesn't,
    ; and not giving it up until we've written a one to
    ; stalkertable+REGISTERED_SYSCTL_OFF because we're sharing this info
    ; with hook_system_check_sysctlbyname_hook.
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_LOCK_SHARED]
    blr x19
    ldr x0, [x28, SVC_STALKER_SYSCTL_NAME_PTR]
    ldr x1, [x28, SVC_STALKER_SYSCTL_MIB_PTR]
    ldr x2, [x28, SVC_STALKER_SYSCTL_MIB_COUNT_PTR]
    ldr x19, [x28, NAME2OID]
    blr x19
    ldr x19, [x28, STALKER_TABLE_PTR]
    mov x20, 1
    str x20, [x19, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19

maybeintercept:
    ; figure out if the system call made by this PID should be
    ; reported back to userland
    ldr x19, [x28, CURRENT_PROC]
    blr x19
    ldr x19, [x28, PROC_PID]
    blr x19
    str w0, [sp, CUR_PID]
    mov w1, w0
    ldr x0, [x28, STALKER_TABLE_PTR]
    ldr x19, [x28, STALKER_CTL_FROM_TABLE]
    blr x19
    ; user doesn't want to intercept any system calls from this pid, bail
    cbz x0, done
    ; does the user want this system call to be intercepted?
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x1, [x19, 0x88]
    ; X0 = pointer to stalker_ctl struct for proc_pid(current_proc())
    ldr x19, [x28, SHOULD_INTERCEPT_CALL]
    blr x19
    ; if user does not want this system call intercepted, we're done
    cbz x0, done

    ; TODO re-implement the sanity checks we overwrote

    mov x0, EXC_SYSCALL
    mov x1, EXC_MACH_SYSCALL
    ldr x2, [sp, SAVED_STATE_PTR]
    ldr x2, [x2, 0x88]                      ; X16, system call number
    cmp x2, 0
    csel x0, x1, x0, lt                     ; exception
    ldr w2, [sp, CUR_PID]
    str x2, [sp, EXC_CODES]                 ; pid which made the call
    mov w2, BEFORE_CALL                     ; if we're here, this call has
                                            ; not happened yet
    str x2, [sp, EXC_CODES+0x8]
    add x1, sp, EXC_CODES                   ; code
    mov w2, 2                               ; codeCnt
    ldr x19, [x28, EXCEPTION_TRIAGE]
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
