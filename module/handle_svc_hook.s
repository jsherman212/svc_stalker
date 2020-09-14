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

    ldr x19, [x28, IS_SYSCTL_REGISTERED]
    blr x19
    ; if we've already registered the sysctl, don't do it again
    cbnz x0, maybeintercept

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
    mov x21, x0
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
    mov x0, x21
    ldr x19, [x28, LCK_RW_DONE]
    blr x19

maybeintercept:
    ; TODO re-implement the sanity checks we overwrote

    ldr x19, [sp, SAVED_STATE_PTR]
    ldr w0, [x19, 0x88]
    ldr x19, [x28, SHOULD_INTERCEPT_CALL]
    blr x19
    cbz x0, done

    ldr x19, [x28, CURRENT_PROC]
    blr x19
    ldr x19, [x28, PROC_PID]
    blr x19
    mov w1, w0
    mov x0, EXC_SYSCALL
    mov x3, EXC_MACH_SYSCALL
    ldr x2, [sp, SAVED_STATE_PTR]
    ldr w2, [x2, 0x88]                      ; X16, call number
    cmp w2, wzr
    csel x0, x3, x0, lt                     ; exception
    mov w2, BEFORE_CALL                     ; if we're here, this call has
                                            ; not happened yet
    ldr x19, [x28, SEND_EXCEPTION_MSG]
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
