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
    cbnz x0, try_create_stalker_lock

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
    add x19, x19, 0x5
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
    mov x20, 0x1
    str x20, [x19, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    ldr x0, [x28, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19

try_create_stalker_lock:
    ; racy... but it's only a read. could be worse :D
    ldr x19, [x28, STALKER_LOCK]
    ; skip this part if it already exists
    cbnz x19, maybe_intercept

    ; Should be done far before springboard even launches, and I don't care
    ; about leaking a few bytes if this does end up getting raced
    ; X0 == "stkr_lg"
    movk x0, 0x7473
    movk x0, 0x726b, lsl 0x10
    movk x0, 0x6c5f, lsl 0x20
    movk x0, 0x0067, lsl 0x30
    str x0, [sp, STALKER_LOCK_GROUP_NAME]
    add x0, sp, STALKER_LOCK_GROUP_NAME
    mov x1, xzr
    ldr x19, [x28, LCK_GRP_ALLOC_INIT]
    blr x19
    cbz x0, done
    mov x1, xzr
    ldr x19, [x28, LCK_RW_ALLOC_INIT]
    blr x19
    cbz x0, done
    str x0, [x28, STALKER_LOCK]

maybe_intercept:
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr w0, [x19, 0x88]
    ldr x19, [x28, SHOULD_INTERCEPT_CALL]
    blr x19
    cbz x0, done

    ; since call numbers are 32 bits in XNU, we can use the upper 32
    ; bits of X16 as a call ID that remains constant between BEFORE_CALL and
    ; CALL_COMPLETED so mini_strace can figure out which BEFORE_CALL saved state
    ; corresponds to a given CALL_COMPLETED saved state
    ; However, we also need to support interception of indirect system calls,
    ; so if X16 == XZR, then the call number is in X0, and we'll OR the call
    ; ID into it as well

    ldr x0, [x28, STALKER_LOCK]
    ldr x19, [x28, LCK_RW_LOCK_SHARED]
    blr x19
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x20, [x19, 0x88]                ; X16
    ; add x23, x19, 0x88
    ; cbnz x20, write_call_id
    ; indirect system call, X0
    ; ldr x20, [x19, 0x8]
    ; add x23, x19, 0x8

; write_call_id:

    ; XXX indirect syscall bug: this is setting up call ID fine
    ; cmp w20, wzr
    ; b.eq die
    ; b live
; die:
    ; brk 0
; live:
    ; clear upper 32 bits
    and x20, x20, 0xffffffff
    ldr x21, [x28, CUR_CALL_ID]
    mov x22, x21
    lsl x21, x21, 0x20
    orr x20, x20, x21
    str x20, [x19, 0x88]
    ; str x20, [x23]
    ; cmp w20, wzr
    ; b.eq die
    ; b live
; die:
    ; brk 0
; live:
    add x22, x22, 0x1
    str x22, [x28, CUR_CALL_ID]
    ldr x0, [x28, STALKER_LOCK]
    ldr x19, [x28, LCK_RW_DONE]
    blr x19

    ldr x19, [x28, CURRENT_PROC]
    blr x19
    ldr x19, [x28, PROC_PID]
    blr x19
    mov w1, w0
    ldr x2, [sp, SAVED_STATE_PTR]
    ldr w2, [x2, 0x88]
    cmp w2, wzr
    mov x0, EXC_SYSCALL
    mov x3, EXC_MACH_SYSCALL
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
