    .globl _main
    .align 4

#include "../common/stalker_cache.h"
#include "../common/stalker_table.h"

#include "handle_svc_hook.h"

; I guess this no longer "literally" an inlined handle_svc hook since we're
; called from sleh_synchronous_hijacker... but we would have reached
; inlined handle_svc shortly after sleh_synchronous_hijacker returns so I
; think the name still fits
;
; This iterates through the PIDs/call numbers the user has registered through the
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

    ; XXX if I put b done here, 14.2 does not crash during boot
    ; b done

    str x0, [sp, SAVED_STATE_PTR]

    adr x19, STALKER_CACHE_PTR_PTR
    ldr x28, [x19]

    ; XXX if I put b try_create_stalker_lock here, 14.2 does not crash
    ; during boot
    ; b try_create_stalker_lock

    ; XXX if I uncomment this, it crashes, but the panic seems to be
    ; manifested as an EXC_GUARD crash for syncdefaultsd??
    ; mov x7, 0x4141
    ; brk 0

    ldr x19, [x28, IS_SYSCTL_REGISTERED]
    blr x19
    ; if we've already registered the sysctl, don't do it again
    cbnz x0, try_create_stalker_lock

    ; set up the kern.svc_stalker_ctl_callnum sysctl
    ; on >=14.2, Apple has depricated non-OID2 sysctls. For non OID2 sysctls,
    ; sysctl_register_oid would deep-copy the first parameter, but this is
    ; not done for OID2 sysctls. So we need to kalloc it instead of passing
    ; a stack address.
    ; I don't care if this is raced, leaking a little bit of mem isn't
    ; the end of the world

    mov x0, SIZEOF_STRUCT_SYSCTL_OID
    ldr x19, [x28, COMMON_KALLOC]
    blr x19
    cbz x0, done
    
    ldr x19, [x28, SYSCTL__KERN_CHILDREN_PTR]
    str x19, [x0, OFFSETOF_OID_PARENT]
    str xzr, [x0, OFFSETOF_OID_LINK]
    mov w19, OID_AUTO
    str w19, [x0, OFFSETOF_OID_NUMBER]
    mov w19, CTLTYPE_INT
    orr w19, w19, CTLFLAG_RD
    orr w19, w19, CTLFLAG_ANYBODY
    orr w19, w19, CTLFLAG_OID2
    str w19, [x0, OFFSETOF_OID_KIND]
    add x19, x28, SVC_STALKER_CTL_CALLNUM
    str x19, [x0, OFFSETOF_OID_ARG1]
    str wzr, [x0, OFFSETOF_OID_ARG2]
    ; oid_name, "kern.svc_stalker_ctl_callnum"
    ldr x19, [x28, SVC_STALKER_SYSCTL_NAME_PTR]
    ; skip "kern."
    add x19, x19, 0x5
    str x19, [x0, OFFSETOF_OID_NAME]
    ldr x19, [x28, SYSCTL_HANDLE_LONG]
    str x19, [x0, OFFSETOF_OID_HANDLER]
    ldr x19, [x28, SVC_STALKER_SYSCTL_FMT_PTR]
    str x19, [x0, OFFSETOF_OID_FMT]
    ldr x19, [x28, SVC_STALKER_SYSCTL_DESCR_PTR]
    str x19, [x0, OFFSETOF_OID_DESCR]
    mov w19, SYSCTL_OID_VERSION
    str w19, [x0, OFFSETOF_OID_VERSION]
    str wzr, [x0, OFFSETOF_OID_REFCNT]

    ; register this sysctl
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

    ; if we're here stalker lock is not NULL
    TAKE_STALKER_LOCK x28, x19

    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x20, [x19, 0x88]                    ; X16 of user pcb
    ; clear upper 32 bits
    and x20, x20, 0xffffffff
    ldr x21, [x28, CUR_CALL_ID]
    mov x22, x21
    lsl x21, x21, 0x20
    orr x20, x20, x21
    str x20, [x19, 0x88]
    add x22, x22, 0x1
    str x22, [x28, CUR_CALL_ID]

    RELEASE_STALKER_LOCK x28, x19

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
