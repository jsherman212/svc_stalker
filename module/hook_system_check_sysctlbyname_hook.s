    .align 4
    .globl _main

#include "hook_system_check_sysctlbyname_hook.h"

_main:
    sub sp, sp, STACK
    ; we branched when parameters were being copied to callee-saved registers
    stp x7, x6, [sp, STACK-0xa0]
    stp x5, x4, [sp, STACK-0x90]
    stp x3, x2, [sp, STACK-0x80]
    stp x1, x0, [sp, STACK-0x70]
    stp x28, x27, [sp, STACK-0x60]
    stp x26, x25, [sp, STACK-0x50]
    stp x24, x23, [sp, STACK-0x40]
    stp x22, x21, [sp, STACK-0x30]
    stp x20, x19, [sp, STACK-0x20]
    stp x29, x30, [sp, STACK-0x10]
    add x29, sp, STACK-0x10

    adr x19, CACHE_START
    str x19, [sp, OFFSET_CACHE_PTR]
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
    ldr x20, [x19, STALKER_TABLE_CACHEOFF]
    str x20, [sp, STALKER_TABLE_PTR]
    ldr x20, [x19, H_S_C_SBN_EPILOGUE_BEGIN_CACHEOFF]
    str x20, [sp, H_S_C_SBN_EPILOGUE_ADDR]

    ; MIB array
    mov x19, x2
    ; length of MIB array
    mov w20, w3

    ; we're sharing this data with handle_svc_hook, and this function we're
    ; hooking doesn't take sysctl_geometry_lock
    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x21, [sp, LCK_RW_LOCK_SHARED_FPTR]
    blr x21
    ; if this sysctl hasn't been added yet, don't do anything
    ldr x21, [sp, STALKER_TABLE_PTR]
    ldr x21, [x21, STALKER_TABLE_REGISTERED_SYSCTL_OFF]
    cbz x21, not_ours
    ldr x21, [sp, NEW_SYSCTL_MIB_COUNT_PTR]
    ldr w21, [x21]
    cmp w21, w20
    b.ne not_ours

    ; same length, so compare MIB contents
    mov w21, wzr ;index
    ldr x22, [sp, NEW_SYSCTL_MIB_PTR] ;cursor
    mov x23, x22 ;base
    mov x24, x19 ;cursor
    mov x25, x24 ;base

mib_check_loop:
    ldr w26, [x22]
    ldr w27, [x24]
    cmp w26, w27
    b.ne not_ours
    add w21, w21, 1
    cmp w21, w20
    b.eq ours
    add x22, x23, w21, lsl 2
    add x24, x25, w21, lsl 2
    b mib_check_loop

ours:
    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [sp, LCK_RW_DONE_FPTR]
    blr x19
    ; if it is ours, branch right to hook_system_check_sysctlbyname's
    ; epilogue, returning no error
    ldr x1, [sp, H_S_C_SBN_EPILOGUE_ADDR]
    add sp, sp, STACK
    mov x0, 0
    br x1

; in the case our sysctl wasn't being dealt with, return back to
; hook_system_check_sysctlbyname to carry out its normal operation
not_ours:
    ldr x0, [sp, SYSCTL_GEOMETRY_LOCK_PTR]
    ldr x0, [x0]
    ldr x19, [sp, LCK_RW_DONE_FPTR]
    blr x19
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    ldp x1, x0, [sp, STACK-0x70]
    ldp x3, x2, [sp, STACK-0x80]
    ldp x5, x4, [sp, STACK-0x90]
    ldp x7, x6, [sp, STACK-0xa0]
    add sp, sp, STACK
    ; this is missing a RET so svc_stalker can write back the instructions
    ; we overwrote to branch to this code
    ; XXX because of this, NOTHING CAN BE AFTER THIS POINT
