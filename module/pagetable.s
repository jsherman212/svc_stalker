    .globl _main
    .align 4

#include "pagetable.h"

; this will mark the memory returned by alloc_static (where the handle_svc
; hook and the svc_stalker_ctl live) as executable, then branch to the
; handle_svc hook
;
; This is what handle_svc calls after I patch it
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
    ldr x20, [x19, HANDLE_SVC_HOOK_FPTR_CACHEOFF]
    str x20, [sp, HANDLE_SVC_HOOK_FPTR]
    ldr x20, [x19, NUM_PAGES_CACHEOFF]
    str x20, [sp, NUM_PAGES]
    ldr x20, [x19, PHYSTOKV_FPTR_CACHEOFF]
    str x20, [sp, PHYSTOKV_FPTR]

    ldr x19, [sp, VADDR_CUR]
    ldr x20, [sp, NUM_PAGES]
    mov x21, PAGE_SIZE
    mul x20, x20, x21
    add x19, x19, x20
    str x20, [sp, VADDR_END]

ptloop:


ptloop_prep:
    ldr x19, [sp, VADDR_CUR]
    add x19, x19, PAGE_SIZE
    ldr x20, [sp, VADDR_END]
    cmp x19, x20
    b.hi done
    str x19, [sp, VADDR_CUR]
    b ptloop

done:
    ; handle_svc_hook expects X19 to be an arm_saved_state struct pointer
    ldr x19, [sp, SAVED_STATE_PTR]
    ldr x20, [sp, HANDLE_SVC_HOOK_FPTR]
    blr x20
    ldp x29, x30, [sp, STACK-0x10]
    ldp x20, x19, [sp, STACK-0x20]
    ldp x22, x21, [sp, STACK-0x30]
    ldp x24, x23, [sp, STACK-0x40]
    ldp x26, x25, [sp, STACK-0x50]
    ldp x28, x27, [sp, STACK-0x60]
    add sp, sp, STACK
    ret

; Next three functions:
; X0 = kernel virtual address
; X1 = corresponding TTE/PTE pointer (virtual addr)
;
; On returning, each return a virtual pointer to the corresponding TTE/PTE
_l1_tte_vm_pointer_for_kvaddr:
    lsr x0, x0, ARM_TT_L1_SHIFT
    and x0, x0, 7                            ; X0: index for kvaddr for L1 tt
    add x0, x1, x0, lsl 3
    ret

_l2_tte_vm_pointer_for_kvaddr:
    lsr x0, x0, ARM_TT_L2_SHIFT
    and x0, x0, 0x7ff                        ; X0: index for kvaddr for L2 tt
    add x0, x1, x0, lsl 3
    ret

_l3_pte_vm_pointer_for_kvaddr:
    lsr x0, x0, ARM_TT_L3_SHIFT
    and x0, x0, 0x7ff                        ; X0: index for kvaddr for L3 pt
    add x0, x1, x0, lsl 3
    ret
