#ifndef pagetable
#define pagetable
#define DO_PAGETABLE_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR_TO_EXEC(0xd10803ff); /* 0xfffffff0156b7250    sub	sp, sp, #0x200            */ \
WRITE_INSTR_TO_EXEC(0xa91a6ffc); /* 0xfffffff0156b7254    stp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR_TO_EXEC(0xa91b67fa); /* 0xfffffff0156b7258    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR_TO_EXEC(0xa91c5ff8); /* 0xfffffff0156b725c    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR_TO_EXEC(0xa91d57f6); /* 0xfffffff0156b7260    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR_TO_EXEC(0xa91e4ff4); /* 0xfffffff0156b7264    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR_TO_EXEC(0xa91f7bfd); /* 0xfffffff0156b7268    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR_TO_EXEC(0x9107c3fd); /* 0xfffffff0156b726c    add	x29, sp, #0x1f0           */ \
WRITE_INSTR_TO_EXEC(0xf900c7f3); /* 0xfffffff0156b7270    str	x19, [sp, #0x188]         */ \
WRITE_INSTR_TO_EXEC(0x10fffe33); /* 0xfffffff0156b7274    adr	x19, #-0x3c               */ \
WRITE_INSTR_TO_EXEC(0xf9400274); /* 0xfffffff0156b7278    ldr	x20, [x19]                */ \
WRITE_INSTR_TO_EXEC(0xf900cbf4); /* 0xfffffff0156b727c    str	x20, [sp, #0x190]         */ \
WRITE_INSTR_TO_EXEC(0xf9400674); /* 0xfffffff0156b7280    ldr	x20, [x19, #0x8]          */ \
WRITE_INSTR_TO_EXEC(0xf900c3f4); /* 0xfffffff0156b7284    str	x20, [sp, #0x180]         */ \
WRITE_INSTR_TO_EXEC(0xf9400a74); /* 0xfffffff0156b7288    ldr	x20, [x19, #0x10]         */ \
WRITE_INSTR_TO_EXEC(0xf900b7f4); /* 0xfffffff0156b728c    str	x20, [sp, #0x168]         */ \
WRITE_INSTR_TO_EXEC(0xf940bff3); /* 0xfffffff0156b7290    ldr	x19, [sp, #0x178]         */ \
WRITE_INSTR_TO_EXEC(0xf940c3f4); /* 0xfffffff0156b7294    ldr	x20, [sp, #0x180]         */ \
WRITE_INSTR_TO_EXEC(0xd2880015); /* 0xfffffff0156b7298    mov	x21, #0x4000              */ \
WRITE_INSTR_TO_EXEC(0x9b157e94); /* 0xfffffff0156b729c    mul	x20, x20, x21             */ \
WRITE_INSTR_TO_EXEC(0x8b140273); /* 0xfffffff0156b72a0    add	x19, x19, x20             */ \
WRITE_INSTR_TO_EXEC(0xf900bbf4); /* 0xfffffff0156b72a4    str	x20, [sp, #0x170]         */ \
/*                                           ptloop:                            */ \
WRITE_INSTR_TO_EXEC(0xf940bff3); /* 0xfffffff0156b72a8    ldr	x19, [sp, #0x178]         */ \
WRITE_INSTR_TO_EXEC(0x91401273); /* 0xfffffff0156b72ac    add	x19, x19, #0x4, lsl #12   */ \
WRITE_INSTR_TO_EXEC(0xf940bbf4); /* 0xfffffff0156b72b0    ldr	x20, [sp, #0x170]         */ \
WRITE_INSTR_TO_EXEC(0xeb14027f); /* 0xfffffff0156b72b4    cmp	x19, x20                  */ \
WRITE_INSTR_TO_EXEC(0x54000068); /* 0xfffffff0156b72b8    b.hi	done                     */ \
WRITE_INSTR_TO_EXEC(0xf900bff3); /* 0xfffffff0156b72bc    str	x19, [sp, #0x178]         */ \
WRITE_INSTR_TO_EXEC(0x17fffffa); /* 0xfffffff0156b72c0    b	ptloop                      */ \
/*                                           done:                              */ \
WRITE_INSTR_TO_EXEC(0xf940c7f3); /* 0xfffffff0156b72c4    ldr	x19, [sp, #0x188]         */ \
WRITE_INSTR_TO_EXEC(0xf940cbf4); /* 0xfffffff0156b72c8    ldr	x20, [sp, #0x190]         */ \
WRITE_INSTR_TO_EXEC(0xd63f0280); /* 0xfffffff0156b72cc    blr	x20                       */ \
WRITE_INSTR_TO_EXEC(0xa95f7bfd); /* 0xfffffff0156b72d0    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR_TO_EXEC(0xa95e4ff4); /* 0xfffffff0156b72d4    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR_TO_EXEC(0xa95d57f6); /* 0xfffffff0156b72d8    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR_TO_EXEC(0xa95c5ff8); /* 0xfffffff0156b72dc    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR_TO_EXEC(0xa95b67fa); /* 0xfffffff0156b72e0    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR_TO_EXEC(0xa95a6ffc); /* 0xfffffff0156b72e4    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR_TO_EXEC(0x910803ff); /* 0xfffffff0156b72e8    add	sp, sp, #0x200            */ \
WRITE_INSTR_TO_EXEC(0xd65f03c0); /* 0xfffffff0156b72ec    ret                           */ \
/*                                           _l1_tte_vm_pointer_for_kvaddr:     */ \
WRITE_INSTR_TO_EXEC(0xd364fc00); /* 0xfffffff0156b72f0    lsr	x0, x0, #36               */ \
WRITE_INSTR_TO_EXEC(0x92400800); /* 0xfffffff0156b72f4    and	x0, x0, #0x7              */ \
WRITE_INSTR_TO_EXEC(0x8b000c20); /* 0xfffffff0156b72f8    add	x0, x1, x0, lsl #3        */ \
WRITE_INSTR_TO_EXEC(0xd65f03c0); /* 0xfffffff0156b72fc    ret                           */ \
/*                                           _l2_tte_vm_pointer_for_kvaddr:     */ \
WRITE_INSTR_TO_EXEC(0xd359fc00); /* 0xfffffff0156b7300    lsr	x0, x0, #25               */ \
WRITE_INSTR_TO_EXEC(0x92402800); /* 0xfffffff0156b7304    and	x0, x0, #0x7ff            */ \
WRITE_INSTR_TO_EXEC(0x8b000c20); /* 0xfffffff0156b7308    add	x0, x1, x0, lsl #3        */ \
WRITE_INSTR_TO_EXEC(0xd65f03c0); /* 0xfffffff0156b730c    ret                           */ \
/*                                           _l3_pte_vm_pointer_for_kvaddr:     */ \
WRITE_INSTR_TO_EXEC(0xd34efc00); /* 0xfffffff0156b7310    lsr	x0, x0, #14               */ \
WRITE_INSTR_TO_EXEC(0x92402800); /* 0xfffffff0156b7314    and	x0, x0, #0x7ff            */ \
WRITE_INSTR_TO_EXEC(0x8b000c20); /* 0xfffffff0156b7318    add	x0, x1, x0, lsl #3        */ \
WRITE_INSTR_TO_EXEC(0xd65f03c0); /* 0xfffffff0156b731c    ret                           */ 
#endif
