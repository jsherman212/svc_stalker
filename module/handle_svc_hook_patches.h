#ifndef handle_svc_hook
#define handle_svc_hook
#define DO_HANDLE_SVC_HOOK_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0156b7250    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a6ffc); /* 0xfffffff0156b7254    stp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0xa91b67fa); /* 0xfffffff0156b7258    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa91c5ff8); /* 0xfffffff0156b725c    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa91d57f6); /* 0xfffffff0156b7260    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa91e4ff4); /* 0xfffffff0156b7264    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa91f7bfd); /* 0xfffffff0156b7268    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0x9107c3fd); /* 0xfffffff0156b726c    add	x29, sp, #0x1f0           */ \
WRITE_INSTR(0xf900b7f3); /* 0xfffffff0156b7270    str	x19, [sp, #0x168]         */ \
WRITE_INSTR(0x10fffdf3); /* 0xfffffff0156b7274    adr	x19, #-0x44               */ \
WRITE_INSTR(0xf900cbf3); /* 0xfffffff0156b7278    str	x19, [sp, #0x190]         */ \
WRITE_INSTR(0xf9400274); /* 0xfffffff0156b727c    ldr	x20, [x19]                */ \
WRITE_INSTR(0xf900c7f4); /* 0xfffffff0156b7280    str	x20, [sp, #0x188]         */ \
WRITE_INSTR(0xf9400674); /* 0xfffffff0156b7284    ldr	x20, [x19, #0x8]          */ \
WRITE_INSTR(0xf900c3f4); /* 0xfffffff0156b7288    str	x20, [sp, #0x180]         */ \
WRITE_INSTR(0xf9400a74); /* 0xfffffff0156b728c    ldr	x20, [x19, #0x10]         */ \
WRITE_INSTR(0xf900bff4); /* 0xfffffff0156b7290    str	x20, [sp, #0x178]         */ \
WRITE_INSTR(0xf9400e74); /* 0xfffffff0156b7294    ldr	x20, [x19, #0x18]         */ \
WRITE_INSTR(0xf900bbf4); /* 0xfffffff0156b7298    str	x20, [sp, #0x170]         */ \
WRITE_INSTR(0xf940c3f3); /* 0xfffffff0156b729c    ldr	x19, [sp, #0x180]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0156b72a0    blr	x19                       */ \
WRITE_INSTR(0xf940bff3); /* 0xfffffff0156b72a4    ldr	x19, [sp, #0x178]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0156b72a8    blr	x19                       */ \
WRITE_INSTR(0xb90153e0); /* 0xfffffff0156b72ac    str	w0, [sp, #0x150]          */ \
WRITE_INSTR(0x2a0003e1); /* 0xfffffff0156b72b0    mov	w1, w0                    */ \
WRITE_INSTR(0xf940bbe0); /* 0xfffffff0156b72b4    ldr	x0, [sp, #0x170]          */ \
WRITE_INSTR(0x94000019); /* 0xfffffff0156b72b8    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72bc    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540001e0); /* 0xfffffff0156b72c0    b.eq	done                     */ \
WRITE_INSTR(0xf940b7f3); /* 0xfffffff0156b72c4    ldr	x19, [sp, #0x168]         */ \
WRITE_INSTR(0xf9404661); /* 0xfffffff0156b72c8    ldr	x1, [x19, #0x88]          */ \
WRITE_INSTR(0x94000025); /* 0xfffffff0156b72cc    bl	_should_intercept_syscall  */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72d0    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000140); /* 0xfffffff0156b72d4    b.eq	done                     */ \
WRITE_INSTR(0xd2800160); /* 0xfffffff0156b72d8    mov	x0, #0xb                  */ \
WRITE_INSTR(0xf940b7e1); /* 0xfffffff0156b72dc    ldr	x1, [sp, #0x168]          */ \
WRITE_INSTR(0xf9404421); /* 0xfffffff0156b72e0    ldr	x1, [x1, #0x88]           */ \
WRITE_INSTR(0xf900b3e1); /* 0xfffffff0156b72e4    str	x1, [sp, #0x160]          */ \
WRITE_INSTR(0xf900b7ff); /* 0xfffffff0156b72e8    str	xzr, [sp, #0x168]         */ \
WRITE_INSTR(0x910583e1); /* 0xfffffff0156b72ec    add	x1, sp, #0x160            */ \
WRITE_INSTR(0x52800042); /* 0xfffffff0156b72f0    mov	w2, #0x2                  */ \
WRITE_INSTR(0xf940c7f3); /* 0xfffffff0156b72f4    ldr	x19, [sp, #0x188]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0156b72f8    blr	x19                       */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b72fc    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b7300    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b7304    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b7308    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b730c    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b7310    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b7314    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7318    ret                           */ \
/*                                           _stalker_ctl_from_table:           */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b731c    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0156b7320    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b7324    b.eq	not_found0               */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0156b7328    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b732c    add	x11, x0, x10, uxtx #4     */ \
/*                                           search0:                           */ \
WRITE_INSTR(0xb940056c); /* 0xfffffff0156b7330    ldr	w12, [x11, #0x4]          */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0156b7334    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b7338    b.eq	found0                   */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0156b733c    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x710ffd5f); /* 0xfffffff0156b7340    cmp	w10, #0x3ff               */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0156b7344    b.ge	not_found0               */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b7348    add	x11, x0, x10, uxtx #4     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b734c    b	search0                     */ \
/*                                           not_found0:                        */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7350    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7354    ret                           */ \
/*                                           found0:                            */ \
WRITE_INSTR(0xaa0b03e0); /* 0xfffffff0156b7358    mov	x0, x11                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b735c    ret                           */ \
/*                                           _should_intercept_syscall:         */ \
WRITE_INSTR(0xf9400400); /* 0xfffffff0156b7360    ldr	x0, [x0, #0x8]            */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7364    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b7368    b.eq	do_not_intercept         */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0156b736c    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0156b7370    mov	x10, x0                   */ \
/*                                           search1:                           */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0156b7374    ldr	x11, [x10]                */ \
WRITE_INSTR(0xeb01017f); /* 0xfffffff0156b7378    cmp	x11, x1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b737c    b.eq	intercept                */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b7380    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0156b7384    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0156b7388    b.ge	do_not_intercept         */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0156b738c    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b7390    b	search1                     */ \
/*                                           do_not_intercept:                  */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7394    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7398    ret                           */ \
/*                                           intercept:                         */ \
WRITE_INSTR(0xd2800020); /* 0xfffffff0156b739c    mov	x0, #0x1                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b73a0    ret                           */ 
#endif
