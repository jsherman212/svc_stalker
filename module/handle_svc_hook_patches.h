#ifndef handle_svc_hook
#define handle_svc_hook
#define DO_HANDLE_SVC_HOOK_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0090a32a0    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a6ffc); /* 0xfffffff0090a32a4    stp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0xa91b67fa); /* 0xfffffff0090a32a8    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa91c5ff8); /* 0xfffffff0090a32ac    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa91d57f6); /* 0xfffffff0090a32b0    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa91e4ff4); /* 0xfffffff0090a32b4    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa91f7bfd); /* 0xfffffff0090a32b8    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0x9107c3fd); /* 0xfffffff0090a32bc    add	x29, sp, #0x1f0           */ \
WRITE_INSTR(0xf900b7f3); /* 0xfffffff0090a32c0    str	x19, [sp, #0x168]         */ \
WRITE_INSTR(0x10fffdf3); /* 0xfffffff0090a32c4    adr	x19, #-0x44               */ \
WRITE_INSTR(0xf900cbf3); /* 0xfffffff0090a32c8    str	x19, [sp, #0x190]         */ \
WRITE_INSTR(0xf9400274); /* 0xfffffff0090a32cc    ldr	x20, [x19]                */ \
WRITE_INSTR(0xf900c7f4); /* 0xfffffff0090a32d0    str	x20, [sp, #0x188]         */ \
WRITE_INSTR(0xf9400674); /* 0xfffffff0090a32d4    ldr	x20, [x19, #0x8]          */ \
WRITE_INSTR(0xf900c3f4); /* 0xfffffff0090a32d8    str	x20, [sp, #0x180]         */ \
WRITE_INSTR(0xf9400a74); /* 0xfffffff0090a32dc    ldr	x20, [x19, #0x10]         */ \
WRITE_INSTR(0xf900bff4); /* 0xfffffff0090a32e0    str	x20, [sp, #0x178]         */ \
WRITE_INSTR(0xf9400e74); /* 0xfffffff0090a32e4    ldr	x20, [x19, #0x18]         */ \
WRITE_INSTR(0xf900bbf4); /* 0xfffffff0090a32e8    str	x20, [sp, #0x170]         */ \
WRITE_INSTR(0xf940c3f3); /* 0xfffffff0090a32ec    ldr	x19, [sp, #0x180]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0090a32f0    blr	x19                       */ \
WRITE_INSTR(0xf940bff3); /* 0xfffffff0090a32f4    ldr	x19, [sp, #0x178]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0090a32f8    blr	x19                       */ \
WRITE_INSTR(0x2a0003e1); /* 0xfffffff0090a32fc    mov	w1, w0                    */ \
WRITE_INSTR(0xf940bbe0); /* 0xfffffff0090a3300    ldr	x0, [sp, #0x170]          */ \
WRITE_INSTR(0x9400001c); /* 0xfffffff0090a3304    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a3308    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000240); /* 0xfffffff0090a330c    b.eq	done                     */ \
WRITE_INSTR(0xf940b7f3); /* 0xfffffff0090a3310    ldr	x19, [sp, #0x168]         */ \
WRITE_INSTR(0xf9404661); /* 0xfffffff0090a3314    ldr	x1, [x19, #0x88]          */ \
WRITE_INSTR(0x94000028); /* 0xfffffff0090a3318    bl	_should_intercept_syscall  */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a331c    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540001a0); /* 0xfffffff0090a3320    b.eq	done                     */ \
WRITE_INSTR(0xd28000e0); /* 0xfffffff0090a3324    mov	x0, #0x7                  */ \
WRITE_INSTR(0xd2800101); /* 0xfffffff0090a3328    mov	x1, #0x8                  */ \
WRITE_INSTR(0xf940b7e2); /* 0xfffffff0090a332c    ldr	x2, [sp, #0x168]          */ \
WRITE_INSTR(0xf9404442); /* 0xfffffff0090a3330    ldr	x2, [x2, #0x88]           */ \
WRITE_INSTR(0xf100005f); /* 0xfffffff0090a3334    cmp	x2, #0x0                  */ \
WRITE_INSTR(0x9a80b020); /* 0xfffffff0090a3338    csel	x0, x1, x0, lt           */ \
WRITE_INSTR(0xf900b3e2); /* 0xfffffff0090a333c    str	x2, [sp, #0x160]          */ \
WRITE_INSTR(0xf900b7ff); /* 0xfffffff0090a3340    str	xzr, [sp, #0x168]         */ \
WRITE_INSTR(0x910583e1); /* 0xfffffff0090a3344    add	x1, sp, #0x160            */ \
WRITE_INSTR(0x52800042); /* 0xfffffff0090a3348    mov	w2, #0x2                  */ \
WRITE_INSTR(0xf940c7f3); /* 0xfffffff0090a334c    ldr	x19, [sp, #0x188]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0090a3350    blr	x19                       */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0090a3354    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0090a3358    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0090a335c    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0090a3360    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0090a3364    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0090a3368    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0090a336c    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a3370    ret                           */ \
/*                                           _stalker_ctl_from_table:           */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0090a3374    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0090a3378    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0090a337c    b.eq	not_found0               */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0090a3380    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0090a3384    add	x11, x0, x10, uxtx #4     */ \
/*                                           search0:                           */ \
WRITE_INSTR(0xb940056c); /* 0xfffffff0090a3388    ldr	w12, [x11, #0x4]          */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0090a338c    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0090a3390    b.eq	found0                   */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0090a3394    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x710ffd5f); /* 0xfffffff0090a3398    cmp	w10, #0x3ff               */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0090a339c    b.ge	not_found0               */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0090a33a0    add	x11, x0, x10, uxtx #4     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0090a33a4    b	search0                     */ \
/*                                           not_found0:                        */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0090a33a8    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a33ac    ret                           */ \
/*                                           found0:                            */ \
WRITE_INSTR(0xaa0b03e0); /* 0xfffffff0090a33b0    mov	x0, x11                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a33b4    ret                           */ \
/*                                           _should_intercept_syscall:         */ \
WRITE_INSTR(0xf9400400); /* 0xfffffff0090a33b8    ldr	x0, [x0, #0x8]            */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a33bc    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0090a33c0    b.eq	do_not_intercept         */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0090a33c4    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0090a33c8    mov	x10, x0                   */ \
/*                                           search1:                           */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0090a33cc    ldr	x11, [x10]                */ \
WRITE_INSTR(0xeb01017f); /* 0xfffffff0090a33d0    cmp	x11, x1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0090a33d4    b.eq	intercept                */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0090a33d8    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0090a33dc    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0090a33e0    b.ge	do_not_intercept         */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0090a33e4    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0090a33e8    b	search1                     */ \
/*                                           do_not_intercept:                  */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0090a33ec    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a33f0    ret                           */ \
/*                                           intercept:                         */ \
WRITE_INSTR(0xd2800020); /* 0xfffffff0090a33f4    mov	x0, #0x1                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a33f8    ret                           */ 
const static int g_handle_svc_hook_num_instrs = 87;
#endif
