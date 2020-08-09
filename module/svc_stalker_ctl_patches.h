#ifndef svc_stalker_ctl
#define svc_stalker_ctl
#define DO_SVC_STALKER_CTL_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0090a32a0    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a6ffc); /* 0xfffffff0090a32a4    stp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0xa91b67fa); /* 0xfffffff0090a32a8    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa91c5ff8); /* 0xfffffff0090a32ac    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa91d57f6); /* 0xfffffff0090a32b0    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa91e4ff4); /* 0xfffffff0090a32b4    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa91f7bfd); /* 0xfffffff0090a32b8    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0x9107c3fd); /* 0xfffffff0090a32bc    add	x29, sp, #0x1f0           */ \
WRITE_INSTR(0xaa0003f3); /* 0xfffffff0090a32c0    mov	x19, x0                   */ \
WRITE_INSTR(0xaa0103f4); /* 0xfffffff0090a32c4    mov	x20, x1                   */ \
WRITE_INSTR(0xaa0203f5); /* 0xfffffff0090a32c8    mov	x21, x2                   */ \
WRITE_INSTR(0x10fffdf6); /* 0xfffffff0090a32cc    adr	x22, #-0x44               */ \
WRITE_INSTR(0xf94002d7); /* 0xfffffff0090a32d0    ldr	x23, [x22]                */ \
WRITE_INSTR(0xf900c7f7); /* 0xfffffff0090a32d4    str	x23, [sp, #0x188]         */ \
WRITE_INSTR(0xf94006d7); /* 0xfffffff0090a32d8    ldr	x23, [x22, #0x8]          */ \
WRITE_INSTR(0xf900b7f7); /* 0xfffffff0090a32dc    str	x23, [sp, #0x168]         */ \
WRITE_INSTR(0xf9400ad7); /* 0xfffffff0090a32e0    ldr	x23, [x22, #0x10]         */ \
WRITE_INSTR(0xf900b3f7); /* 0xfffffff0090a32e4    str	x23, [sp, #0x160]         */ \
WRITE_INSTR(0xb9400a96); /* 0xfffffff0090a32e8    ldr	w22, [x20, #0x8]          */ \
WRITE_INSTR(0x710002df); /* 0xfffffff0090a32ec    cmp	w22, #0x0                 */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0090a32f0    b.eq	check_if_patched         */ \
WRITE_INSTR(0x710006df); /* 0xfffffff0090a32f4    cmp	w22, #0x1                 */ \
WRITE_INSTR(0x54000620); /* 0xfffffff0090a32f8    b.eq	syscall_manage           */ \
WRITE_INSTR(0x71000adf); /* 0xfffffff0090a32fc    cmp	w22, #0x2                 */ \
WRITE_INSTR(0x54000d80); /* 0xfffffff0090a3300    b.eq	out_givetablekaddr       */ \
WRITE_INSTR(0x1400005f); /* 0xfffffff0090a3304    b	out_einval                  */ \
/*                                           check_if_patched:                  */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0090a3308    ldr	w22, [x20]                */ \
WRITE_INSTR(0x310006df); /* 0xfffffff0090a330c    cmn	w22, #0x1                 */ \
WRITE_INSTR(0x54000c80); /* 0xfffffff0090a3310    b.eq	out_patched              */ \
/*                                           pid_manage:                        */ \
WRITE_INSTR(0x54000b6b); /* 0xfffffff0090a3314    b.lt	out_einval               */ \
WRITE_INSTR(0xb9401297); /* 0xfffffff0090a3318    ldr	w23, [x20, #0x10]         */ \
WRITE_INSTR(0x35000057); /* 0xfffffff0090a331c    cbnz	w23, add_pid             */ \
WRITE_INSTR(0x14000012); /* 0xfffffff0090a3320    b	delete_pid                  */ \
/*                                           add_pid:                           */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0090a3324    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0090a3328    mov	w1, w22                   */ \
WRITE_INSTR(0x9400006f); /* 0xfffffff0090a332c    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a3330    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000c61); /* 0xfffffff0090a3334    b.ne	success                  */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0090a3338    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x9400007c); /* 0xfffffff0090a333c    bl	_get_nearest_free_stalker_ctl*/ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a3340    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540009e0); /* 0xfffffff0090a3344    b.eq	out_einval               */ \
WRITE_INSTR(0xb900001f); /* 0xfffffff0090a3348    str	wzr, [x0]                 */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0090a334c    ldr	w22, [x20]                */ \
WRITE_INSTR(0xb9000416); /* 0xfffffff0090a3350    str	w22, [x0, #0x4]           */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0090a3354    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0090a3358    ldr	w23, [x22]                */ \
WRITE_INSTR(0x110006f7); /* 0xfffffff0090a335c    add	w23, w23, #0x1            */ \
WRITE_INSTR(0xb90002d7); /* 0xfffffff0090a3360    str	w23, [x22]                */ \
WRITE_INSTR(0x14000057); /* 0xfffffff0090a3364    b	success                     */ \
/*                                           delete_pid:                        */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0090a3368    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0090a336c    mov	w1, w22                   */ \
WRITE_INSTR(0x9400005e); /* 0xfffffff0090a3370    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a3374    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000840); /* 0xfffffff0090a3378    b.eq	out_einval               */ \
WRITE_INSTR(0x52800036); /* 0xfffffff0090a337c    mov	w22, #0x1                 */ \
WRITE_INSTR(0xb9000016); /* 0xfffffff0090a3380    str	w22, [x0]                 */ \
WRITE_INSTR(0xb900041f); /* 0xfffffff0090a3384    str	wzr, [x0, #0x4]           */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0090a3388    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0090a338c    ldr	w23, [x22]                */ \
WRITE_INSTR(0x510006f7); /* 0xfffffff0090a3390    sub	w23, w23, #0x1            */ \
WRITE_INSTR(0xb90002d7); /* 0xfffffff0090a3394    str	w23, [x22]                */ \
WRITE_INSTR(0xf9400416); /* 0xfffffff0090a3398    ldr	x22, [x0, #0x8]           */ \
WRITE_INSTR(0xf10002df); /* 0xfffffff0090a339c    cmp	x22, #0x0                 */ \
WRITE_INSTR(0x54000900); /* 0xfffffff0090a33a0    b.eq	success                  */ \
WRITE_INSTR(0xaa0003f7); /* 0xfffffff0090a33a4    mov	x23, x0                   */ \
WRITE_INSTR(0xaa1603e0); /* 0xfffffff0090a33a8    mov	x0, x22                   */ \
WRITE_INSTR(0xf940b3f6); /* 0xfffffff0090a33ac    ldr	x22, [sp, #0x160]         */ \
WRITE_INSTR(0xd63f02c0); /* 0xfffffff0090a33b0    blr	x22                       */ \
WRITE_INSTR(0xf90006ff); /* 0xfffffff0090a33b4    str	xzr, [x23, #0x8]          */ \
WRITE_INSTR(0x14000042); /* 0xfffffff0090a33b8    b	success                     */ \
/*                                           syscall_manage:                    */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0090a33bc    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0xb9400281); /* 0xfffffff0090a33c0    ldr	w1, [x20]                 */ \
WRITE_INSTR(0x94000049); /* 0xfffffff0090a33c4    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a33c8    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540005a0); /* 0xfffffff0090a33cc    b.eq	out_einval               */ \
WRITE_INSTR(0xf900abe0); /* 0xfffffff0090a33d0    str	x0, [sp, #0x150]          */ \
WRITE_INSTR(0xb9401a96); /* 0xfffffff0090a33d4    ldr	w22, [x20, #0x18]         */ \
WRITE_INSTR(0x34000436); /* 0xfffffff0090a33d8    cbz	w22, delete_syscall       */ \
WRITE_INSTR(0xf9400416); /* 0xfffffff0090a33dc    ldr	x22, [x0, #0x8]           */ \
WRITE_INSTR(0xb50002f6); /* 0xfffffff0090a33e0    cbnz	x22, add_syscall         */ \
WRITE_INSTR(0xd2807d00); /* 0xfffffff0090a33e4    mov	x0, #0x3e8                */ \
WRITE_INSTR(0x52800101); /* 0xfffffff0090a33e8    mov	w1, #0x8                  */ \
WRITE_INSTR(0x9b017c00); /* 0xfffffff0090a33ec    mul	x0, x0, x1                */ \
WRITE_INSTR(0xf900afe0); /* 0xfffffff0090a33f0    str	x0, [sp, #0x158]          */ \
WRITE_INSTR(0x910563e0); /* 0xfffffff0090a33f4    add	x0, sp, #0x158            */ \
WRITE_INSTR(0x2a1f03e1); /* 0xfffffff0090a33f8    mov	w1, wzr                   */ \
WRITE_INSTR(0xaa1f03e2); /* 0xfffffff0090a33fc    mov	x2, xzr                   */ \
WRITE_INSTR(0xf940b7f6); /* 0xfffffff0090a3400    ldr	x22, [sp, #0x168]         */ \
WRITE_INSTR(0xd63f02c0); /* 0xfffffff0090a3404    blr	x22                       */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a3408    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000420); /* 0xfffffff0090a340c    b.eq	out_enomem               */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0090a3410    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf90006c0); /* 0xfffffff0090a3414    str	x0, [x22, #0x8]           */ \
WRITE_INSTR(0x52800017); /* 0xfffffff0090a3418    mov	w23, #0x0                 */ \
WRITE_INSTR(0xaa0003f8); /* 0xfffffff0090a341c    mov	x24, x0                   */ \
WRITE_INSTR(0xd2880019); /* 0xfffffff0090a3420    mov	x25, #0x4000              */ \
/*                                           call_list_init_loop:               */ \
WRITE_INSTR(0xf9000319); /* 0xfffffff0090a3424    str	x25, [x24]                */ \
WRITE_INSTR(0x110006f7); /* 0xfffffff0090a3428    add	w23, w23, #0x1            */ \
WRITE_INSTR(0x710fa2ff); /* 0xfffffff0090a342c    cmp	w23, #0x3e8               */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0090a3430    b.ge	add_syscall              */ \
WRITE_INSTR(0x8b376c18); /* 0xfffffff0090a3434    add	x24, x0, x23, uxtx #3     */ \
WRITE_INSTR(0x17fffffb); /* 0xfffffff0090a3438    b	call_list_init_loop         */ \
/*                                           add_syscall:                       */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0090a343c    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf94006c0); /* 0xfffffff0090a3440    ldr	x0, [x22, #0x8]           */ \
WRITE_INSTR(0x9400004b); /* 0xfffffff0090a3444    bl	_get_call_list_free_slot   */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a3448    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540001a0); /* 0xfffffff0090a344c    b.eq	out_einval               */ \
WRITE_INSTR(0xb9801296); /* 0xfffffff0090a3450    ldrsw	x22, [x20, #0x10]       */ \
WRITE_INSTR(0xf9000016); /* 0xfffffff0090a3454    str	x22, [x0]                 */ \
WRITE_INSTR(0x1400001a); /* 0xfffffff0090a3458    b	success                     */ \
/*                                           delete_syscall:                    */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0090a345c    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf94006c0); /* 0xfffffff0090a3460    ldr	x0, [x22, #0x8]           */ \
WRITE_INSTR(0xb9801281); /* 0xfffffff0090a3464    ldrsw	x1, [x20, #0x10]        */ \
WRITE_INSTR(0x94000050); /* 0xfffffff0090a3468    bl	_find_call_list_slot       */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0090a346c    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0090a3470    b.eq	out_einval               */ \
WRITE_INSTR(0xd2880016); /* 0xfffffff0090a3474    mov	x22, #0x4000              */ \
WRITE_INSTR(0xf9000016); /* 0xfffffff0090a3478    str	x22, [x0]                 */ \
WRITE_INSTR(0x14000011); /* 0xfffffff0090a347c    b	success                     */ \
/*                                           out_einval:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0090a3480    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0090a3484    str	w0, [x21]                 */ \
WRITE_INSTR(0x528002c0); /* 0xfffffff0090a3488    mov	w0, #0x16                 */ \
WRITE_INSTR(0x1400000f); /* 0xfffffff0090a348c    b	done                        */ \
/*                                           out_enomem:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0090a3490    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0090a3494    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800180); /* 0xfffffff0090a3498    mov	w0, #0xc                  */ \
WRITE_INSTR(0x1400000b); /* 0xfffffff0090a349c    b	done                        */ \
/*                                           out_patched:                       */ \
WRITE_INSTR(0x52807ce0); /* 0xfffffff0090a34a0    mov	w0, #0x3e7                */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0090a34a4    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0090a34a8    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000007); /* 0xfffffff0090a34ac    b	done                        */ \
/*                                           out_givetablekaddr:                */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0090a34b0    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0xf90002a0); /* 0xfffffff0090a34b4    str	x0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0090a34b8    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000003); /* 0xfffffff0090a34bc    b	done                        */ \
/*                                           success:                           */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0090a34c0    mov	w0, #0x0                  */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0090a34c4    str	w0, [x21]                 */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0090a34c8    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0090a34cc    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0090a34d0    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0090a34d4    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0090a34d8    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0090a34dc    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0090a34e0    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a34e4    ret                           */ \
/*                                           _stalker_ctl_from_table:           */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0090a34e8    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0090a34ec    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0090a34f0    b.eq	not_found0               */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0090a34f4    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0090a34f8    add	x11, x0, x10, uxtx #4     */ \
/*                                           search0:                           */ \
WRITE_INSTR(0xb940056c); /* 0xfffffff0090a34fc    ldr	w12, [x11, #0x4]          */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0090a3500    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0090a3504    b.eq	found0                   */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0090a3508    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x710ffd5f); /* 0xfffffff0090a350c    cmp	w10, #0x3ff               */ \
WRITE_INSTR(0x5400006c); /* 0xfffffff0090a3510    b.gt	not_found0               */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0090a3514    add	x11, x0, x10, uxtx #4     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0090a3518    b	search0                     */ \
/*                                           not_found0:                        */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0090a351c    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a3520    ret                           */ \
/*                                           found0:                            */ \
WRITE_INSTR(0xaa0b03e0); /* 0xfffffff0090a3524    mov	x0, x11                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a3528    ret                           */ \
/*                                           _get_nearest_free_stalker_ctl:     */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0090a352c    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x710ffd3f); /* 0xfffffff0090a3530    cmp	w9, #0x3ff                */ \
WRITE_INSTR(0x540001aa); /* 0xfffffff0090a3534    b.ge	nofree0                  */ \
WRITE_INSTR(0x52800029); /* 0xfffffff0090a3538    mov	w9, #0x1                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0090a353c    add	x10, x0, x9, uxtx #4      */ \
/*                                           freeloop0:                         */ \
WRITE_INSTR(0xb940014b); /* 0xfffffff0090a3540    ldr	w11, [x10]                */ \
WRITE_INSTR(0x7100057f); /* 0xfffffff0090a3544    cmp	w11, #0x1                 */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0090a3548    b.eq	foundfree0               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0090a354c    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710ffd3f); /* 0xfffffff0090a3550    cmp	w9, #0x3ff                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0090a3554    b.ge	nofree0                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0090a3558    add	x10, x0, x9, uxtx #4      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0090a355c    b	freeloop0                   */ \
/*                                           foundfree0:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0090a3560    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a3564    ret                           */ \
/*                                           nofree0:                           */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0090a3568    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a356c    ret                           */ \
/*                                           _get_call_list_free_slot:          */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0090a3570    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0090a3574    mov	x10, x0                   */ \
/*                                           freeloop1:                         */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0090a3578    ldr	x11, [x10]                */ \
WRITE_INSTR(0xf140117f); /* 0xfffffff0090a357c    cmp	x11, #0x4, lsl #12        */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0090a3580    b.eq	foundfree1               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0090a3584    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0090a3588    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0090a358c    b.ge	nofree1                  */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0090a3590    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0090a3594    b	freeloop1                   */ \
/*                                           foundfree1:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0090a3598    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a359c    ret                           */ \
/*                                           nofree1:                           */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0090a35a0    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a35a4    ret                           */ \
/*                                           _find_call_list_slot:              */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0090a35a8    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0090a35ac    mov	x10, x0                   */ \
/*                                           slotloop:                          */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0090a35b0    ldr	x11, [x10]                */ \
WRITE_INSTR(0xeb01017f); /* 0xfffffff0090a35b4    cmp	x11, x1                   */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0090a35b8    b.eq	found                    */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0090a35bc    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0090a35c0    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0090a35c4    b.ge	notfound                 */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0090a35c8    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0090a35cc    b	slotloop                    */ \
/*                                           found:                             */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0090a35d0    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a35d4    ret                           */ \
/*                                           notfound:                          */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0090a35d8    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0090a35dc    ret                           */ 
const static int g_svc_stalker_ctl_num_instrs = 208;
#endif
