#ifndef svc_stalker_ctl
#define svc_stalker_ctl
#define DO_SVC_STALKER_CTL_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0156b7250    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a6ffc); /* 0xfffffff0156b7254    stp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0xa91b67fa); /* 0xfffffff0156b7258    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa91c5ff8); /* 0xfffffff0156b725c    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa91d57f6); /* 0xfffffff0156b7260    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa91e4ff4); /* 0xfffffff0156b7264    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa91f7bfd); /* 0xfffffff0156b7268    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0x9107c3fd); /* 0xfffffff0156b726c    add	x29, sp, #0x1f0           */ \
WRITE_INSTR(0xaa0003f3); /* 0xfffffff0156b7270    mov	x19, x0                   */ \
WRITE_INSTR(0xaa0103f4); /* 0xfffffff0156b7274    mov	x20, x1                   */ \
WRITE_INSTR(0xaa0203f5); /* 0xfffffff0156b7278    mov	x21, x2                   */ \
WRITE_INSTR(0x10fffd76); /* 0xfffffff0156b727c    adr	x22, #-0x54               */ \
WRITE_INSTR(0xf94002d7); /* 0xfffffff0156b7280    ldr	x23, [x22]                */ \
WRITE_INSTR(0xf900c7f7); /* 0xfffffff0156b7284    str	x23, [sp, #0x188]         */ \
WRITE_INSTR(0xf94006d7); /* 0xfffffff0156b7288    ldr	x23, [x22, #0x8]          */ \
WRITE_INSTR(0xf900bff7); /* 0xfffffff0156b728c    str	x23, [sp, #0x178]         */ \
WRITE_INSTR(0xf9400ad7); /* 0xfffffff0156b7290    ldr	x23, [x22, #0x10]         */ \
WRITE_INSTR(0xf900bbf7); /* 0xfffffff0156b7294    str	x23, [sp, #0x170]         */ \
WRITE_INSTR(0xf9400ed7); /* 0xfffffff0156b7298    ldr	x23, [x22, #0x18]         */ \
WRITE_INSTR(0xf900b7f7); /* 0xfffffff0156b729c    str	x23, [sp, #0x168]         */ \
WRITE_INSTR(0xf94012d7); /* 0xfffffff0156b72a0    ldr	x23, [x22, #0x20]         */ \
WRITE_INSTR(0xf900b3f7); /* 0xfffffff0156b72a4    str	x23, [sp, #0x160]         */ \
WRITE_INSTR(0xb9400a96); /* 0xfffffff0156b72a8    ldr	w22, [x20, #0x8]          */ \
WRITE_INSTR(0x710002df); /* 0xfffffff0156b72ac    cmp	w22, #0x0                 */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0156b72b0    b.eq	check_if_patched         */ \
WRITE_INSTR(0x710006df); /* 0xfffffff0156b72b4    cmp	w22, #0x1                 */ \
WRITE_INSTR(0x540004e0); /* 0xfffffff0156b72b8    b.eq	syscall_manage           */ \
WRITE_INSTR(0x14000057); /* 0xfffffff0156b72bc    b	out_einval                  */ \
/*                                           check_if_patched:                  */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b72c0    ldr	w22, [x20]                */ \
WRITE_INSTR(0x310006df); /* 0xfffffff0156b72c4    cmn	w22, #0x1                 */ \
WRITE_INSTR(0x54000b80); /* 0xfffffff0156b72c8    b.eq	out_patched              */ \
/*                                           pid_manage:                        */ \
WRITE_INSTR(0x54000a6b); /* 0xfffffff0156b72cc    b.lt	out_einval               */ \
WRITE_INSTR(0xb9401297); /* 0xfffffff0156b72d0    ldr	w23, [x20, #0x10]         */ \
WRITE_INSTR(0x35000057); /* 0xfffffff0156b72d4    cbnz	w23, add_pid             */ \
WRITE_INSTR(0x1400000e); /* 0xfffffff0156b72d8    b	delete_pid                  */ \
/*                                           add_pid:                           */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b72dc    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0156b72e0    mov	w1, w22                   */ \
WRITE_INSTR(0x94000063); /* 0xfffffff0156b72e4    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72e8    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000ae1); /* 0xfffffff0156b72ec    b.ne	success                  */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b72f0    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x94000070); /* 0xfffffff0156b72f4    bl	_get_nearest_free_stalker_ctl*/ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72f8    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540008e0); /* 0xfffffff0156b72fc    b.eq	out_einval               */ \
WRITE_INSTR(0xb900001f); /* 0xfffffff0156b7300    str	wzr, [x0]                 */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b7304    ldr	w22, [x20]                */ \
WRITE_INSTR(0xb9000416); /* 0xfffffff0156b7308    str	w22, [x0, #0x4]           */ \
WRITE_INSTR(0x1400004f); /* 0xfffffff0156b730c    b	success                     */ \
/*                                           delete_pid:                        */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b7310    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0156b7314    mov	w1, w22                   */ \
WRITE_INSTR(0x94000056); /* 0xfffffff0156b7318    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b731c    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540007c0); /* 0xfffffff0156b7320    b.eq	out_einval               */ \
WRITE_INSTR(0x52800036); /* 0xfffffff0156b7324    mov	w22, #0x1                 */ \
WRITE_INSTR(0xb9000016); /* 0xfffffff0156b7328    str	w22, [x0]                 */ \
WRITE_INSTR(0xb900041f); /* 0xfffffff0156b732c    str	wzr, [x0, #0x4]           */ \
WRITE_INSTR(0xf9400416); /* 0xfffffff0156b7330    ldr	x22, [x0, #0x8]           */ \
WRITE_INSTR(0xf10002df); /* 0xfffffff0156b7334    cmp	x22, #0x0                 */ \
WRITE_INSTR(0x54000880); /* 0xfffffff0156b7338    b.eq	success                  */ \
WRITE_INSTR(0xaa0003f7); /* 0xfffffff0156b733c    mov	x23, x0                   */ \
WRITE_INSTR(0xaa1603e0); /* 0xfffffff0156b7340    mov	x0, x22                   */ \
WRITE_INSTR(0xf940b3f6); /* 0xfffffff0156b7344    ldr	x22, [sp, #0x160]         */ \
WRITE_INSTR(0xd63f02c0); /* 0xfffffff0156b7348    blr	x22                       */ \
WRITE_INSTR(0xf90006ff); /* 0xfffffff0156b734c    str	xzr, [x23, #0x8]          */ \
WRITE_INSTR(0x1400003e); /* 0xfffffff0156b7350    b	success                     */ \
/*                                           syscall_manage:                    */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b7354    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0156b7358    mov	w1, w22                   */ \
WRITE_INSTR(0x94000045); /* 0xfffffff0156b735c    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7360    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540005a0); /* 0xfffffff0156b7364    b.eq	out_einval               */ \
WRITE_INSTR(0xf900abe0); /* 0xfffffff0156b7368    str	x0, [sp, #0x150]          */ \
WRITE_INSTR(0xb9401a96); /* 0xfffffff0156b736c    ldr	w22, [x20, #0x18]         */ \
WRITE_INSTR(0x34000436); /* 0xfffffff0156b7370    cbz	w22, delete_syscall       */ \
WRITE_INSTR(0xf9400416); /* 0xfffffff0156b7374    ldr	x22, [x0, #0x8]           */ \
WRITE_INSTR(0xb50002f6); /* 0xfffffff0156b7378    cbnz	x22, add_syscall         */ \
WRITE_INSTR(0xd2807d00); /* 0xfffffff0156b737c    mov	x0, #0x3e8                */ \
WRITE_INSTR(0x52800101); /* 0xfffffff0156b7380    mov	w1, #0x8                  */ \
WRITE_INSTR(0x9b017c00); /* 0xfffffff0156b7384    mul	x0, x0, x1                */ \
WRITE_INSTR(0xf900afe0); /* 0xfffffff0156b7388    str	x0, [sp, #0x158]          */ \
WRITE_INSTR(0x910563e0); /* 0xfffffff0156b738c    add	x0, sp, #0x158            */ \
WRITE_INSTR(0x2a1f03e1); /* 0xfffffff0156b7390    mov	w1, wzr                   */ \
WRITE_INSTR(0xaa1f03e2); /* 0xfffffff0156b7394    mov	x2, xzr                   */ \
WRITE_INSTR(0xf940b7f6); /* 0xfffffff0156b7398    ldr	x22, [sp, #0x168]         */ \
WRITE_INSTR(0xd63f02c0); /* 0xfffffff0156b739c    blr	x22                       */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b73a0    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000420); /* 0xfffffff0156b73a4    b.eq	out_enomem               */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0156b73a8    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf90006c0); /* 0xfffffff0156b73ac    str	x0, [x22, #0x8]           */ \
WRITE_INSTR(0x52800017); /* 0xfffffff0156b73b0    mov	w23, #0x0                 */ \
WRITE_INSTR(0xaa0003f8); /* 0xfffffff0156b73b4    mov	x24, x0                   */ \
WRITE_INSTR(0xd2880019); /* 0xfffffff0156b73b8    mov	x25, #0x4000              */ \
/*                                           call_list_init_loop:               */ \
WRITE_INSTR(0xf9000319); /* 0xfffffff0156b73bc    str	x25, [x24]                */ \
WRITE_INSTR(0x110006f7); /* 0xfffffff0156b73c0    add	w23, w23, #0x1            */ \
WRITE_INSTR(0x710fa2ff); /* 0xfffffff0156b73c4    cmp	w23, #0x3e8               */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0156b73c8    b.ge	add_syscall              */ \
WRITE_INSTR(0x8b376c18); /* 0xfffffff0156b73cc    add	x24, x0, x23, uxtx #3     */ \
WRITE_INSTR(0x17fffffb); /* 0xfffffff0156b73d0    b	call_list_init_loop         */ \
/*                                           add_syscall:                       */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0156b73d4    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf94006c0); /* 0xfffffff0156b73d8    ldr	x0, [x22, #0x8]           */ \
WRITE_INSTR(0x94000047); /* 0xfffffff0156b73dc    bl	_get_call_list_free_slot   */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b73e0    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540001a0); /* 0xfffffff0156b73e4    b.eq	out_einval               */ \
WRITE_INSTR(0xb9401296); /* 0xfffffff0156b73e8    ldr	w22, [x20, #0x10]         */ \
WRITE_INSTR(0xb9000016); /* 0xfffffff0156b73ec    str	w22, [x0]                 */ \
WRITE_INSTR(0x14000016); /* 0xfffffff0156b73f0    b	success                     */ \
/*                                           delete_syscall:                    */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0156b73f4    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf94006c0); /* 0xfffffff0156b73f8    ldr	x0, [x22, #0x8]           */ \
WRITE_INSTR(0xf9400a81); /* 0xfffffff0156b73fc    ldr	x1, [x20, #0x10]          */ \
WRITE_INSTR(0x9400004c); /* 0xfffffff0156b7400    bl	_find_call_list_slot       */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7404    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0156b7408    b.eq	out_einval               */ \
WRITE_INSTR(0xd2880016); /* 0xfffffff0156b740c    mov	x22, #0x4000              */ \
WRITE_INSTR(0xf9000016); /* 0xfffffff0156b7410    str	x22, [x0]                 */ \
WRITE_INSTR(0x1400000d); /* 0xfffffff0156b7414    b	success                     */ \
/*                                           out_einval:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b7418    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b741c    str	w0, [x21]                 */ \
WRITE_INSTR(0x528002c0); /* 0xfffffff0156b7420    mov	w0, #0x16                 */ \
WRITE_INSTR(0x1400000b); /* 0xfffffff0156b7424    b	done                        */ \
/*                                           out_enomem:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b7428    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b742c    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800180); /* 0xfffffff0156b7430    mov	w0, #0xc                  */ \
WRITE_INSTR(0x14000007); /* 0xfffffff0156b7434    b	done                        */ \
/*                                           out_patched:                       */ \
WRITE_INSTR(0x52807ce0); /* 0xfffffff0156b7438    mov	w0, #0x3e7                */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b743c    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7440    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000003); /* 0xfffffff0156b7444    b	done                        */ \
/*                                           success:                           */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7448    mov	w0, #0x0                  */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b744c    str	w0, [x21]                 */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b7450    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b7454    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b7458    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b745c    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b7460    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b7464    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b7468    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b746c    ret                           */ \
/*                                           _stalker_ctl_from_table:           */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b7470    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0156b7474    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b7478    b.eq	not_found0               */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0156b747c    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b7480    add	x11, x0, x10, uxtx #4     */ \
/*                                           search0:                           */ \
WRITE_INSTR(0xb940056c); /* 0xfffffff0156b7484    ldr	w12, [x11, #0x4]          */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0156b7488    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b748c    b.eq	found0                   */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0156b7490    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x710ffd5f); /* 0xfffffff0156b7494    cmp	w10, #0x3ff               */ \
WRITE_INSTR(0x5400006c); /* 0xfffffff0156b7498    b.gt	not_found0               */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b749c    add	x11, x0, x10, uxtx #4     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b74a0    b	search0                     */ \
/*                                           not_found0:                        */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b74a4    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74a8    ret                           */ \
/*                                           found0:                            */ \
WRITE_INSTR(0xaa0b03e0); /* 0xfffffff0156b74ac    mov	x0, x11                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74b0    ret                           */ \
/*                                           _get_nearest_free_stalker_ctl:     */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b74b4    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x710ffd3f); /* 0xfffffff0156b74b8    cmp	w9, #0x3ff                */ \
WRITE_INSTR(0x540001aa); /* 0xfffffff0156b74bc    b.ge	nofree0                  */ \
WRITE_INSTR(0x52800029); /* 0xfffffff0156b74c0    mov	w9, #0x1                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0156b74c4    add	x10, x0, x9, uxtx #4      */ \
/*                                           freeloop0:                         */ \
WRITE_INSTR(0xb940014b); /* 0xfffffff0156b74c8    ldr	w11, [x10]                */ \
WRITE_INSTR(0x7100057f); /* 0xfffffff0156b74cc    cmp	w11, #0x1                 */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b74d0    b.eq	foundfree0               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b74d4    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710ffd3f); /* 0xfffffff0156b74d8    cmp	w9, #0x3ff                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0156b74dc    b.ge	nofree0                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0156b74e0    add	x10, x0, x9, uxtx #4      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b74e4    b	freeloop0                   */ \
/*                                           foundfree0:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b74e8    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74ec    ret                           */ \
/*                                           nofree0:                           */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b74f0    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74f4    ret                           */ \
/*                                           _get_call_list_free_slot:          */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0156b74f8    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0156b74fc    mov	x10, x0                   */ \
/*                                           freeloop1:                         */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0156b7500    ldr	x11, [x10]                */ \
WRITE_INSTR(0xf140117f); /* 0xfffffff0156b7504    cmp	x11, #0x4, lsl #12        */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b7508    b.eq	foundfree1               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b750c    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0156b7510    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0156b7514    b.ge	nofree1                  */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0156b7518    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b751c    b	freeloop1                   */ \
/*                                           foundfree1:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b7520    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7524    ret                           */ \
/*                                           nofree1:                           */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7528    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b752c    ret                           */ \
/*                                           _find_call_list_slot:              */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0156b7530    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0156b7534    mov	x10, x0                   */ \
/*                                           slotloop:                          */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0156b7538    ldr	x11, [x10]                */ \
WRITE_INSTR(0xeb01017f); /* 0xfffffff0156b753c    cmp	x11, x1                   */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b7540    b.eq	found                    */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b7544    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0156b7548    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0156b754c    b.ge	notfound                 */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0156b7550    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b7554    b	slotloop                    */ \
/*                                           found:                             */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b7558    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b755c    ret                           */ \
/*                                           notfound:                          */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7560    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7564    ret                           */ 
#endif
