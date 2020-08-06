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
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b72b0    b.eq	check_if_patched         */ \
WRITE_INSTR(0x710006df); /* 0xfffffff0156b72b4    cmp	w22, #0x1                 */ \
WRITE_INSTR(0x54000620); /* 0xfffffff0156b72b8    b.eq	syscall_manage           */ \
WRITE_INSTR(0x71000adf); /* 0xfffffff0156b72bc    cmp	w22, #0x2                 */ \
WRITE_INSTR(0x54000d80); /* 0xfffffff0156b72c0    b.eq	out_givetablekaddr       */ \
WRITE_INSTR(0x1400005f); /* 0xfffffff0156b72c4    b	out_einval                  */ \
/*                                           check_if_patched:                  */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b72c8    ldr	w22, [x20]                */ \
WRITE_INSTR(0x310006df); /* 0xfffffff0156b72cc    cmn	w22, #0x1                 */ \
WRITE_INSTR(0x54000c80); /* 0xfffffff0156b72d0    b.eq	out_patched              */ \
/*                                           pid_manage:                        */ \
WRITE_INSTR(0x54000b6b); /* 0xfffffff0156b72d4    b.lt	out_einval               */ \
WRITE_INSTR(0xb9401297); /* 0xfffffff0156b72d8    ldr	w23, [x20, #0x10]         */ \
WRITE_INSTR(0x35000057); /* 0xfffffff0156b72dc    cbnz	w23, add_pid             */ \
WRITE_INSTR(0x14000012); /* 0xfffffff0156b72e0    b	delete_pid                  */ \
/*                                           add_pid:                           */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b72e4    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0156b72e8    mov	w1, w22                   */ \
WRITE_INSTR(0x9400006f); /* 0xfffffff0156b72ec    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72f0    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000c61); /* 0xfffffff0156b72f4    b.ne	success                  */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b72f8    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x9400007c); /* 0xfffffff0156b72fc    bl	_get_nearest_free_stalker_ctl*/ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7300    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540009e0); /* 0xfffffff0156b7304    b.eq	out_einval               */ \
WRITE_INSTR(0xb900001f); /* 0xfffffff0156b7308    str	wzr, [x0]                 */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b730c    ldr	w22, [x20]                */ \
WRITE_INSTR(0xb9000416); /* 0xfffffff0156b7310    str	w22, [x0, #0x4]           */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0156b7314    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0156b7318    ldr	w23, [x22]                */ \
WRITE_INSTR(0x110006f7); /* 0xfffffff0156b731c    add	w23, w23, #0x1            */ \
WRITE_INSTR(0xb90002d7); /* 0xfffffff0156b7320    str	w23, [x22]                */ \
WRITE_INSTR(0x14000057); /* 0xfffffff0156b7324    b	success                     */ \
/*                                           delete_pid:                        */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b7328    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x2a1603e1); /* 0xfffffff0156b732c    mov	w1, w22                   */ \
WRITE_INSTR(0x9400005e); /* 0xfffffff0156b7330    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7334    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000840); /* 0xfffffff0156b7338    b.eq	out_einval               */ \
WRITE_INSTR(0x52800036); /* 0xfffffff0156b733c    mov	w22, #0x1                 */ \
WRITE_INSTR(0xb9000016); /* 0xfffffff0156b7340    str	w22, [x0]                 */ \
WRITE_INSTR(0xb900041f); /* 0xfffffff0156b7344    str	wzr, [x0, #0x4]           */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0156b7348    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0156b734c    ldr	w23, [x22]                */ \
WRITE_INSTR(0x510006f7); /* 0xfffffff0156b7350    sub	w23, w23, #0x1            */ \
WRITE_INSTR(0xb90002d7); /* 0xfffffff0156b7354    str	w23, [x22]                */ \
WRITE_INSTR(0xf9400416); /* 0xfffffff0156b7358    ldr	x22, [x0, #0x8]           */ \
WRITE_INSTR(0xf10002df); /* 0xfffffff0156b735c    cmp	x22, #0x0                 */ \
WRITE_INSTR(0x54000900); /* 0xfffffff0156b7360    b.eq	success                  */ \
WRITE_INSTR(0xaa0003f7); /* 0xfffffff0156b7364    mov	x23, x0                   */ \
WRITE_INSTR(0xaa1603e0); /* 0xfffffff0156b7368    mov	x0, x22                   */ \
WRITE_INSTR(0xf940b3f6); /* 0xfffffff0156b736c    ldr	x22, [sp, #0x160]         */ \
WRITE_INSTR(0xd63f02c0); /* 0xfffffff0156b7370    blr	x22                       */ \
WRITE_INSTR(0xf90006ff); /* 0xfffffff0156b7374    str	xzr, [x23, #0x8]          */ \
WRITE_INSTR(0x14000042); /* 0xfffffff0156b7378    b	success                     */ \
/*                                           syscall_manage:                    */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b737c    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0xb9400281); /* 0xfffffff0156b7380    ldr	w1, [x20]                 */ \
WRITE_INSTR(0x94000049); /* 0xfffffff0156b7384    bl	_stalker_ctl_from_table    */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7388    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540005a0); /* 0xfffffff0156b738c    b.eq	out_einval               */ \
WRITE_INSTR(0xf900abe0); /* 0xfffffff0156b7390    str	x0, [sp, #0x150]          */ \
WRITE_INSTR(0xb9401a96); /* 0xfffffff0156b7394    ldr	w22, [x20, #0x18]         */ \
WRITE_INSTR(0x34000436); /* 0xfffffff0156b7398    cbz	w22, delete_syscall       */ \
WRITE_INSTR(0xf9400416); /* 0xfffffff0156b739c    ldr	x22, [x0, #0x8]           */ \
WRITE_INSTR(0xb50002f6); /* 0xfffffff0156b73a0    cbnz	x22, add_syscall         */ \
WRITE_INSTR(0xd2807d00); /* 0xfffffff0156b73a4    mov	x0, #0x3e8                */ \
WRITE_INSTR(0x52800101); /* 0xfffffff0156b73a8    mov	w1, #0x8                  */ \
WRITE_INSTR(0x9b017c00); /* 0xfffffff0156b73ac    mul	x0, x0, x1                */ \
WRITE_INSTR(0xf900afe0); /* 0xfffffff0156b73b0    str	x0, [sp, #0x158]          */ \
WRITE_INSTR(0x910563e0); /* 0xfffffff0156b73b4    add	x0, sp, #0x158            */ \
WRITE_INSTR(0x2a1f03e1); /* 0xfffffff0156b73b8    mov	w1, wzr                   */ \
WRITE_INSTR(0xaa1f03e2); /* 0xfffffff0156b73bc    mov	x2, xzr                   */ \
WRITE_INSTR(0xf940b7f6); /* 0xfffffff0156b73c0    ldr	x22, [sp, #0x168]         */ \
WRITE_INSTR(0xd63f02c0); /* 0xfffffff0156b73c4    blr	x22                       */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b73c8    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000420); /* 0xfffffff0156b73cc    b.eq	out_enomem               */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0156b73d0    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf90006c0); /* 0xfffffff0156b73d4    str	x0, [x22, #0x8]           */ \
WRITE_INSTR(0x52800017); /* 0xfffffff0156b73d8    mov	w23, #0x0                 */ \
WRITE_INSTR(0xaa0003f8); /* 0xfffffff0156b73dc    mov	x24, x0                   */ \
WRITE_INSTR(0xd2880019); /* 0xfffffff0156b73e0    mov	x25, #0x4000              */ \
/*                                           call_list_init_loop:               */ \
WRITE_INSTR(0xf9000319); /* 0xfffffff0156b73e4    str	x25, [x24]                */ \
WRITE_INSTR(0x110006f7); /* 0xfffffff0156b73e8    add	w23, w23, #0x1            */ \
WRITE_INSTR(0x710fa2ff); /* 0xfffffff0156b73ec    cmp	w23, #0x3e8               */ \
WRITE_INSTR(0x5400006a); /* 0xfffffff0156b73f0    b.ge	add_syscall              */ \
WRITE_INSTR(0x8b376c18); /* 0xfffffff0156b73f4    add	x24, x0, x23, uxtx #3     */ \
WRITE_INSTR(0x17fffffb); /* 0xfffffff0156b73f8    b	call_list_init_loop         */ \
/*                                           add_syscall:                       */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0156b73fc    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf94006c0); /* 0xfffffff0156b7400    ldr	x0, [x22, #0x8]           */ \
WRITE_INSTR(0x9400004b); /* 0xfffffff0156b7404    bl	_get_call_list_free_slot   */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7408    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x540001a0); /* 0xfffffff0156b740c    b.eq	out_einval               */ \
WRITE_INSTR(0xb9801296); /* 0xfffffff0156b7410    ldrsw	x22, [x20, #0x10]       */ \
WRITE_INSTR(0xf9000016); /* 0xfffffff0156b7414    str	x22, [x0]                 */ \
WRITE_INSTR(0x1400001a); /* 0xfffffff0156b7418    b	success                     */ \
/*                                           delete_syscall:                    */ \
WRITE_INSTR(0xf940abf6); /* 0xfffffff0156b741c    ldr	x22, [sp, #0x150]         */ \
WRITE_INSTR(0xf94006c0); /* 0xfffffff0156b7420    ldr	x0, [x22, #0x8]           */ \
WRITE_INSTR(0xb9801281); /* 0xfffffff0156b7424    ldrsw	x1, [x20, #0x10]        */ \
WRITE_INSTR(0x94000050); /* 0xfffffff0156b7428    bl	_find_call_list_slot       */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b742c    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0156b7430    b.eq	out_einval               */ \
WRITE_INSTR(0xd2880016); /* 0xfffffff0156b7434    mov	x22, #0x4000              */ \
WRITE_INSTR(0xf9000016); /* 0xfffffff0156b7438    str	x22, [x0]                 */ \
WRITE_INSTR(0x14000011); /* 0xfffffff0156b743c    b	success                     */ \
/*                                           out_einval:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b7440    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b7444    str	w0, [x21]                 */ \
WRITE_INSTR(0x528002c0); /* 0xfffffff0156b7448    mov	w0, #0x16                 */ \
WRITE_INSTR(0x1400000f); /* 0xfffffff0156b744c    b	done                        */ \
/*                                           out_enomem:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b7450    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b7454    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800180); /* 0xfffffff0156b7458    mov	w0, #0xc                  */ \
WRITE_INSTR(0x1400000b); /* 0xfffffff0156b745c    b	done                        */ \
/*                                           out_patched:                       */ \
WRITE_INSTR(0x52807ce0); /* 0xfffffff0156b7460    mov	w0, #0x3e7                */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b7464    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7468    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000007); /* 0xfffffff0156b746c    b	done                        */ \
/*                                           out_givetablekaddr:                */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b7470    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0xf90002a0); /* 0xfffffff0156b7474    str	x0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7478    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000003); /* 0xfffffff0156b747c    b	done                        */ \
/*                                           success:                           */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7480    mov	w0, #0x0                  */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b7484    str	w0, [x21]                 */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b7488    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b748c    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b7490    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b7494    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b7498    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b749c    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b74a0    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74a4    ret                           */ \
/*                                           _stalker_ctl_from_table:           */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b74a8    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0156b74ac    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b74b0    b.eq	not_found0               */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0156b74b4    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b74b8    add	x11, x0, x10, uxtx #4     */ \
/*                                           search0:                           */ \
WRITE_INSTR(0xb940056c); /* 0xfffffff0156b74bc    ldr	w12, [x11, #0x4]          */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0156b74c0    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b74c4    b.eq	found0                   */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0156b74c8    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x710ffd5f); /* 0xfffffff0156b74cc    cmp	w10, #0x3ff               */ \
WRITE_INSTR(0x5400006c); /* 0xfffffff0156b74d0    b.gt	not_found0               */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b74d4    add	x11, x0, x10, uxtx #4     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b74d8    b	search0                     */ \
/*                                           not_found0:                        */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b74dc    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74e0    ret                           */ \
/*                                           found0:                            */ \
WRITE_INSTR(0xaa0b03e0); /* 0xfffffff0156b74e4    mov	x0, x11                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b74e8    ret                           */ \
/*                                           _get_nearest_free_stalker_ctl:     */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b74ec    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x710ffd3f); /* 0xfffffff0156b74f0    cmp	w9, #0x3ff                */ \
WRITE_INSTR(0x540001aa); /* 0xfffffff0156b74f4    b.ge	nofree0                  */ \
WRITE_INSTR(0x52800029); /* 0xfffffff0156b74f8    mov	w9, #0x1                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0156b74fc    add	x10, x0, x9, uxtx #4      */ \
/*                                           freeloop0:                         */ \
WRITE_INSTR(0xb940014b); /* 0xfffffff0156b7500    ldr	w11, [x10]                */ \
WRITE_INSTR(0x7100057f); /* 0xfffffff0156b7504    cmp	w11, #0x1                 */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b7508    b.eq	foundfree0               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b750c    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710ffd3f); /* 0xfffffff0156b7510    cmp	w9, #0x3ff                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0156b7514    b.ge	nofree0                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0156b7518    add	x10, x0, x9, uxtx #4      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b751c    b	freeloop0                   */ \
/*                                           foundfree0:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b7520    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7524    ret                           */ \
/*                                           nofree0:                           */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7528    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b752c    ret                           */ \
/*                                           _get_call_list_free_slot:          */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0156b7530    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0156b7534    mov	x10, x0                   */ \
/*                                           freeloop1:                         */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0156b7538    ldr	x11, [x10]                */ \
WRITE_INSTR(0xf140117f); /* 0xfffffff0156b753c    cmp	x11, #0x4, lsl #12        */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b7540    b.eq	foundfree1               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b7544    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0156b7548    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0156b754c    b.ge	nofree1                  */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0156b7550    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b7554    b	freeloop1                   */ \
/*                                           foundfree1:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b7558    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b755c    ret                           */ \
/*                                           nofree1:                           */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7560    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7564    ret                           */ \
/*                                           _find_call_list_slot:              */ \
WRITE_INSTR(0x52800009); /* 0xfffffff0156b7568    mov	w9, #0x0                  */ \
WRITE_INSTR(0xaa0003ea); /* 0xfffffff0156b756c    mov	x10, x0                   */ \
/*                                           slotloop:                          */ \
WRITE_INSTR(0xf940014b); /* 0xfffffff0156b7570    ldr	x11, [x10]                */ \
WRITE_INSTR(0xeb01017f); /* 0xfffffff0156b7574    cmp	x11, x1                   */ \
WRITE_INSTR(0x540000c0); /* 0xfffffff0156b7578    b.eq	found                    */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b757c    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x710fa13f); /* 0xfffffff0156b7580    cmp	w9, #0x3e8                */ \
WRITE_INSTR(0x540000aa); /* 0xfffffff0156b7584    b.ge	notfound                 */ \
WRITE_INSTR(0x8b296c0a); /* 0xfffffff0156b7588    add	x10, x0, x9, uxtx #3      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b758c    b	slotloop                    */ \
/*                                           found:                             */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b7590    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7594    ret                           */ \
/*                                           notfound:                          */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7598    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b759c    ret                           */ 
#endif
