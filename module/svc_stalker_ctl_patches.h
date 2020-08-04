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
WRITE_INSTR(0x10fffdf6); /* 0xfffffff0156b727c    adr	x22, #-0x44               */ \
WRITE_INSTR(0xf94002d7); /* 0xfffffff0156b7280    ldr	x23, [x22]                */ \
WRITE_INSTR(0xf900c7f7); /* 0xfffffff0156b7284    str	x23, [sp, #0x188]         */ \
WRITE_INSTR(0xf94006d7); /* 0xfffffff0156b7288    ldr	x23, [x22, #0x8]          */ \
WRITE_INSTR(0xf900bff7); /* 0xfffffff0156b728c    str	x23, [sp, #0x178]         */ \
WRITE_INSTR(0xf9400ad7); /* 0xfffffff0156b7290    ldr	x23, [x22, #0x10]         */ \
WRITE_INSTR(0xf900bbf7); /* 0xfffffff0156b7294    str	x23, [sp, #0x170]         */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b7298    ldr	w22, [x20]                */ \
WRITE_INSTR(0x710002df); /* 0xfffffff0156b729c    cmp	w22, #0x0                 */ \
WRITE_INSTR(0x5400048b); /* 0xfffffff0156b72a0    b.lt	maybebadpid              */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0156b72a4    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0156b72a8    ldr	w23, [x22]                */ \
WRITE_INSTR(0x713ffeff); /* 0xfffffff0156b72ac    cmp	w23, #0xfff               */ \
WRITE_INSTR(0x5400008a); /* 0xfffffff0156b72b0    b.ge	fulltable                */ \
WRITE_INSTR(0xb9400a97); /* 0xfffffff0156b72b4    ldr	w23, [x20, #0x8]          */ \
WRITE_INSTR(0x34000097); /* 0xfffffff0156b72b8    cbz	w23, remove_pid           */ \
WRITE_INSTR(0x1400000f); /* 0xfffffff0156b72bc    b	add_pid                     */ \
/*                                           fulltable:                         */ \
WRITE_INSTR(0xb9400a96); /* 0xfffffff0156b72c0    ldr	w22, [x20, #0x8]          */ \
WRITE_INSTR(0x35000436); /* 0xfffffff0156b72c4    cbnz	w22, out_einval          */ \
/*                                           remove_pid:                        */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b72c8    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0xb9400281); /* 0xfffffff0156b72cc    ldr	w1, [x20]                 */ \
WRITE_INSTR(0x9400002c); /* 0xfffffff0156b72d0    bl	_get_slot_ptr_for_pid      */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72d4    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000380); /* 0xfffffff0156b72d8    b.eq	out_einval               */ \
WRITE_INSTR(0x12800001); /* 0xfffffff0156b72dc    mov	w1, #-0x1                 */ \
WRITE_INSTR(0xb9000001); /* 0xfffffff0156b72e0    str	w1, [x0]                  */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0156b72e4    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0156b72e8    ldr	w23, [x22]                */ \
WRITE_INSTR(0x510006f7); /* 0xfffffff0156b72ec    sub	w23, w23, #0x1            */ \
WRITE_INSTR(0xb90002d7); /* 0xfffffff0156b72f0    str	w23, [x22]                */ \
WRITE_INSTR(0x14000019); /* 0xfffffff0156b72f4    b	success                     */ \
/*                                           add_pid:                           */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b72f8    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0xb9400281); /* 0xfffffff0156b72fc    ldr	w1, [x20]                 */ \
WRITE_INSTR(0x94000020); /* 0xfffffff0156b7300    bl	_get_slot_ptr_for_pid      */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b7304    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000281); /* 0xfffffff0156b7308    b.ne	success                  */ \
WRITE_INSTR(0xf940c7e0); /* 0xfffffff0156b730c    ldr	x0, [sp, #0x188]          */ \
WRITE_INSTR(0x9400002d); /* 0xfffffff0156b7310    bl	_get_nearest_empty_slot    */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b7314    ldr	w22, [x20]                */ \
WRITE_INSTR(0xb9000016); /* 0xfffffff0156b7318    str	w22, [x0]                 */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0156b731c    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d7); /* 0xfffffff0156b7320    ldr	w23, [x22]                */ \
WRITE_INSTR(0x110006f7); /* 0xfffffff0156b7324    add	w23, w23, #0x1            */ \
WRITE_INSTR(0xb90002d7); /* 0xfffffff0156b7328    str	w23, [x22]                */ \
WRITE_INSTR(0x1400000b); /* 0xfffffff0156b732c    b	success                     */ \
/*                                           maybebadpid:                       */ \
WRITE_INSTR(0x310006df); /* 0xfffffff0156b7330    cmn	w22, #0x1                 */ \
WRITE_INSTR(0x540000a1); /* 0xfffffff0156b7334    b.ne	out_einval               */ \
WRITE_INSTR(0x52807ce0); /* 0xfffffff0156b7338    mov	w0, #0x3e7                */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b733c    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7340    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000007); /* 0xfffffff0156b7344    b	done                        */ \
/*                                           out_einval:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b7348    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b734c    str	w0, [x21]                 */ \
WRITE_INSTR(0x528002c0); /* 0xfffffff0156b7350    mov	w0, #0x16                 */ \
WRITE_INSTR(0x14000003); /* 0xfffffff0156b7354    b	done                        */ \
/*                                           success:                           */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b7358    mov	w0, #0x0                  */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b735c    str	w0, [x21]                 */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b7360    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b7364    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b7368    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b736c    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b7370    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b7374    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b7378    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b737c    ret                           */ \
/*                                           _get_slot_ptr_for_pid:             */ \
WRITE_INSTR(0xb940000c); /* 0xfffffff0156b7380    ldr	w12, [x0]                 */ \
WRITE_INSTR(0x7100019f); /* 0xfffffff0156b7384    cmp	w12, #0x0                 */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b7388    b.eq	not_found                */ \
WRITE_INSTR(0x52800029); /* 0xfffffff0156b738c    mov	w9, #0x1                  */ \
WRITE_INSTR(0x8b29680a); /* 0xfffffff0156b7390    add	x10, x0, x9, uxtx #2      */ \
/*                                           slotloop:                          */ \
WRITE_INSTR(0xb940014b); /* 0xfffffff0156b7394    ldr	w11, [x10]                */ \
WRITE_INSTR(0x6b01017f); /* 0xfffffff0156b7398    cmp	w11, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b739c    b.eq	found                    */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b73a0    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x713ffd3f); /* 0xfffffff0156b73a4    cmp	w9, #0xfff                */ \
WRITE_INSTR(0x5400006c); /* 0xfffffff0156b73a8    b.gt	not_found                */ \
WRITE_INSTR(0x8b29680a); /* 0xfffffff0156b73ac    add	x10, x0, x9, uxtx #2      */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b73b0    b	slotloop                    */ \
/*                                           not_found:                         */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b73b4    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b73b8    ret                           */ \
/*                                           found:                             */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b73bc    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b73c0    ret                           */ \
/*                                           _get_nearest_empty_slot:           */ \
WRITE_INSTR(0x52800029); /* 0xfffffff0156b73c4    mov	w9, #0x1                  */ \
WRITE_INSTR(0x8b29680a); /* 0xfffffff0156b73c8    add	x10, x0, x9, uxtx #2      */ \
/*                                           emptyslotloop:                     */ \
WRITE_INSTR(0xb940014b); /* 0xfffffff0156b73cc    ldr	w11, [x10]                */ \
WRITE_INSTR(0x3100057f); /* 0xfffffff0156b73d0    cmn	w11, #0x1                 */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0156b73d4    b.eq	foundempty               */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b73d8    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x8b29680a); /* 0xfffffff0156b73dc    add	x10, x0, x9, uxtx #2      */ \
WRITE_INSTR(0x17fffffb); /* 0xfffffff0156b73e0    b	emptyslotloop               */ \
/*                                           foundempty:                        */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b73e4    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b73e8    ret                           */ 
#endif
