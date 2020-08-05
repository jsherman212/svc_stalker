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
/*                                           out_einval:                        */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b72a8    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b72ac    str	w0, [x21]                 */ \
WRITE_INSTR(0x528002c0); /* 0xfffffff0156b72b0    mov	w0, #0x16                 */ \
WRITE_INSTR(0x14000003); /* 0xfffffff0156b72b4    b	done                        */ \
/*                                           success:                           */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b72b8    mov	w0, #0x0                  */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b72bc    str	w0, [x21]                 */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b72c0    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b72c4    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b72c8    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b72cc    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b72d0    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b72d4    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b72d8    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b72dc    ret                           */ \
/*                                           _stalker_ctl_from_table:           */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b72e0    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0156b72e4    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b72e8    b.eq	not_found0               */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0156b72ec    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b72f0    add	x11, x0, x10, uxtx #4     */ \
/*                                           search0:                           */ \
WRITE_INSTR(0xb940056c); /* 0xfffffff0156b72f4    ldr	w12, [x11, #0x4]          */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0156b72f8    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b72fc    b.eq	found0                   */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0156b7300    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x710ffd5f); /* 0xfffffff0156b7304    cmp	w10, #0x3ff               */ \
WRITE_INSTR(0x5400006c); /* 0xfffffff0156b7308    b.gt	not_found0               */ \
WRITE_INSTR(0x8b2a700b); /* 0xfffffff0156b730c    add	x11, x0, x10, uxtx #4     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b7310    b	search0                     */ \
/*                                           not_found0:                        */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7314    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7318    ret                           */ \
/*                                           found0:                            */ \
WRITE_INSTR(0xaa0b03e0); /* 0xfffffff0156b731c    mov	x0, x11                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7320    ret                           */ \
/*                                           _get_nearest_free_stalker_ctl:     */ \
WRITE_INSTR(0x52800029); /* 0xfffffff0156b7324    mov	w9, #0x1                  */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0156b7328    add	x10, x0, x9, uxtx #4      */ \
/*                                           freeloop:                          */ \
WRITE_INSTR(0xb940014b); /* 0xfffffff0156b732c    ldr	w11, [x10]                */ \
WRITE_INSTR(0x7100057f); /* 0xfffffff0156b7330    cmp	w11, #0x1                 */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0156b7334    b.eq	foundfree                */ \
WRITE_INSTR(0x11000529); /* 0xfffffff0156b7338    add	w9, w9, #0x1              */ \
WRITE_INSTR(0x8b29700a); /* 0xfffffff0156b733c    add	x10, x0, x9, uxtx #4      */ \
WRITE_INSTR(0x17fffffb); /* 0xfffffff0156b7340    b	freeloop                    */ \
/*                                           foundfree:                         */ \
WRITE_INSTR(0xaa0a03e0); /* 0xfffffff0156b7344    mov	x0, x10                   */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7348    ret                           */ 
#endif
