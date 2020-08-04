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
WRITE_INSTR(0x9400001b); /* 0xfffffff0156b72b8    bl	_pid_in_table              */ \
WRITE_INSTR(0xf100001f); /* 0xfffffff0156b72bc    cmp	x0, #0x0                  */ \
WRITE_INSTR(0x54000220); /* 0xfffffff0156b72c0    b.eq	done                     */ \
WRITE_INSTR(0xf940b7f3); /* 0xfffffff0156b72c4    ldr	x19, [sp, #0x168]         */ \
WRITE_INSTR(0xf9404673); /* 0xfffffff0156b72c8    ldr	x19, [x19, #0x88]         */ \
WRITE_INSTR(0xf1000a7f); /* 0xfffffff0156b72cc    cmp	x19, #0x2                 */ \
WRITE_INSTR(0x54000080); /* 0xfffffff0156b72d0    b.eq	send_exc_msg             */ \
WRITE_INSTR(0xf100527f); /* 0xfffffff0156b72d4    cmp	x19, #0x14                */ \
WRITE_INSTR(0x54000040); /* 0xfffffff0156b72d8    b.eq	send_exc_msg             */ \
WRITE_INSTR(0x1400000a); /* 0xfffffff0156b72dc    b	done                        */ \
/*                                           send_exc_msg:                      */ \
WRITE_INSTR(0xd2800160); /* 0xfffffff0156b72e0    mov	x0, #0xb                  */ \
WRITE_INSTR(0xf940b7e1); /* 0xfffffff0156b72e4    ldr	x1, [sp, #0x168]          */ \
WRITE_INSTR(0xf9404421); /* 0xfffffff0156b72e8    ldr	x1, [x1, #0x88]           */ \
WRITE_INSTR(0xf900b3e1); /* 0xfffffff0156b72ec    str	x1, [sp, #0x160]          */ \
WRITE_INSTR(0xf900b7ff); /* 0xfffffff0156b72f0    str	xzr, [sp, #0x168]         */ \
WRITE_INSTR(0x910583e1); /* 0xfffffff0156b72f4    add	x1, sp, #0x160            */ \
WRITE_INSTR(0x52800042); /* 0xfffffff0156b72f8    mov	w2, #0x2                  */ \
WRITE_INSTR(0xf940c7f3); /* 0xfffffff0156b72fc    ldr	x19, [sp, #0x188]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0156b7300    blr	x19                       */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b7304    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b7308    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b730c    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b7310    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b7314    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b7318    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b731c    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7320    ret                           */ \
/*                                           _pid_in_table:                     */ \
WRITE_INSTR(0xb9400009); /* 0xfffffff0156b7324    ldr	w9, [x0]                  */ \
WRITE_INSTR(0x7100013f); /* 0xfffffff0156b7328    cmp	w9, #0x0                  */ \
WRITE_INSTR(0x54000160); /* 0xfffffff0156b732c    b.eq	not_found                */ \
WRITE_INSTR(0x5280002a); /* 0xfffffff0156b7330    mov	w10, #0x1                 */ \
WRITE_INSTR(0x8b2a680b); /* 0xfffffff0156b7334    add	x11, x0, x10, uxtx #2     */ \
/*                                           search:                            */ \
WRITE_INSTR(0xb940016c); /* 0xfffffff0156b7338    ldr	w12, [x11]                */ \
WRITE_INSTR(0x6b01019f); /* 0xfffffff0156b733c    cmp	w12, w1                   */ \
WRITE_INSTR(0x54000100); /* 0xfffffff0156b7340    b.eq	found                    */ \
WRITE_INSTR(0x1100054a); /* 0xfffffff0156b7344    add	w10, w10, #0x1            */ \
WRITE_INSTR(0x713ffd5f); /* 0xfffffff0156b7348    cmp	w10, #0xfff               */ \
WRITE_INSTR(0x5400006c); /* 0xfffffff0156b734c    b.gt	not_found                */ \
WRITE_INSTR(0x8b2a680b); /* 0xfffffff0156b7350    add	x11, x0, x10, uxtx #2     */ \
WRITE_INSTR(0x17fffff9); /* 0xfffffff0156b7354    b	search                      */ \
/*                                           not_found:                         */ \
WRITE_INSTR(0xd2800000); /* 0xfffffff0156b7358    mov	x0, #0x0                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b735c    ret                           */ \
/*                                           found:                             */ \
WRITE_INSTR(0xd2800020); /* 0xfffffff0156b7360    mov	x0, #0x1                  */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7364    ret                           */ 
#endif
