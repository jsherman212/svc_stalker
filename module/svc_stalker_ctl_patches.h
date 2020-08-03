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
WRITE_INSTR(0x10fffe76); /* 0xfffffff0156b727c    adr	x22, #-0x34               */ \
WRITE_INSTR(0xf900cbf6); /* 0xfffffff0156b7280    str	x22, [sp, #0x190]         */ \
WRITE_INSTR(0xf94002d7); /* 0xfffffff0156b7284    ldr	x23, [x22]                */ \
WRITE_INSTR(0xf900c7f7); /* 0xfffffff0156b7288    str	x23, [sp, #0x188]         */ \
WRITE_INSTR(0xb9400296); /* 0xfffffff0156b728c    ldr	w22, [x20]                */ \
WRITE_INSTR(0x710002df); /* 0xfffffff0156b7290    cmp	w22, #0x0                 */ \
WRITE_INSTR(0x540000eb); /* 0xfffffff0156b7294    b.lt	maybebadpid              */ \
WRITE_INSTR(0xf940c7f6); /* 0xfffffff0156b7298    ldr	x22, [sp, #0x188]         */ \
WRITE_INSTR(0xb94002d6); /* 0xfffffff0156b729c    ldr	w22, [x22]                */ \
WRITE_INSTR(0xd4200000); /* 0xfffffff0156b72a0    brk	#0                        */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b72a4    mov	w0, #0x0                  */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b72a8    str	w0, [x21]                 */ \
WRITE_INSTR(0x1400000b); /* 0xfffffff0156b72ac    b	done                        */ \
/*                                           maybebadpid:                       */ \
WRITE_INSTR(0x310006df); /* 0xfffffff0156b72b0    cmn	w22, #0x1                 */ \
WRITE_INSTR(0x540000a1); /* 0xfffffff0156b72b4    b.ne	badpid                   */ \
WRITE_INSTR(0x52807ce0); /* 0xfffffff0156b72b8    mov	w0, #0x3e7                */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b72bc    str	w0, [x21]                 */ \
WRITE_INSTR(0x52800000); /* 0xfffffff0156b72c0    mov	w0, #0x0                  */ \
WRITE_INSTR(0x14000005); /* 0xfffffff0156b72c4    b	done                        */ \
/*                                           badpid:                            */ \
WRITE_INSTR(0x12800000); /* 0xfffffff0156b72c8    mov	w0, #-0x1                 */ \
WRITE_INSTR(0xb90002a0); /* 0xfffffff0156b72cc    str	w0, [x21]                 */ \
WRITE_INSTR(0x528002c0); /* 0xfffffff0156b72d0    mov	w0, #0x16                 */ \
WRITE_INSTR(0x14000001); /* 0xfffffff0156b72d4    b	done                        */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b72d8    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b72dc    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b72e0    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b72e4    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b72e8    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b72ec    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b72f0    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b72f4    ret                           */ 
#endif
