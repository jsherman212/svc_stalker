#ifndef handle_svc_patches
#define handle_svc_patches
#define DO_HANDLE_SVC_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0156b7230    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a73fb); /* 0xfffffff0156b7234    stp	x27, x28, [sp, #0x1a0]    */ \
WRITE_INSTR(0xa91b67fa); /* 0xfffffff0156b7238    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa91c5ff8); /* 0xfffffff0156b723c    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa91d57f6); /* 0xfffffff0156b7240    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa91e4ff4); /* 0xfffffff0156b7244    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa91f7bfd); /* 0xfffffff0156b7248    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0x9107c3fd); /* 0xfffffff0156b724c    add	x29, sp, #0x1f0           */ \
WRITE_INSTR(0xd2882820); /* 0xfffffff0156b7250    mov	x0, #0x4141               */ \
WRITE_INSTR(0xd2884841); /* 0xfffffff0156b7254    mov	x1, #0x4242               */ \
WRITE_INSTR(0xd2886862); /* 0xfffffff0156b7258    mov	x2, #0x4343               */ \
WRITE_INSTR(0xd4200000); /* 0xfffffff0156b725c    brk	#0                        */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b7260    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b7264    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b7268    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b726c    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b7270    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b7274    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b7278    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b727c    ret                           */ 
#endif
