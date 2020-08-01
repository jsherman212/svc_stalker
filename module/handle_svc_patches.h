#ifndef handle_svc_patches
#define handle_svc_patches
#define DO_HANDLE_SVC_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0156b7238    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a73fb); /* 0xfffffff0156b723c    stp	x27, x28, [sp, #0x1a0]    */ \
WRITE_INSTR(0xa91b67fa); /* 0xfffffff0156b7240    stp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa91c5ff8); /* 0xfffffff0156b7244    stp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa91d57f6); /* 0xfffffff0156b7248    stp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa91e4ff4); /* 0xfffffff0156b724c    stp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa91f7bfd); /* 0xfffffff0156b7250    stp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0x9107c3fd); /* 0xfffffff0156b7254    add	x29, sp, #0x1f0           */ \
WRITE_INSTR(0x10fffec9); /* 0xfffffff0156b7258    adr	x9, #-0x28                */ \
WRITE_INSTR(0xf81d83e9); /* 0xfffffff0156b725c    stur	x9, [sp, #-0x28]         */ \
WRITE_INSTR(0xf940012a); /* 0xfffffff0156b7260    ldr	x10, [x9]                 */ \
WRITE_INSTR(0xf900c7ea); /* 0xfffffff0156b7264    str	x10, [sp, #0x188]         */ \
WRITE_INSTR(0xf85d83e9); /* 0xfffffff0156b7268    ldur	x9, [sp, #-0x28]         */ \
WRITE_INSTR(0xf9400129); /* 0xfffffff0156b726c    ldr	x9, [x9]                  */ \
WRITE_INSTR(0xf940c7ea); /* 0xfffffff0156b7270    ldr	x10, [sp, #0x188]         */ \
WRITE_INSTR(0xd4200000); /* 0xfffffff0156b7274    brk	#0                        */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b7278    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b727c    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b7280    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b7284    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b7288    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b728c    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b7290    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b7294    ret                           */ 
#endif
