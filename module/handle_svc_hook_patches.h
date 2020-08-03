#ifndef handle_svc_hook
#define handle_svc_hook
#define DO_HANDLE_SVC_HOOK_PATCHES \
/*                                           _main:                             */ \
WRITE_INSTR(0xd10803ff); /* 0xfffffff0156b7250    sub	sp, sp, #0x200            */ \
WRITE_INSTR(0xa91a73fb); /* 0xfffffff0156b7254    stp	x27, x28, [sp, #0x1a0]    */ \
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
WRITE_INSTR(0x1400000a); /* 0xfffffff0156b729c    b	done                        */ \
WRITE_INSTR(0xd28000e0); /* 0xfffffff0156b72a0    mov	x0, #0x7                  */ \
WRITE_INSTR(0xf940b7e1); /* 0xfffffff0156b72a4    ldr	x1, [sp, #0x168]          */ \
WRITE_INSTR(0xf9404421); /* 0xfffffff0156b72a8    ldr	x1, [x1, #0x88]           */ \
WRITE_INSTR(0xf900b3e1); /* 0xfffffff0156b72ac    str	x1, [sp, #0x160]          */ \
WRITE_INSTR(0xf900b7ff); /* 0xfffffff0156b72b0    str	xzr, [sp, #0x168]         */ \
WRITE_INSTR(0x910583e1); /* 0xfffffff0156b72b4    add	x1, sp, #0x160            */ \
WRITE_INSTR(0x52800042); /* 0xfffffff0156b72b8    mov	w2, #0x2                  */ \
WRITE_INSTR(0xf940c7f3); /* 0xfffffff0156b72bc    ldr	x19, [sp, #0x188]         */ \
WRITE_INSTR(0xd63f0260); /* 0xfffffff0156b72c0    blr	x19                       */ \
/*                                           done:                              */ \
WRITE_INSTR(0xa95f7bfd); /* 0xfffffff0156b72c4    ldp	x29, x30, [sp, #0x1f0]    */ \
WRITE_INSTR(0xa95e4ff4); /* 0xfffffff0156b72c8    ldp	x20, x19, [sp, #0x1e0]    */ \
WRITE_INSTR(0xa95d57f6); /* 0xfffffff0156b72cc    ldp	x22, x21, [sp, #0x1d0]    */ \
WRITE_INSTR(0xa95c5ff8); /* 0xfffffff0156b72d0    ldp	x24, x23, [sp, #0x1c0]    */ \
WRITE_INSTR(0xa95b67fa); /* 0xfffffff0156b72d4    ldp	x26, x25, [sp, #0x1b0]    */ \
WRITE_INSTR(0xa95a6ffc); /* 0xfffffff0156b72d8    ldp	x28, x27, [sp, #0x1a0]    */ \
WRITE_INSTR(0x910803ff); /* 0xfffffff0156b72dc    add	sp, sp, #0x200            */ \
WRITE_INSTR(0xd65f03c0); /* 0xfffffff0156b72e0    ret                           */ \
/*                                           dump_saved_state:                  */ \
WRITE_INSTR(0xf940b7f2); /* 0xfffffff0156b72e4    ldr	x18, [sp, #0x168]         */ \
WRITE_INSTR(0x91002252); /* 0xfffffff0156b72e8    add	x18, x18, #0x8            */ \
WRITE_INSTR(0xa9400640); /* 0xfffffff0156b72ec    ldp	x0, x1, [x18]             */ \
WRITE_INSTR(0xa9410e42); /* 0xfffffff0156b72f0    ldp	x2, x3, [x18, #0x10]      */ \
WRITE_INSTR(0xa9421644); /* 0xfffffff0156b72f4    ldp	x4, x5, [x18, #0x20]      */ \
WRITE_INSTR(0xa9431e46); /* 0xfffffff0156b72f8    ldp	x6, x7, [x18, #0x30]      */ \
WRITE_INSTR(0xa9442648); /* 0xfffffff0156b72fc    ldp	x8, x9, [x18, #0x40]      */ \
WRITE_INSTR(0xa9452e4a); /* 0xfffffff0156b7300    ldp	x10, x11, [x18, #0x50]    */ \
WRITE_INSTR(0xa946364c); /* 0xfffffff0156b7304    ldp	x12, x13, [x18, #0x60]    */ \
WRITE_INSTR(0xa9473e4e); /* 0xfffffff0156b7308    ldp	x14, x15, [x18, #0x70]    */ \
WRITE_INSTR(0xa9484650); /* 0xfffffff0156b730c    ldp	x16, x17, [x18, #0x80]    */ \
WRITE_INSTR(0xf9404e53); /* 0xfffffff0156b7310    ldr	x19, [x18, #0x98]         */ \
WRITE_INSTR(0xa94a5654); /* 0xfffffff0156b7314    ldp	x20, x21, [x18, #0xa0]    */ \
WRITE_INSTR(0xa94b5e56); /* 0xfffffff0156b7318    ldp	x22, x23, [x18, #0xb0]    */ \
WRITE_INSTR(0xa94c6658); /* 0xfffffff0156b731c    ldp	x24, x25, [x18, #0xc0]    */ \
WRITE_INSTR(0xa94d6e5a); /* 0xfffffff0156b7320    ldp	x26, x27, [x18, #0xd0]    */ \
WRITE_INSTR(0xa94e765c); /* 0xfffffff0156b7324    ldp	x28, x29, [x18, #0xe0]    */ \
WRITE_INSTR(0xf9407a5e); /* 0xfffffff0156b7328    ldr	x30, [x18, #0xf0]         */ \
WRITE_INSTR(0xf9408252); /* 0xfffffff0156b732c    ldr	x18, [x18, #0x100]        */ \
WRITE_INSTR(0xd4200000); /* 0xfffffff0156b7330    brk	#0                        */ 
#endif
