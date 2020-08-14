    .align 4
    .globl _main

#include "hook_system_check_sysctlbyname_hook.h"

_main:
    mov x19, 0x4141
    brk 0
    ret
