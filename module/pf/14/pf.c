#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "../../common/common.h"
#include "../../common/pongo.h"

uint64_t g_kalloc_external_addr = 0;
uint64_t g_kfree_ext_addr = 0;

bool kalloc_external_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* we've landed inside kalloc_external, find its prologue
     *
     * looking for stp x29, x30, [sp, -0x10]!
     */
    uint32_t instr_limit = 200;

    while(*opcode_stream != 0xa9bf7bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_kalloc_external_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found kalloc_external");

    /* printf("%s: kalloc_external @ %#llx\n", __func__, */
    /*         g_kalloc_external_addr - kernel_slide); */

    return true;
}

bool kfree_ext_finder_14(xnu_pf_patch_t *patch, void *cacheable_stream){
    uint32_t *opcode_stream = cacheable_stream;

    /* we've landed inside kfree_ext, find its prologue
     *
     * looking for stp x29, x30, [sp, -0x10]!
     */
    uint32_t instr_limit = 200;

    while(*opcode_stream != 0xa9bf7bfd){
        if(instr_limit-- == 0)
            return false;

        opcode_stream--;
    }

    g_kfree_ext_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found kfree_ext");

    printf("%s: kfree_ext @ %#llx\n", __func__, g_kfree_ext_addr - kernel_slide);

    return true;
}
