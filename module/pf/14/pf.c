#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

#include "../disas.h"
#include "../offsets.h"

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

    return true;
}

bool ExceptionVectorsBase_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;
    uint32_t limit = PAGE_SIZE / sizeof(uint32_t);

    /* go backwords one opcode, we'll hit the stream of values that clang
     * decided to page align ExceptionVectorsBase with
     */
    opcode_stream--;

    uintptr_t orig_opcode_stream = (uintptr_t)opcode_stream;
    uint32_t filler_opcode = *opcode_stream;

    /* go backwords until we hit an instruction */
    while(limit-- != 0){
        uint32_t cur = *opcode_stream;

        if(cur != filler_opcode)
            break;

        opcode_stream--;
    }

    /* get off this instruction, now we point to the beginning of unused
     * executable code
     */
    opcode_stream++;

    g_exec_scratch_space_size = orig_opcode_stream - (uintptr_t)opcode_stream;
    g_exec_scratch_space_addr = xnu_ptr_to_va(opcode_stream);

    puts("svc_stalker: found unused executable code");

    return true;
}

bool sysctl__kern_children_and_register_oid_finder_14(xnu_pf_patch_t *patch,
        void *cacheable_stream){
    uint32_t *opcode_stream = (uint32_t *)cacheable_stream;

    /* we've landed in entropy_buffer_init
     *
     * The first adrp/adr from this point on will lead us to
     * sysctl__kern_children
     */
    uint64_t addr_va = 0;

    if(bits(opcode_stream[7], 31, 31) == 0)
        addr_va = get_adr_va_target(opcode_stream + 7);
    else
        addr_va = get_adrp_add_va_target(opcode_stream + 7);

    g_sysctl__kern_children_addr = addr_va;

    /* the BL right after the adrp/adr is branching to sysctl_register_oid */
    uint32_t *sysctl_register_oid = get_branch_dst_ptr(opcode_stream[9],
            opcode_stream + 9);

    g_sysctl_register_oid_addr = xnu_ptr_to_va(sysctl_register_oid);

    printf("%s: sysctl__kern_children @ %#llx sysctl_register_oid @ %#llx\n",
            __func__, g_sysctl__kern_children_addr - kernel_slide,
            g_sysctl_register_oid_addr - kernel_slide);

    puts("svc_stalker: found sysctl__kern_children");
    puts("svc_stalker: found sysctl_register_oid");

    return true;
}
