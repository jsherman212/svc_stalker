#ifndef PAGETABLE_H
#define PAGETABLE_H

#define PAGE_SIZE                   (0x4000)

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (3)
#define NUM_INSTRS_BEFORE_CACHE     (9)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

#define HANDLE_SVC_HOOK_FPTR_CACHEOFF (0x0)
#define NUM_PAGES_CACHEOFF          (0x8)
#define PHYSTOKV_FPTR_CACHEOFF      (0x10)

/* local variables */
#define HANDLE_SVC_HOOK_FPTR        (STACK-0x70)
#define SAVED_STATE_PTR             (STACK-0x78)
#define NUM_PAGES                   (STACK-0x80)
#define VADDR_CUR                   (STACK-0x88)
#define VADDR_END                   (STACK-0x90)
#define PHYSTOKV_FPTR               (STACK-0x98)

/* TTE stuff, 16k devices */
/* mask for extracting pointer to the next table */
#define ARM_TTE_TABLE_MASK          (0x0000ffffffffc000)

#define ARM_16K_TT_L1_SHIFT         (36)
#define ARM_16K_TT_L2_SHIFT         (25)
#define ARM_16K_TT_L3_SHIFT         (14)

#define ARM_TT_L1_SHIFT             ARM_16K_TT_L1_SHIFT
#define ARM_TT_L2_SHIFT             ARM_16K_TT_L2_SHIFT
#define ARM_TT_L3_SHIFT             ARM_16K_TT_L3_SHIFT

#define ARM_16K_TT_L1_INDEX_MASK    (0x00007ff000000000)
#define ARM_16K_TT_L2_INDEX_MASK    (0x0000000ffe000000)
#define ARM_16K_TT_L3_INDEX_MASK    (0x0000000001ffc000)

#define ARM_TT_L1_INDEX_MASK        ARM_16K_TT_L1_INDEX_MASK
#define ARM_TT_L2_INDEX_MASK        ARM_16K_TT_L2_INDEX_MASK
#define ARM_TT_L3_INDEX_MASK        ARM_16K_TT_L3_INDEX_MASK

/* #define L1_TABLE_INDEX(va) (((va) & ARM_TT_L1_INDEX_MASK) >> ARM_TT_L1_SHIFT) */
/* #define L2_TABLE_INDEX(va) (((va) & ARM_TT_L2_INDEX_MASK) >> ARM_TT_L2_SHIFT) */
/* #define L3_TABLE_INDEX(va) (((va) & ARM_TT_L3_INDEX_MASK) >> ARM_TT_L3_SHIFT) */

#define ARM_TTE_TYPE_FAULT          (0x0000000000000000)
#define ARM_TTE_EMPTY               (0x0000000000000000)
#define ARM_TTE_VALID               (0x0000000000000001)
#define ARM_TTE_TYPE_MASK           (0x0000000000000002)
#define ARM_TTE_TYPE_TABLE          (0x0000000000000002)
#define ARM_TTE_TYPE_BLOCK          (0x0000000000000000)

#define ARM_PTE_TYPE_MASK           (0x0000000000000002)
#define ARM_PTE_TYPE_VALID          (0x0000000000000003)
/* #define PTE_IS_VALID(x) (((x) & 0x3) == ARM_PTE_TYPE_VALID) */

/* #define ttenum(a)               ((a) >> ARM_TT_L1_SHIFT) */

#define ARM_PGSHIFT                 (14)
/* #define ARM_PGBYTES (1 << ARM_PGSHIFT) */

#define AP_RWNA                     (0x0) /* priv=read-write, user=no-access */
#define AP_RWRW                     (0x1) /* priv=read-write, user=read-write */
#define AP_RONA                     (0x2) /* priv=read-only, user=no-access */
#define AP_RORO                     (0x3) /* priv=read-only, user=read-only */
#define AP_MASK                     (0x3) /* mask to find ap bits */

#define ARM_TTE_BLOCK_APSHIFT       (6)
#define ARM_TTE_BLOCK_APMASK        (0xc0)
#define ARM_TTE_BLOCK_PNXMASK       (0x0020000000000000)
#define ARM_TTE_BLOCK_NXMASK        (0x0040000000000000)
#define ARM_TTE_BLOCK_WIREDMASK     (0x0400000000000000)
#define ARM_TTE_BLOCK_WIRED         (0x0400000000000000)

#define ARM_TTE_BLOCK_PNX           (0x0020000000000000)
#define ARM_TTE_BLOCK_NX            (0x0040000000000000)

#define ARM_PTE_PNX                 (0x0020000000000000)
#define ARM_PTE_NX                  (0x0040000000000000)

#define ARM_PTE_HINT_MASK           (0x0010000000000000)
#define ARM_PTE_APMASK              (0xc0)
#define ARM_PTE_NXMASK              (0x0040000000000000)
#define ARM_PTE_PNXMASK             (0x0020000000000000)
#define ARM_PTE_WIRED               (0x0400000000000000)
#define ARM_PTE_WIRED_MASK          (0x0400000000000000)

/* from vm_prot.h */
#define	VM_PROT_NONE                (0x00)
#define VM_PROT_READ                (0x01)
#define VM_PROT_WRITE               (0x02)
#define VM_PROT_EXECUTE             (0x04)
#define VM_PROT_NO_CHANGE           (0x08)
#define VM_PROT_COPY                (0x10)
#define VM_PROT_WANTS_COPY          (0x10)

#endif
