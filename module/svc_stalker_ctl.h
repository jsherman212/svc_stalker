#ifndef SVC_STALKER_CTL
#define SVC_STALKER_CTL

#define STACK                       (0x200)

#define NUM_CACHED_PTRS             (3)
#define NUM_INSTRS_BEFORE_CACHE     (11)
/* offset of start of cached kernel pointers */
#define CACHE_START                 (-((4*NUM_INSTRS_BEFORE_CACHE)+(8*NUM_CACHED_PTRS)))

#define STALKER_TABLE_CACHEOFF      (0x0)
#define KALLOC_CANBLOCK_FPTR_CACHEOFF (0x8)
#define KFREE_ADDR_FPTR_CACHEOFF    (0x10)

/* parameters */
#define PID_ARG                     (0x0)
#define FLAVOR_ARG                  (0x8)
#define ARG2                        (0x10)
#define ARG3                        (0x18)

#define PID_MANAGE                  (0)
#define CALL_LIST_MANAGE            (1)

/* local variables */
#define OFFSET_CACHE_PTR            (STACK-0x70)
#define STALKER_TABLE_PTR           (STACK-0x78)
#define CUR_PID_SLOT                (STACK-0x80)
#define IOLOG_FPTR                  (STACK-0x88)
#define IOMALLOC_FPTR               (STACK-0x90)
#define KALLOC_CANBLOCK_FPTR        (STACK-0x98)
#define KFREE_ADDR_FPTR             (STACK-0xa0)
#define CALL_LIST_KALLOC_SZ         (STACK-0xa8)
#define CUR_STALKER_CTL             (STACK-0xb0)

/* stalker table stuff */
#define STALKER_TABLE_MAX           (1023)
#define STALKER_TABLE_FREE_SLOT     (0x0)
#define STALKER_TABLE_NUM_PIDS_OFF  (0x0)

/* struct stalker_ctl {
 *       is this entry not being used?
 *     uint32_t free;
 *
 *       what pid this entry belongs to
 *     int32_t pid;
 *
 *       list of system call numbers to intercept & send to userland
 *     int64_t *call_list;
 * };
 *
 * Empty spots in the call list are represented by 0x4000 because that
 * doesn't represent any system call or mach trap.
 *
 * sizeof(struct stalker_ctl) = 0x10
 */
#define STALKER_CTL_FREE_OFF        (0x0)
#define STALKER_CTL_PID_OFF         (0x4)
#define STALKER_CTL_CALL_LIST_OFF   (0x8)

#define CALL_LIST_MAX               (1000)
#define CALL_LIST_FREE_SLOT         (0x4000)

#endif
