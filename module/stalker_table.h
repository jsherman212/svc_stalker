#ifndef STALKER_TABLE
#define STALKER_TABLE

#define STALKER_TABLE_MAX                       (1023)
#define STALKER_TABLE_FREE_SLOT                 (0x0)

#define STALKER_TABLE_NUM_PIDS_OFF              (0x0)
#define STALKER_TABLE_REGISTERED_SYSCTL_OFF     (0x8)

/* struct stalker_ctl {
 *       is this entry not being used?
 *     uint32_t free;
 *
 *       what pid this entry belongs to
 *     uint32_t pid;
 *
 *       list of call numbers to intercept & send to userland, kalloc'ed
 *       this is treated as a direct lookup table. call_list[call_num] will
 *       tell us if we are intercepting this call or not
 *     uint8_t *call_list;
 * };
 *
 * sizeof(struct stalker_ctl) = 0x10
 */
#define SIZEOF_STRUCT_STALKER_CTL               (0x10)

#define STALKER_CTL_FREE_OFF                    (0x0)
#define STALKER_CTL_PID_OFF                     (0x4)
#define STALKER_CTL_CALL_LIST_OFF               (0x8)

/* since Mach trap numbers are negative, to keep from writing before the
 * beginning of the page allocated for the call list, we'll keep a pointer
 * 0x2000 bytes from the beginning of the page
 *
 * XXX because platform syscalls call number is 0x80000000, that obviously won't
 * fit in the call_list allocation, so just stick the flag for that at the
 * very beginning of the page
 */
#define CALL_LIST_DISPLACEMENT_SHIFT            13

/* -0x1fff instead of -0x2000 so user cannot accidentally modify platform
 * syscall flag
 */
#define CALL_NUM_MIN                            0x1fff
#define CALL_NUM_MAX                            (0x1fff)

#define PLATFORM_SYSCALL_CALL_NUM_SHIFT         31

#endif
