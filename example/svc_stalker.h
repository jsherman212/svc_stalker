/* Include this in your userspace programs that utilize svc_stalker's
 * call interception
 */

#ifndef SVC_STALKER
#define SVC_STALKER

#define PID_MANAGE                              (0)
#define CALL_LIST_MANAGE                        (1)

#define BEFORE_CALL                             (0)
#define CALL_COMPLETED                          (1)

#define STALKER_TABLE_MAX                       (1023)

#define CALL_NUM_MIN                            (-0x1fff)
#define CALL_NUM_MAX                            (0x1fff)

#endif
