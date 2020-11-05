#ifndef SS_PATCHER
#define SS_PATCHER

#include <stdbool.h>

typedef struct xnu_pf_patch xnu_pf_patch_t;

bool stalker_main_patcher(xnu_pf_patch_t *, void *);

#endif
