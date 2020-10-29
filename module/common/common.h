#ifndef COMMON
#define COMMON

#include <mach-o/loader.h>

int atoi(char *);
int isdigit(int);

char *strcpy(char *, const char *);

__attribute__ ((noreturn)) void stalker_fatal_error(void);

extern struct mach_header_64 *mh_execute_header;
extern uint64_t kernel_slide;

#define PAGE_SIZE                   (0x4000)

#endif
