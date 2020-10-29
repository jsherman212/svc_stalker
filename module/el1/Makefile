ASM_SRCS = $(wildcard *.s)
ASM_HDRS = $(patsubst %.s, %.h, $(ASM_SRCS))
ASM_INSTR_HDRS = $(patsubst %.s, %_instrs.h, $(ASM_SRCS))

$(ASM_INSTR_HDRS) : $(ASM_SRCS) $(ASM_HDRS) \
	../common/stalker_cache.h ../common/stalker_table.h
	chmod +x ./hookgen.pl
	./hookgen.pl common_functions
	./hookgen.pl handle_svc_hook
	./hookgen.pl hook_system_check_sysctlbyname_hook
	./hookgen.pl return_interceptor
	./hookgen.pl sleh_synchronous_hijacker
	./hookgen.pl svc_stalker_ctl
