CC=clang
SDK=$(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS=-isysroot $(SDK) -arch arm64 -mabi=aapcs -Xlinker -kext -nostdlib
CFLAGS+=-Wno-string-plus-int -fno-stack-protector

TARGET=svc_stalker

SOURCES=svc_stalker.c

$(TARGET) : $(SOURCES) handle_svc_hook.s handle_svc_hook.h \
	svc_stalker_ctl.s svc_stalker_ctl.h \
	hook_system_check_sysctlbyname_hook.s hook_system_check_sysctlbyname_hook.h \
	common_functions.s arm_prepare_syscall_return_fakestk.s \
	arm_prepare_syscall_return_hook.s platform_syscall_hook.s \
	thread_exception_return_hook.s thread_exception_return_hook.h
	chmod +x ./hookgen.pl	# just in case
	# TODO only do this when asm files have changed, not all every time
	./hookgen.pl handle_svc_hook
	./hookgen.pl svc_stalker_ctl
	./hookgen.pl hook_system_check_sysctlbyname_hook
	./hookgen.pl common_functions
	./hookgen.pl arm_prepare_syscall_return_fakestk
	./hookgen.pl arm_prepare_syscall_return_hook
	./hookgen.pl platform_syscall_hook
	./hookgen.pl thread_exception_return_hook
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)
