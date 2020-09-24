CC=clang
SDK=$(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS=-isysroot $(SDK) -arch arm64 -mabi=aapcs -Xlinker -kext -nostdlib
CFLAGS+=-Wno-string-plus-int -fno-stack-protector

TARGET=svc_stalker

SOURCES=svc_stalker.c

$(TARGET) : $(SOURCES) handle_svc_hook.s handle_svc_hook.h \
	svc_stalker_ctl.s svc_stalker_ctl.h \
	hook_system_check_sysctlbyname_hook.s hook_system_check_sysctlbyname_hook.h \
	common_functions.s \
	sleh_synchronous_hijacker.s sleh_synchronous_hijacker.h \
	return_interceptor.s return_interceptor.h
	chmod +x ./hookgen.pl	# just in case
	# TODO only do this when asm files have changed, not all every time
	./hookgen.pl handle_svc_hook
	./hookgen.pl svc_stalker_ctl
	./hookgen.pl hook_system_check_sysctlbyname_hook
	./hookgen.pl common_functions
	./hookgen.pl sleh_synchronous_hijacker
	./hookgen.pl return_interceptor
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)
