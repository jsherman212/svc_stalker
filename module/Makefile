CC=clang
SDK=$(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS=-isysroot $(SDK) -arch arm64 -mabi=aapcs -Xlinker -kext -nostdlib
CFLAGS+=-Wno-string-plus-int -fno-stack-protector

TARGET=svc_stalker

SOURCES=svc_stalker.c

$(TARGET) : $(SOURCES) handle_svc_hook.s handle_svc_hook.h \
	svc_stalker_ctl.s svc_stalker_ctl.h \
	hook_system_check_sysctlbyname_hook.s hook_system_check_sysctlbyname_hook.h
	chmod +x ./hookgen.pl	# just in case
	./hookgen.pl handle_svc_hook
	./hookgen.pl svc_stalker_ctl
	./hookgen.pl hook_system_check_sysctlbyname_hook
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)
