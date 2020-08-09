CC=clang
SDK=$(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS=-isysroot $(SDK) -arch arm64 -mabi=aapcs -Xlinker -kext -nostdlib

TARGET=svc_stalker

SOURCES=svc_stalker.c

$(TARGET) : $(SOURCES) handle_svc_hook.s handle_svc_hook.h \
	svc_stalker_ctl.s svc_stalker_ctl.h
	chmod +x ./hookgen.pl	# just in case
	./hookgen.pl handle_svc_hook
	./hookgen.pl svc_stalker_ctl
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)
