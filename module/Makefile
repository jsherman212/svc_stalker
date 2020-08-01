CC=clang
SDK=$(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS=-isysroot $(SDK) -arch arm64 -mabi=aapcs -Xlinker -kext -nostdlib

TARGET=svc_stalker

SOURCES=svc_stalker.c

$(TARGET) : $(SOURCES) handle_svc_hook.s
	./hookgen.pl
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET)
