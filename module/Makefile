CC = clang
SDK = $(shell xcrun --sdk iphoneos --show-sdk-path)
CFLAGS = -isysroot $(SDK) -arch arm64 -Wno-string-plus-int -fno-stack-protector
CFLAGS += -D_FORTIFY_SOURCE=0 -nostdlib
LDFLAGS = -Xlinker -kext

export CC
export CFLAGS

TARGET_DIRS = common el1 pf

all : $(TARGET_DIRS) svc_stalker

.PHONY : target_dirs $(TARGET_DIRS)

target_dirs : $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@

OBJECT_FILES = $(shell find ./common ./pf -type f -name "*.o")
INSTR_FILES = $(shell find ./el1 -type f -name "*_instrs.h")

svc_stalker : $(OBJECT_FILES) $(INSTR_FILES) svc_stalker.c common/common.h \
	pf/offsets.h pf/pfs.h
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECT_FILES) svc_stalker.c -o svc_stalker
