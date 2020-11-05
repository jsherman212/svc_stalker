TARGET_DIRS = 13 14

all : disas.o macho.o ss_patcher.o $(TARGET_DIRS)

disas.o : disas.c disas.h
	$(CC) $(CFLAGS) disas.c -c

macho.o : macho.c macho.h
	$(CC) $(CFLAGS) macho.c -c

ss_patcher.o : ss_patcher.c ss_patcher.h
	$(CC) $(CFLAGS) ss_patcher.c -c

target_dirs : $(TARGET_DIRS)

.PHONY : all target_dirs $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@
