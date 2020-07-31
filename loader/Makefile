CC=clang
CFLAGS=-g -framework CoreFoundation -framework IOKit

TARGET=loader

SOURCES=loader.c

$(TARGET) : $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o loader
