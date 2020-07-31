TARGET_DIRS=loader

all : $(TARGET_DIRS)

.PHONY: all $(TARGET_DIRS)

$(TARGET_DIRS) :
	$(MAKE) -C $@
