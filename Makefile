ifndef TARGET_COMPILE
    TARGET_COMPILE = /root/工作/arm-gnu-toolchain-12.2.rel1-aarch64-aarch64-none-elf/bin/aarch64-none-elf-
endif

ifndef KP_DIR
    KP_DIR = ../../KernelPatch
endif

CC = $(TARGET_COMPILE)gcc
STRIP = $(TARGET_COMPILE)strip

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include

INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := FsTimeSpoof.o

all: FsTimeSpoof.kpm

FsTimeSpoof.kpm: FsTimeSpoof.o
	$(CC) -r -o $@ $^
	$(STRIP) --strip-unneeded $@

%.o: %.c
	$(CC) -Wall -Wextra -O2 $(CFLAGS) $(INCLUDE_FLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f *.kpm *.o
