CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -pthread
BINS     = a2tpctl
KDIR    ?= /lib/modules/$(shell uname -r)/build

all: $(BINS)

a2tpctl: src/a2tpctl.c src/proto.h src/kapi.h
	$(CC) $(CFLAGS) -o $@ src/a2tpctl.c

# kernel module (out-of-tree)
kmod:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules

kmod-clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel clean

clean: kmod-clean
	rm -f $(BINS)

.PHONY: all clean kmod kmod-clean
