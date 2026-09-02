CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -D_GNU_SOURCE -pthread
BINS     = a2tpctl
KDIR    ?= /lib/modules/$(shell uname -r)/build
VER     ?= 1.0
DEB     = build/a2tp-dkms_$(VER)_amd64.deb
STAGE   = build/deb/a2tp-dkms
SRCROOT = $(STAGE)/usr/src/a2tp-$(VER)

all: $(BINS)

a2tpctl: src/a2tpctl.c src/proto.h src/kapi.h
	$(CC) $(CFLAGS) -o $@ src/a2tpctl.c

# kernel module (out-of-tree)
kmod:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel modules

kmod-clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/kernel clean

# dkms deb：模块源码(/usr/src，dkms 每内核自动重编) + 用户态工具(/usr/bin/a2tpctl)
deb: a2tpctl
	rm -rf build/deb
	install -d $(SRCROOT)/kernel $(SRCROOT)/src
	install -m 644 kernel/Makefile kernel/a2tp.h kernel/a2tp_main.c \
		kernel/a2tp_core.c kernel/a2tp_srv.c kernel/a2tp_netdev.c $(SRCROOT)/kernel/
	install -m 644 src/a2tpctl.c src/proto.h src/kapi.h $(SRCROOT)/src/
	install -m 644 Makefile LICENSE README.md $(SRCROOT)/
	sed 's/@VER@/$(VER)/' packaging/dkms.conf > $(SRCROOT)/dkms.conf
	install -d $(STAGE)/usr/bin
	install -m 755 a2tpctl $(STAGE)/usr/bin/a2tpctl
	install -d $(STAGE)/usr/lib/modules-load.d
	install -m 644 packaging/modules-load.conf $(STAGE)/usr/lib/modules-load.d/a2tp.conf
	install -d $(STAGE)/DEBIAN
	sed 's/@VER@/$(VER)/' packaging/debian/control > $(STAGE)/DEBIAN/control
	sed 's/@VER@/$(VER)/' packaging/debian/postinst > $(STAGE)/DEBIAN/postinst
	sed 's/@VER@/$(VER)/' packaging/debian/prerm   > $(STAGE)/DEBIAN/prerm
	chmod 755 $(STAGE)/DEBIAN/postinst $(STAGE)/DEBIAN/prerm
	chmod -R go-w $(STAGE)
	dpkg-deb --build --root-owner-group $(STAGE) $(DEB)
	@echo "==> $(DEB)"

clean: kmod-clean
	rm -f $(BINS)
	rm -rf build

.PHONY: all clean kmod kmod-clean deb
