# Template (kept for reference only). The live kbuild Makefile is ../src/Makefile
# and is invoked by build_510.sh with M="$ROOT/src".
# KDIR must point at a 5.10 kernel tree prepared with CONFIG_CFI_CLANG=y.
KDIR ?= /root/kernel_common

obj-m += kpm_host.o
kpm_host-objs := kpm_host_core.o kpm_host_re.o kpm_ctl.o

ccflags-y += -fno-stack-protector -fno-plt -ffixed-x18

PWD := $(shell pwd)
CLANG_DIR ?= /root/prebuilt_clang/clang-r416183/bin
export PATH := $(CLANG_DIR):$(PATH)

.PHONY: all clean install

all:
	@$(MAKE) -C $(KDIR) ARCH=arm64 LLVM=1 CC=$(CLANG_DIR)/clang HOSTCC=gcc \
		NM=$(CLANG_DIR)/llvm-nm AR=$(CLANG_DIR)/llvm-ar LD=$(CLANG_DIR)/ld.lld \
		OBJCOPY=$(CLANG_DIR)/llvm-objcopy CROSS_COMPILE=aarch64-linux-gnu- \
		KCFLAGS="-fsanitize-cfi-canonical-jump-tables" \
		M=$(PWD) modules

clean:
	@$(MAKE) -C $(KDIR) ARCH=arm64 LLVM=1 M=$(PWD) clean
	rm -f kpm_host.ko kpm_host.o kpm_host_re.o kpm_host_core.o kpm_host.mod kpm_host.mod.c modules.order Module.symvers

install: all
	cp -f kpm_host.ko kpm_host-gki-5.10.ko
	@echo "built: kpm_host-gki-5.10.ko"