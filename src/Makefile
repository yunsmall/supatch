# kbuild Makefile for the resident KPM loader agent (kpm_host).
# Invoked via: make -C $KDIR ARCH=arm64 ... M=$(SRC) modules
# (see ../build/build_510.sh for the full command line / toolchain).

obj-m += kpm_host.o
kpm_host-objs := kpm_host_core.o kpm_host_re.o kpm_ctl.o

# -fno-plt 会生成 R_AARCH64_ADR_GOT_PAGE 重定位，内核模块加载器不支持
ccflags-y += -fno-stack-protector -ffixed-x18

.PHONY: clean
clean:
	@$(MAKE) -C $(KDIR) ARCH=arm64 LLVM=1 M=$(PWD) clean
	rm -f kpm_host.ko *.o *.mod module.mod module.mod.o modules.order Module.symvers