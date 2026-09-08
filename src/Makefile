# kbuild Makefile for the resident KPM loader agent (kpm_host).
# Invoked via: make -C $KDIR ARCH=arm64 ... M=$(SRC) modules
# (see ../build/build_510.sh for the full command line / toolchain).

obj-m += kpm_host.o
kpm_host-objs := kpm_host_core.o kpm_host_re.o kpm_ctl.o

ccflags-y += -fno-stack-protector -fno-plt -ffixed-x18

.PHONY: clean
clean:
	@$(MAKE) -C $(KDIR) ARCH=arm64 LLVM=1 M=$(PWD) clean
	rm -f kpm_host.ko *.o *.mod module.mod module.mod.o modules.order Module.symvers