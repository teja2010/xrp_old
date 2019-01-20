current_dir := $(shell pwd)
KDIR ?= $(current_dir)/deps/kernelsrc/linux-4.15
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

CLANG_FLAGS = -I. -I$(KDIR)/arch/$(ARCH)/include \
-I$(KDIR)/arch/$(ARCH)/include/generated \
-I$(KDIR)/include \
-I$(KDIR)/arch/$(ARCH)/include/uapi \
-I$(KDIR)/arch/$(ARCH)/include/generated/uapi \
-I$(KDIR)/include/uapi \
-I$(KDIR)/include/generated/uapi \
-include $(KDIR)/include/linux/kconfig.h \
-I$(KDIR)/tools/testing/selftests/bpf/ \
-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
-Wno-gnu-variable-sized-type-not-at-end \
-Wno-address-of-packed-member -Wno-tautological-compare \
-Wno-unknown-warning-option \
-O2 -emit-llvm

BPFDIR := $(KDIR)/tools/lib/bpf
BPFOBJ := $(BPFDIR)/libbpf.a
USRFLAGS := -I. -I$(KDIR)/tools/lib/ -I$(KDIR)/ -g


all: xrp_tcp_simple.o xrp

xrp_tcp_simple.o: xrp_tcp_simple.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - | \
	$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

xrp: xrp.c $(BPFOBJ)
	$(CLANG) $(USRFLAGS) xrp.c bpf_load.c $(BPFOBJ) -lelf -o xrp

$(BPFOBJ)::
	$(MAKE) -C $(BPFDIR) OUTPUT=$(BPFDIR)/

clean::
	rm xrp *.o   deps/kernelsrc/linux-4.15/tools/lib/bpf/libbpf.a
