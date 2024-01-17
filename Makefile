.PHONY: default
default: all

APPS_SRC_DIR_NAME := apps
APPS_SRC_DIR := $(abspath $(APPS_SRC_DIR_NAME))
APPS := $(patsubst %.bpf.c,%,$(notdir $(wildcard $(APPS_SRC_DIR)/*.bpf.c)))

CROSS ?= 1
CROSS_ARCH ?= arc
HOST_ARCH := $(shell uname -m \
		| sed 's/x86_64/x86/' \
		| sed 's/arm.*/arm/' \
		| sed 's/aarch64/arm64/')

ifeq ($(CROSS),1)
ARCH := $(CROSS_ARCH)
STDLIB ?= gnu
TARGET := $(ARCH)-linux-$(STDLIB)
TOOLCHAIN_PREFIX := $(TARGET)-
CC := $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld
else
ARCH := $(HOST_ARCH)
TARGET =
TOOLCHAIN_PREFIX =
CC = gcc
LD = ld
endif

ARCH_DIR := $(abspath output/$(ARCH))
DEPS_DIR := $(ARCH_DIR)/deps
BUILD_DIR := $(ARCH_DIR)/build

APPS_BUILD_DIR := $(BUILD_DIR)/$(APPS_SRC_DIR_NAME)
APPS_BIN_DIR := $(ARCH_DIR)/bin

ifeq ($(filter-out %64 %64be %64eb %64le %64el s390x,$(TARGET)),)
	BITS := 64
	BITS_SUFFIX := 64
else
	BITS := 32
	BITS_SUFFIX :=
endif

LIB_DIR := $(DEPS_DIR)/usr/lib
LIB64_DIR := $(DEPS_DIR)/usr/lib$(BITS_SUFFIX)
INCLUDE_DIR := $(DEPS_DIR)/usr/include

CFLAGS := -g3 -Og -Wall -I$(APPS_BUILD_DIR) -I$(APPS_SRC_DIR) -I$(INCLUDE_DIR)
LDFLAGS_STATIC := $(LIB64_DIR)/libbpf.a $(LIB_DIR)/libz.a $(LIB_DIR)/libelf.a -L$(LIB_DIR) -L$(LIB64_DIR)
LDFLAGS_SHARED := -lbpf -lz -lelf -L$(LIB_DIR) -L$(LIB64_DIR)
NPROC = $(shell nproc)

#
# Verbosity
#

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(DEPS_DIR))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

#
# Clang configuration
#

CLANG ?= clang

define find_includes
    $(shell $(1) -v -x c -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-I\1|p }')
endef

ifeq ($(CROSS),1)
CLANG_SYS_INCLUDES := $(call find_includes,$(CC))
else
CLANG_SYS_INCLUDES := $(call find_includes,$(CLANG))
endif

CLANG_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Xclang -target-feature -Xclang +alu32 -I$(APPS_SRC_DIR) -I$(INCLUDE_DIR) $(CLANG_SYS_INCLUDES)

#
# Configure pkgconfig for dependencies
#

PKG_CONFIG_PATH := $(DEPS_DIR)/usr/lib/pkgconfig
export PKG_CONFIG_PATH

#
# zlib
#

ZLIB_SRC := $(abspath zlib)
ZLIB_OBJ := $(abspath $(LIB_DIR)/libz.a)
ZLIB_SHARED := $(abspath $(LIB_DIR)/libz.so)
ZLIB_BUILD_DIR := $(BUILD_DIR)/zlib

$(BUILD_DIR)/zlib/Makefile: $(ZLIB_SRC)/configure | $(ZLIB_BUILD_DIR)
	$(call msg,CONFIG,$@)
	$(Q)cd $(BUILD_DIR)/zlib && CHOST=$(TARGET) CFLAGS="-Og -g3 -fPIC" $(ZLIB_SRC)/configure --prefix=/usr

$(ZLIB_OBJ): $(ZLIB_SRC)/*.c $(ZLIB_SRC)/*.h $(BUILD_DIR)/zlib/Makefile | $(ZLIB_BUILD_DIR)
	$(call msg,LIB,$@)
	$(Q)$(MAKE) V=$(V) -j $(NPROC) -C $(BUILD_DIR)/zlib
	$(Q)$(MAKE) V=$(V) -j $(NPROC) -C $(BUILD_DIR)/zlib DESTDIR="$(DEPS_DIR)" LDCONFIG=true install
	$(Q)sed -i -e 's|prefix=/usr|prefix=$(DEPS_DIR)/usr|g' $(DEPS_DIR)/usr/lib/pkgconfig/zlib.pc

.PHONY: zlib
zlib: $(ZLIB_OBJ)

#
# libelf
#

LIBELF_TAR := $(abspath elfutils-0.189.tar.bz2)
LIBELF_SRC := $(abspath elfutils-0.189)
LIBELF_OBJ := $(abspath $(LIB_DIR)/libelf.a)
LIBELF_SHARED := $(abspath $(LIB_DIR)/libelf.so)
LIBELF_BUILD_DIR := $(BUILD_DIR)/elfutils

$(LIBELF_TAR):
	$(call msg,WGET,$@)
	$(Q)wget https://sourceware.org/elfutils/ftp/0.189/elfutils-0.189.tar.bz2

$(LIBELF_SRC): $(LIBELF_TAR)
	$(call msg,SRC,$@)
	$(Q)tar -xf elfutils-0.189.tar.bz2
	$(Q)cd $(LIBELF_SRC) && autoreconf -i -f

$(LIBELF_BUILD_DIR)/Makefile: $(LIBELF_SRC) $(ZLIB_OBJ) | $(LIBELF_BUILD_DIR)
	$(call msg,CONFIG,$@)
	$(Q)cd $(LIBELF_BUILD_DIR) && CFLAGS="-Og -g3 $(shell PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' pkg-config --cflags --libs zlib)" \
		$(LIBELF_SRC)/configure \
			--host=$(TARGET) \
			--target=$(TARGET) \
			--program-prefix=eu- \
			--disable-libdebuginfod \
			--disable-debuginfod \
			--without-bzlib \
			--without-lzma \
			--without-zstd \
			--prefix=/usr \
			--sysconfdir=/etc \
			--localstatedir=/var

$(LIBELF_OBJ): $(LIBELF_BUILD_DIR)/Makefile $(ZLIB_OBJ) | $(LIBELF_BUILD_DIR)
	$(call msg,LIB,$@)
	$(Q)make V=$(V) -j $(NPROC) -C $(LIBELF_BUILD_DIR)
	$(Q)make V=$(V) -j $(NPROC) -C $(LIBELF_BUILD_DIR) DESTDIR="$(DEPS_DIR)" install
	$(Q)sed -i -e 's|prefix=/usr|prefix=$(DEPS_DIR)/usr|g' $(DEPS_DIR)/usr/lib/pkgconfig/libelf.pc
	$(Q)sed -i -e 's|prefix=/usr|prefix=$(DEPS_DIR)/usr|g' $(DEPS_DIR)/usr/lib/pkgconfig/libdw.pc

.PHONY: libelf
libelf: $(LIBELF_OBJ)

#
# libbpf
#

LIBBPF_SRC := $(abspath libbpf)

# libbpf build scripts install libraries to lib or lib64
# depending on a bitness of the architecture.
LIBBPF_OBJ := $(abspath $(LIB64_DIR)/libbpf.a)
LIBBPF_BUILD_DIR := $(BUILD_DIR)/libbpf

$(LIBBPF_OBJ): $(LIBBPF_SRC)/src/*.c $(LIBBPF_SRC)/src/*.h $(LIBBPF_SRC)/src/Makefile $(ZLIB_OBJ) $(LIBELF_OBJ) | $(LIBBPF_BUILD_DIR)
	$(call msg,LIB,$@)
	$(Q)CFLAGS="-Og -g3 $(shell PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' pkg-config --cflags --libs libelf)" CC=$(CC) \
		make V=$(V) -j $(NPROC) -C $(LIBBPF_SRC)/src OBJDIR=$(LIBBPF_BUILD_DIR)
	$(Q)CFLAGS="-Og -g3 $(shell PKG_CONFIG_PATH='$(PKG_CONFIG_PATH)' pkg-config --cflags --libs libelf)" CC=$(CC) \
		make V=$(V) -j $(NPROC) -C $(LIBBPF_SRC)/src OBJDIR=$(LIBBPF_BUILD_DIR) DESTDIR=$(DEPS_DIR) install install_uapi_headers
	$(Q)sed -i -e 's|prefix=/usr|prefix=$(DEPS_DIR)/usr|g' $(LIB64_DIR)/pkgconfig/libbpf.pc

.PHONY: libbpf
libbpf: $(LIBBPF_OBJ)

#
# Output directories
#

$(INCLUDE_DIR) $(LIB_DIR) $(ZLIB_BUILD_DIR) $(LIBELF_BUILD_DIR) $(LIBBPF_BUILD_DIR) $(APPS_BUILD_DIR) $(APPS_BIN_DIR):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

#
# Install vmlinux.h
#

VMLINUX_HEADERS := $(abspath headers/$(ARCH)/vmlinux.h)

$(INCLUDE_DIR)/vmlinux.h: $(VMLINUX_HEADERS) $(INCLUDE_DIR)
	$(call msg,HEADERS,$@)
	$(Q)cp $(shell readlink -e $(VMLINUX_HEADERS)) $@

#
# List all dependencies
#

DEPENDENCIES := $(LIBBPF_OBJ) $(ZLIB_OBJ) $(LIBELF_OBJ) $(INCLUDE_DIR)/vmlinux.h

.PHONY: build-deps
build-deps: $(DEPENDENCIES)

#
# Tap interface
#

USE_TAP ?= 0

TAP_NAME := tap1
TAP_IP_HOST := 10.42.0.1
TAP_IP_TARGET := 10.42.0.100

tap:
	$(call msg,CONFIG,tap interface)
	$(Q)ip tuntap add $(TAP_NAME) mode tap
	$(Q)ip addr add $(TAP_IP_HOST)/24 dev $(TAP_NAME)
	$(Q)ip link set $(TAP_NAME) up

ifeq ($(USE_TAP),1)
ARC_HOSTNAME := arc-tap
else
ARC_HOSTNAME := arc
endif

#
# Install all programs
#

define build =
$(APPS_BUILD_DIR)/$(1).bpf.o: $(APPS_SRC_DIR)/$(1).bpf.c $(DEPENDENCIES) | $(APPS_BUILD_DIR)
	$(call msg,OBJ,$$@)
	$(Q)$(CLANG) $(CLANG_CFLAGS) -c $$< -o $$@

$(APPS_BUILD_DIR)/$(1).skel.h: $(APPS_BUILD_DIR)/$(1).bpf.o | $(APPS_BUILD_DIR)
	$(call msg,SKEL,$$@)
	$(Q)bpftool gen skeleton $$< > $$@

$(APPS_BUILD_DIR)/$(1).o: $(APPS_SRC_DIR)/$(1).c $(APPS_BUILD_DIR)/$(1).skel.h $(DEPENDENCIES) | $(APPS_BUILD_DIR)
	$(call msg,OBJ,$$@)
	$(Q)$(CC) $(CFLAGS) -c $$< -o $$@

$(APPS_BIN_DIR)/$(1): $(APPS_BUILD_DIR)/$(1).o | $(APPS_BUILD_DIR) $(APPS_BIN_DIR)
	$(call msg,BIN,$$@)
	$(Q)$(CC) $(CFLAGS) $$< $(LDFLAGS_STATIC) -o $$@

$(APPS_BIN_DIR)/$(1)_shared: $(APPS_BUILD_DIR)/$(1).o | $(APPS_BUILD_DIR) $(APPS_BIN_DIR)
	$(call msg,BIN,$$@)
	$(Q)$(CC) $(CFLAGS) $$< $(LDFLAGS_SHARED) -o $$@

build-$(1): $(APPS_BIN_DIR)/$(1) $(APPS_BIN_DIR)/$(1)_shared

clean-$(1):
	$(call msg,CLEAN,$(1))
	$(Q)rm -f $(APPS_BIN_DIR)/$(1) $(APPS_BIN_DIR)/$(1)_shared $(APPS_BUILD_DIR)/$(1).o $(APPS_BUILD_DIR)/$(1).skel.h $(APPS_BUILD_DIR)/$(1).bpf.o

ifeq ($(CROSS),1)
qemu-load-$(1): $(APPS_BIN_DIR)/$(1)
	$(call msg,LOAD,$$^)
	$(Q)rsync $$^ $(ARC_HOSTNAME):

qemu-load-$(1)-shared: $(APPS_BIN_DIR)/$(1)_shared
	$(call msg,LOAD,$$^)
	$(Q)rsync $$^ $(ARC_HOSTNAME):

run-$(1): $(APPS_BIN_DIR)/$(1)
	$(call msg,RUN,$$<)
	$(Q)ssh -t $(ARC_HOSTNAME) "/root/$(1)"

run-$(1)-shared: $(APPS_BIN_DIR)/$(1)_shared
	$(call msg,RUN,$$<)
	$(Q)ssh -t $(ARC_HOSTNAME) "/root/$(1)_shared"
else
run-$(1): $(APPS_BIN_DIR)/$(1)
	$(call msg,RUN,$$<)
	$(Q)sudo $$<
endif

disas-$(1): $(APPS_BUILD_DIR)/$(1).bpf.o
	$(call msg,DISAS,$$<)
	$(Q)llvm-objdump -S --print-imm-hex $$<
endef

$(foreach app,$(APPS),$(eval $(call build,$(app))))

.PHONY: clean clean-apps clean-deps clean-all
clean: clean-apps
clean-apps:
	$(call msg,CLEAN,applications)
	$(Q)rm -rf $(APPS_BUILD_DIR) $(APPS_BIN_DIR)
clean-deps:
	$(call msg,CLEAN,dependencies)
	$(Q)rm -rf $(DEPS_DIR) $(ZLIB_BUILD_DIR) $(LIBELF_BUILD_DIR) $(LIBBPF_BUILD_DIR)
clean-all: clean-apps clean-deps

#
# QEMU
#

ifeq ($(CROSS),1)

LNXIMG  ?= linux/build/vmlinux
GDB     ?= $(TARGET)-gdb

ifeq ($(BITS),64)
QEMU    ?= qemu-system-arc64
else
QEMU    ?= qemu-system-arc
endif

QEMU_GDB_PORT := 2000

ifeq ($(USE_TAP),1)
QEMU_NETDEV := -netdev tap,id=net0,ifname=tap1,script=no,downscript=no
else
QEMU_FTP      := hostfwd=tcp::2021-:21
QEMU_SSH      := hostfwd=tcp::2022-:22
QEMU_TLN      := hostfwd=tcp::2023-:23
QEMU_NC       := hostfwd=tcp::2001-:2001
QEMU_NETDEV := -netdev user,id=net0,$(QEMU_FTP),$(QEMU_SSH),$(QEMU_TLN),$(QEMU_NC)
endif

QEMU_FLAGS    := -M virt -cpu archs -nographic -no-reboot \
                 -global cpu.freq_hz=50000000 $(QEMU_NETDEV) \
                 -device virtio-net-device,netdev=net0

.PHONY: qemu-start qemu-start-gdb qemu-connect qemu-load qemu-setup

qemu-start:
	$(QEMU) $(QEMU_FLAGS) -kernel $(LNXIMG)

qemu-start-gdb:
	$(QEMU) $(QEMU_FLAGS) -kernel $(LNXIMG) -S -gdb tcp::$(QEMU_GDB_PORT)

qemu-connect:
	$(GDB) -tui -q                                            \
			   -ex "add-auto-load-safe-path $(dir $(LNXIMG))" \
			   -ex "file $(LNXIMG)"                           \
			   -ex "set remotetimeout 3000"                   \
			   -ex "tar rem :$(QEMU_GDB_PORT)"                \
			   -ex "b bpf_int_jit_compile"                    \
			   -ex "cont"

qemu-load: $(patsubst %, qemu-load-%, $(APPS)) $(patsubst %, qemu-load-%-shared, $(APPS))

qemu-libs:
	$(call msg,QEMU,substitute shared libraries)
	rsync -cvilr $(LIB_DIR)/*.so* $(ARC_HOSTNAME):/usr/lib/

qemu-setup:
	$(call msg,QEMU,configure for eBPF)
	ssh $(ARC_HOSTNAME) "mount -t debugfs debugfs /sys/kernel/debug"
	ssh $(ARC_HOSTNAME) "sysctl net.core.bpf_jit_enable=1"

endif

#
# Default target
#

.PHONY: all help config

all: $(foreach app,$(APPS),build-$(app))

help:
	@echo  'Variables:'
	@echo  '    CROSS=0,1                   - Default: "1". Use cross compile mode or not. In'
	@echo  '                                  this mode all executables and libraries are built'
	@echo  '                                  for ARC platform. "qemu-*" targets are available in'
	@echo  '                                  this mode (see help below). If CROSS=0 then executables'
	@echo  '                                  and libraries are built for host.'
	@echo  '    CROSS_ARCH=arc,arc32,arc64  - Default: "arc". Version of Linux toolchain for ARC.'
	@echo  '    STDLIB=gnu,uclibc           - Default: "gnu". Standard library of Linux toolchain for ARC.'
	@echo  ''
	@echo  'Build commands:'
	@echo  '    all               - Build all applications with dependencies'
	@echo  '    build-deps        - Build dependencies only'
	@echo  '    build-<app>       - Build application <app>'
	@echo  "    disas-<app>       - Show <app>'s disassembly for eBPF part (<app>.bpf.o)"
	@echo  ''
	@echo  'Clean commands:'
	@echo  '    clean             - Clean applications'
	@echo  '    clean-deps        - Clean dependencies only'
	@echo  '    clean-all         - Clean everything'
	@echo  '    clean-<app>       - Clean application <app>'
	@echo  ''
	@echo  'List of applications:'
	@echo  '     $(APPS)'
	@echo  ''
ifeq ($(CROSS),1)
	@echo  'QEMU commands:'
	@echo  '    qemu-start        - Start QEMU using "vmlinux" image in the current directory'
	@echo  '                        Use LNXIMG to set your own vmlinux path'
	@echo  '    qemu-setup        - Enable debugfs and eBPF JIT on the target'
	@echo  '    qemu-start-gdb    - Start QEMU with GDB server on port $(QPORT)'
	@echo  '    qemu-connect      - Connect to QEMU using GDB'
	@echo  "    qemu-load         - Load all applications to target's /root directory"
	@echo  '    qemu-load-<app>   - Load application <app> only'
	@echo  '    run-<app>         - Run application <app> on the target'
else
	@echo  'Run commands:'
	@echo  '    run-<app>         - Run application <app> using sudo'
endif
	@echo  ''
	@echo  'Common commands:'
	@echo  '    config            - Show current configuration'
	@echo  '    tap               - Configure tap interface for QEMU (must be invoked as root)'

config:
	@echo  'ARCH = $(ARCH)'
	@echo  'CC = $(CC)'
	@echo  'CFLAGS = $(CFLAGS)'
	@echo  'LDFLAGS = $(LDFLAGS)'
	@echo  'CLANG_CFLAGS = $(CLANG_CFLAGS)'
