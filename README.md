# ARC eBPF Testbench

## Introduction

ARC eBPF testbench is intended to simplify building and running eBPF programs for ARC
processors. Essentially this testbench automates steps from
["Cross-compiling eBPF Programs"](https://foss-for-synopsys-dwc-arc-processors.github.io/toolchain/ebpf/cross.html) guide.

Also, it includes all necessary configuration files for building Linux kernel with
support of eBPF for testing purposes using QEMU (`extras` directory). This part of the
testbench corresponds to ["Building Linux Image for Working with eBPF in QEMU"](https://foss-for-synopsys-dwc-arc-processors.github.io/toolchain/ebpf/env.html) guide.

Right now ARC HS3x/4x processors only are fully supported by the testbench since eBPF JIT is implemented only for ARCv2 architecture. Support of JIT for eBPF
is necessary for using eBPF features like `bpf_loop` helper.

## Retrieving The Testbench

Clone the repository in one step:

```shell
git clone --recurse-submodules https://github.com/foss-for-synopsys-dwc-arc-processors/arc-bpf-testbench
```

Clone the repository in two steps:

```shell
git clone https://github.com/foss-for-synopsys-dwc-arc-processors/arc-bpf-testbench
cd arc-bpf-testbench
git submodule update --init --recursive
```

## Prerequisites

* **ARC GNU toolchain** for Linux must be in `PATH` environment variables. The testbench expects these names for binaries
(`stdlib` stands for `uclibc` or `gnu` depending on the type of used toolchain):

  * `arc-linux-<stdlib>-gcc` for HS3x/4x
  * `arc32-linux-<stdlib>-gcc` for HS5x
  * `arc64-linux-<stdlib>-gcc` for HS6x

* Consider using the latest available version of **Clang** for building eBPF programs with latest features. If Clang packages
for your Linux host are not available for any reason, then follow [Building Clang with eBPF Target for ARC HS Hosts](https://foss-for-synopsys-dwc-arc-processors.github.io/toolchain/ebpf/clang.html) guide for building Clang manually.

* `make`

* `bpftool`

## Structure of The Testbench

The testbench consists of a single `Makefile`. Submodules `libbpf`, `zlib` and `elfutils`
contain sources for all necessary dependencies for building eBPF programs.

`apps` directory contains examples of eBPF programs from [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap)
repository. Each application consists of 2 parts: eBPF part and an application itself (e.g., `minimal.bpf.c` and `minimal.c`
respectively). You can add your own `myapp` application to the testbench by placing corresponding files to the `app` directory
with following names: `myapp.bpf.c` and `myapp.c`.

## Building Applications

Build all applications from `apps` directory:

```plain
$ make
  MKDIR    /home/user/synopsys/arc-bpf-testbench/output/arc/build/zlib
  CONFIG   /home/user/synopsys/arc-bpf-testbench/output/arc/build/zlib/Makefile
Using arc-linux-gnu-ar
Using arc-linux-gnu-ranlib
Using arc-linux-gnu-nm
Checking for arc-linux-gnu-gcc...
Building static library libz.a version 1.2.13 with arc-linux-gnu-gcc.
Checking for size_t... Yes.
Checking for off64_t... Yes.
Checking for fseeko... Yes.
Checking for strerror... Yes.
...

$ ls output/arc/bin/
bootstrap  fentry  kprobe  minimal  minimal_legacy  sockfilter  tc  uprobe  usdt
```

Clean and rebuild `minimal` application only:

```plain
$ make clean-minimal
  CLEAN    minimal

$ make build-minimal
  OBJ      /home/user/synopsys/arc-bpf-testbench/output/arc/build/apps/minimal.bpf.o
  SKEL     /home/user/synopsys/arc-bpf-testbench/output/arc/build/apps/minimal.skel.h
  OBJ      /home/user/synopsys/arc-bpf-testbench/output/arc/build/apps/minimal.o
  BIN      /home/user/synopsys/arc-bpf-testbench/output/arc/bin/minimal
```

Show disassembly of eBPF part for `minimal` application:

```plain
$ make disas-minimal
  DISAS    /home/user/synopsys/arc-bpf-testbench/output/arc/build/apps/minimal.bpf.o

/home/user/synopsys/arc-bpf-testbench/output/arc/build/apps/minimal.bpf.o:	file format elf64-bpf

Disassembly of section tp/syscalls/sys_enter_write:

0000000000000000 <handle_tp>:
; 	int pid = bpf_get_current_pid_tgid() >> 32;
       0:	85 00 00 00 0e 00 00 00	call 0xe
       1:	77 00 00 00 20 00 00 00	r0 >>= 0x20
; 	if (pid != my_pid)
       2:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
       4:	61 11 00 00 00 00 00 00	r1 = *(u32 *)(r1 + 0x0)
       5:	5d 01 05 00 00 00 00 00	if r1 != r0 goto +0x5 <LBB0_2>
; 	bpf_printk("BPF triggered from PID %d.\n", pid);
       6:	18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00	r1 = 0x0 ll
       8:	b7 02 00 00 1c 00 00 00	r2 = 0x1c
       9:	bf 03 00 00 00 00 00 00	r3 = r0
      10:	85 00 00 00 06 00 00 00	call 0x6

0000000000000058 <LBB0_2>:
; }
      11:	b7 00 00 00 00 00 00 00	r0 = 0x0
      12:	95 00 00 00 00 00 00 00	exit
```

If you pass `CROSS=0` variable to `make` then testbench uses host's GCC and build
all dependencies and applications for the host. It's useful when it's necessary to
verify the same applications on the host. Example:

```plain
$ make CROSS=0
...

$ ls output/arm64/bin
bootstrap  fentry  kprobe  minimal  minimal_legacy  sockfilter  tc  uprobe  usdt

$  make CROSS=0 run-minimal
  RUN      /home/user/synopsys/arc-bpf-testbench/output/arm64/bin/minimal
[sudo] password for user: 
libbpf: loading object 'minimal_bpf' from buffer
libbpf: elf: section(3) tp/syscalls/sys_enter_write, size 104, link 0, flags 6, type=1
libbpf: sec 'tp/syscalls/sys_enter_write': found program 'handle_tp' at insn offset 0 (0 bytes), code size 13 insns (104 bytes)
libbpf: elf: section(4) .reltp/syscalls/sys_enter_write, size 32, link 22, flags 40, type=9
libbpf: elf: section(5) license, size 13, link 0, flags 3, type=1
libbpf: license of minimal_bpf is Dual BSD/GPL
libbpf: elf: section(6) .bss, size 4, link 0, flags 3, type=8
libbpf: elf: section(7) .rodata, size 28, link 0, flags 2, type=1
libbpf: elf: section(13) .BTF, size 600, link 0, flags 0, type=1
libbpf: elf: section(15) .BTF.ext, size 160, link 0, flags 0, type=1
libbpf: elf: section(22) .symtab, size 336, link 1, flags 0, type=2
libbpf: looking for externs among 14 symbols...
libbpf: collected 0 externs total
libbpf: map 'minimal_.bss' (global data): at sec_idx 6, offset 0, flags 400.
libbpf: map 0 is "minimal_.bss"
libbpf: map 'minimal_.rodata' (global data): at sec_idx 7, offset 0, flags 80.
libbpf: map 1 is "minimal_.rodata"
libbpf: sec '.reltp/syscalls/sys_enter_write': collecting relocation for section(3) 'tp/syscalls/sys_enter_write'
libbpf: sec '.reltp/syscalls/sys_enter_write': relo #0: insn #2 against 'my_pid'
libbpf: prog 'handle_tp': found data map 0 (minimal_.bss, sec 6, off 0) for insn 2
libbpf: sec '.reltp/syscalls/sys_enter_write': relo #1: insn #6 against '.rodata'
libbpf: prog 'handle_tp': found data map 1 (minimal_.rodata, sec 7, off 0) for insn 6
libbpf: map 'minimal_.bss': created successfully, fd=4
libbpf: map 'minimal_.rodata': created successfully, fd=5
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.
```

## Running Applications in QEMU

QEMU commands are reviewed in ["Building Linux Image for Working with eBPF in QEMU"](https://foss-for-synopsys-dwc-arc-processors.github.io/toolchain/ebpf/env.html) guide. Follow this guide to configure your environment properly.

## Getting Help for Commands

Run `make help` to get information about all available commands:

```plain
$ make help

Variables:
    CROSS=0,1                   - Default: "1". Use cross compile mode or not. In
                                  this mode all executables and libraries are built
                                  for ARC platform. "qemu-*" targets are available in
                                  this mode (see help below). If CROSS=0 then executables
                                  and libraries are built for host.
    CROSS_ARCH=arc,arc32,arc64  - Default: "arc". Version of Linux toolchain for ARC.
    STDLIB=gnu,uclibc           - Default: "gnu". Standard library of Linux toolchain for ARC.

Build commands:
    all               - Build all applications with dependencies
    build-deps        - Build dependencies only
    build-<app>       - Build application <app>
    disas-<app>       - Show <app>'s disassembly for eBPF part (<app>.bpf.o)

Clean commands:
    clean             - Clean applications
    clean-deps        - Clean dependencies only
    clean-all         - Clean everything
    clean-<app>       - Clean application <app>

List of applications:
     bootstrap fentry kprobe minimal minimal_legacy sockfilter tc uprobe usdt

QEMU commands:
    qemu-start        - Start QEMU using "vmlinux" image in the current directory
                        Use LNXIMG to set your own vmlinux path
    qemu-setup        - Enable debugfs and eBPF JIT on the target
    qemu-start-gdb    - Start QEMU with GDB server on port 
    qemu-connect      - Connect to QEMU using GDB
    qemu-load         - Load all applications to target's /root directory
    qemu-load-<app>   - Load application <app> only
    run-<app>         - Run application <app> on the target

Common commands:
    config            - Show current configuration
    tap               - Configure tap interface for QEMU (must be invoked as root)
```

## Versions of Submodules

| Library | Tag | Repository |
| ------- | --- | ---------- |
| `libbpf`| `v1.1.0` | <https://github.com/libbpf/libbpf> |
| `elfutils` | `elfutils-0.189` | <https://sourceware.org/git/elfutils.git> |
| `zlib` | `v1.2.13` | <https://github.com/madler/zlib> |
