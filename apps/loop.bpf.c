// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 Synopsys */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define N 5

char LICENSE[] SEC("license") = "Dual BSD/GPL";

int my_pid = 0;

static int callback(__u32 index, void *data)
{
	bpf_printk("Iteration: %d/%d.\n", index, N);
	return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid != my_pid)
		return 0;

	bpf_printk("BPF triggered from PID %d.\n", pid);
	bpf_printk("Looping %d times.\n", N);
	bpf_loop(N, callback, 0, 0);

	return 0;
}
