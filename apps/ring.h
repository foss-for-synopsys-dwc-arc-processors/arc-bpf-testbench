#ifndef __RING_H
#define __RING_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 512

struct event {
	pid_t pid;
	pid_t ppid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
};

#endif /* __RING_H */
