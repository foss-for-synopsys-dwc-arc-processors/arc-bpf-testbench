#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef struct {
	int counter;
} atomic_t;

struct refcount_struct {
	atomic_t refs;
};

typedef struct refcount_struct refcount_t;

typedef unsigned int __u32;

typedef __u32 u32;

struct load_weight {
	long unsigned int weight;
	u32 inv_weight;
};

struct rb_node {
	long unsigned int __rb_parent_color;
	struct rb_node *rb_right;
	struct rb_node *rb_left;
};

struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

typedef long long unsigned int __u64;

typedef __u64 u64;

struct sched_entity {
	struct load_weight load;
	struct rb_node run_node;
	struct list_head group_node;
	unsigned int on_rq;
	u64 exec_start;
	u64 sum_exec_runtime;
	u64 vruntime;
	u64 prev_sum_exec_runtime;
	u64 nr_migrations;
};

struct sched_rt_entity {
	struct list_head run_list;
	long unsigned int timeout;
	long unsigned int watchdog_stamp;
	unsigned int time_slice;
	short unsigned int on_rq;
	short unsigned int on_list;
	struct sched_rt_entity *back;
};

typedef long long int __s64;

typedef __s64 s64;

typedef s64 ktime_t;

struct timerqueue_node {
	struct rb_node node;
	ktime_t expires;
};

enum hrtimer_restart {
	HRTIMER_NORESTART = 0,
	HRTIMER_RESTART = 1,
};

typedef unsigned char __u8;

typedef __u8 u8;

struct hrtimer_clock_base;

struct hrtimer {
	struct timerqueue_node node;
	ktime_t _softexpires;
	enum hrtimer_restart (*function)(struct hrtimer *);
	struct hrtimer_clock_base *base;
	u8 state;
	u8 is_rel;
	u8 is_soft;
	u8 is_hard;
};

struct sched_dl_entity {
	struct rb_node rb_node;
	u64 dl_runtime;
	u64 dl_deadline;
	u64 dl_period;
	u64 dl_bw;
	u64 dl_density;
	s64 runtime;
	u64 deadline;
	unsigned int flags;
	unsigned int dl_throttled: 1;
	unsigned int dl_yielded: 1;
	unsigned int dl_non_contending: 1;
	unsigned int dl_overrun: 1;
	struct hrtimer dl_timer;
	struct hrtimer inactive_timer;
	struct sched_dl_entity *pi_se;
};

struct sched_statistics {};

struct cpumask {
	long unsigned int bits[1];
};

typedef struct cpumask cpumask_t;

union rcu_special {
	struct {
		u8 blocked;
		u8 need_qs;
		u8 exp_hint;
		u8 need_mb;
	} b;
	u32 s;
};

typedef _Bool bool;

struct sched_info {};

struct vm_area_struct;

struct vmacache {
	u64 seqnum;
	struct vm_area_struct *vmas[4];
};

typedef int __kernel_clockid_t;

typedef __kernel_clockid_t clockid_t;

enum timespec_type {
	TT_NONE = 0,
	TT_NATIVE = 1,
	TT_COMPAT = 2,
};

struct __kernel_timespec;

struct old_timespec32;

struct pollfd;

struct restart_block {
	long unsigned int arch_data;
	long int (*fn)(struct restart_block *);
	union {
		struct {
			u32 *uaddr;
			u32 val;
			u32 flags;
			u32 bitset;
			u64 time;
			u32 *uaddr2;
		} futex;
		struct {
			clockid_t clockid;
			enum timespec_type type;
			union {
				struct __kernel_timespec *rmtp;
				struct old_timespec32 *compat_rmtp;
			};
			u64 expires;
		} nanosleep;
		struct {
			struct pollfd *ufds;
			int nfds;
			int has_timeout;
			long unsigned int tv_sec;
			long unsigned int tv_nsec;
		} poll;
	};
};

typedef int __kernel_pid_t;

typedef __kernel_pid_t pid_t;

struct hlist_node {
	struct hlist_node *next;
	struct hlist_node **pprev;
};

typedef struct {} arch_spinlock_t;

struct raw_spinlock {
	arch_spinlock_t raw_lock;
};

typedef struct raw_spinlock raw_spinlock_t;

struct prev_cputime {
	u64 utime;
	u64 stime;
	raw_spinlock_t lock;
};

struct rb_root {
	struct rb_node *rb_node;
};

struct rb_root_cached {
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;
};

struct timerqueue_head {
	struct rb_root_cached rb_root;
};

struct posix_cputimer_base {
	u64 nextevt;
	struct timerqueue_head tqhead;
};

struct posix_cputimers {
	struct posix_cputimer_base bases[3];
	unsigned int timers_active;
	unsigned int expiry_active;
};

struct sem_undo_list;

struct sysv_sem {
	struct sem_undo_list *undo_list;
};

struct sysv_shm {
	struct list_head shm_clist;
};

typedef struct {
	long unsigned int sig[2];
} sigset_t;

struct sigpending {
	struct list_head list;
	sigset_t signal;
};

typedef unsigned int __kernel_size_t;

typedef __kernel_size_t size_t;

struct seccomp {};

struct syscall_user_dispatch {};

struct spinlock {
	union {
		struct raw_spinlock rlock;
	};
};

typedef struct spinlock spinlock_t;

struct wake_q_node {
	struct wake_q_node *next;
};

struct irqtrace_events {
	unsigned int irq_events;
	long unsigned int hardirq_enable_ip;
	long unsigned int hardirq_disable_ip;
	unsigned int hardirq_enable_event;
	unsigned int hardirq_disable_event;
	long unsigned int softirq_disable_ip;
	long unsigned int softirq_enable_ip;
	unsigned int softirq_disable_event;
	unsigned int softirq_enable_event;
};

struct task_io_accounting {};

typedef atomic_t atomic_long_t;

struct mutex {
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct tlbflush_unmap_batch {};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *);
};

typedef short unsigned int __u16;

struct page;

struct page_frag {
	struct page *page;
	__u16 offset;
	__u16 size;
};

struct kmap_ctrl {};

struct timer_list {
	struct hlist_node entry;
	long unsigned int expires;
	void (*function)(struct timer_list *);
	u32 flags;
};

struct llist_node;

struct llist_head {
	struct llist_node *first;
};

struct thread_struct {
	long unsigned int ksp;
	long unsigned int callee_reg;
	long unsigned int fault_address;
};

struct sched_class;

struct rcu_node;

struct mm_struct;

struct pid;

struct completion;

struct cred;

struct nameidata;

struct fs_struct;

struct files_struct;

struct io_uring_task;

struct nsproxy;

struct signal_struct;

struct sighand_struct;

struct rt_mutex_waiter;

struct bio_list;

struct blk_plug;

struct reclaim_state;

struct backing_dev_info;

struct io_context;

struct kernel_siginfo;

typedef struct kernel_siginfo kernel_siginfo_t;

struct robust_list_head;

struct futex_pi_state;

struct perf_event_context;

struct pipe_inode_info;

struct bpf_local_storage;

struct bpf_run_ctx;

struct task_struct {
	unsigned int __state;
	void *stack;
	refcount_t usage;
	unsigned int flags;
	unsigned int ptrace;
	int on_rq;
	int prio;
	int static_prio;
	int normal_prio;
	unsigned int rt_priority;
	struct sched_entity se;
	struct sched_rt_entity rt;
	struct sched_dl_entity dl;
	const struct sched_class *sched_class;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct sched_statistics stats;
	unsigned int policy;
	int nr_cpus_allowed;
	const cpumask_t *cpus_ptr;
	cpumask_t *user_cpus_ptr;
	cpumask_t cpus_mask;
	void *migration_pending;
	short unsigned int migration_flags;
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
	long unsigned int rcu_tasks_nvcsw;
	u8 rcu_tasks_holdout;
	u8 rcu_tasks_idx;
	int rcu_tasks_idle_cpu;
	struct list_head rcu_tasks_holdout_list;
	int trc_reader_nesting;
	int trc_ipi_to_cpu;
	union rcu_special trc_reader_special;
	bool trc_reader_checked;
	struct list_head trc_holdout_list;
	struct sched_info sched_info;
	struct list_head tasks;
	struct mm_struct *mm;
	struct mm_struct *active_mm;
	struct vmacache vmacache;
	int exit_state;
	int exit_code;
	int exit_signal;
	int pdeath_signal;
	long unsigned int jobctl;
	unsigned int personality;
	unsigned int sched_reset_on_fork: 1;
	unsigned int sched_contributes_to_load: 1;
	unsigned int sched_migrated: 1;
	int: 29;
	unsigned int sched_remote_wakeup: 1;
	unsigned int in_execve: 1;
	unsigned int in_iowait: 1;
	unsigned int in_eventfd_signal: 1;
	long unsigned int atomic_flags;
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
	struct task_struct *real_parent;
	struct task_struct *parent;
	struct list_head children;
	struct list_head sibling;
	struct task_struct *group_leader;
	struct list_head ptraced;
	struct list_head ptrace_entry;
	struct pid *thread_pid;
	struct hlist_node pid_links[4];
	struct list_head thread_group;
	struct list_head thread_node;
	struct completion *vfork_done;
	int *set_child_tid;
	int *clear_child_tid;
	void *worker_private;
	u64 utime;
	u64 stime;
	u64 gtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	u64 start_time;
	u64 start_boottime;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	struct posix_cputimers posix_cputimers;
	const struct cred *ptracer_cred;
	const struct cred *real_cred;
	const struct cred *cred;
	char comm[16];
	struct nameidata *nameidata;
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
	struct fs_struct *fs;
	struct files_struct *files;
	struct io_uring_task *io_uring;
	struct nsproxy *nsproxy;
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked;
	sigset_t real_blocked;
	sigset_t saved_sigmask;
	struct sigpending pending;
	long unsigned int sas_ss_sp;
	size_t sas_ss_size;
	unsigned int sas_ss_flags;
	struct callback_head *task_works;
	struct seccomp seccomp;
	struct syscall_user_dispatch syscall_dispatch;
	u64 parent_exec_id;
	u64 self_exec_id;
	spinlock_t alloc_lock;
	raw_spinlock_t pi_lock;
	struct wake_q_node wake_q;
	struct rb_root_cached pi_waiters;
	struct task_struct *pi_top_task;
	struct rt_mutex_waiter *pi_blocked_on;
	struct irqtrace_events irqtrace;
	unsigned int hardirq_threaded;
	u64 hardirq_chain_key;
	int softirqs_enabled;
	int softirq_context;
	int irq_config;
	void *journal_info;
	struct bio_list *bio_list;
	struct blk_plug *plug;
	struct reclaim_state *reclaim_state;
	struct backing_dev_info *backing_dev_info;
	struct io_context *io_context;
	long unsigned int ptrace_message;
	kernel_siginfo_t *last_siginfo;
	struct task_io_accounting ioac;
	struct robust_list_head *robust_list;
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
	struct mutex futex_exit_mutex;
	unsigned int futex_state;
	struct perf_event_context *perf_event_ctxp[2];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
	struct tlbflush_unmap_batch tlb_ubc;
	union {
		refcount_t rcu_users;
		struct callback_head rcu;
	};
	struct pipe_inode_info *splice_pipe;
	struct page_frag task_frag;
	int nr_dirtied;
	int nr_dirtied_pause;
	long unsigned int dirty_paused_when;
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
	long unsigned int trace;
	long unsigned int trace_recursion;
	struct kmap_ctrl kmap_ctrl;
	int pagefault_disabled;
	struct task_struct *oom_reaper_list;
	struct timer_list oom_reaper_timer;
	struct bpf_local_storage *bpf_storage;
	struct bpf_run_ctx *bpf_ctx;
	struct llist_head kretprobe_instances;
	struct thread_struct thread;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

typedef signed char __s8;

typedef short int __s16;

typedef int __s32;

typedef __s8 s8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

enum {
	false = 0,
	true = 1,
};

typedef long int __kernel_long_t;

typedef long unsigned int __kernel_ulong_t;

typedef unsigned int __kernel_uid32_t;

typedef unsigned int __kernel_gid32_t;

typedef int __kernel_ssize_t;

typedef long long int __kernel_loff_t;

typedef long long int __kernel_time64_t;

typedef __kernel_long_t __kernel_clock_t;

typedef int __kernel_timer_t;

typedef __u16 __be16;

typedef __u32 __le32;

typedef __u32 __be32;

typedef __u32 __wsum;

typedef unsigned int __poll_t;

typedef u32 __kernel_dev_t;

typedef __kernel_dev_t dev_t;

typedef short unsigned int umode_t;

typedef __kernel_uid32_t uid_t;

typedef __kernel_gid32_t gid_t;

typedef __kernel_loff_t loff_t;

typedef __kernel_ssize_t ssize_t;

typedef u16 uint16_t;

typedef u32 uint32_t;

typedef u64 uint64_t;

typedef u64 sector_t;

typedef u64 blkcnt_t;

typedef unsigned int gfp_t;

typedef unsigned int fmode_t;

typedef u32 phys_addr_t;

struct hlist_head {
	struct hlist_node *first;
};

typedef struct {
	s64 counter;
} atomic64_t;

typedef __s64 time64_t;

struct __kernel_timespec {
	__kernel_time64_t tv_sec;
	long long int tv_nsec;
};

struct timespec64 {
	time64_t tv_sec;
	long int tv_nsec;
};

typedef s32 old_time32_t;

struct old_timespec32 {
	old_time32_t tv_sec;
	s32 tv_nsec;
};

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map {
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[5];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

typedef struct {
	uid_t val;
} kuid_t;

typedef struct {
	gid_t val;
} kgid_t;

struct proc_ns_operations;

struct ns_common {
	atomic_long_t stashed;
	const struct proc_ns_operations *ops;
	unsigned int inum;
	refcount_t count;
};

struct work_struct;

typedef void (*work_func_t)(struct work_struct *);

struct work_struct {
	atomic_long_t data;
	struct list_head entry;
	work_func_t func;
};

struct ctl_table;

struct ctl_table_root;

struct ctl_table_set;

struct ctl_dir;

struct ctl_node;

struct ctl_table_header {
	union {
		struct {
			struct ctl_table *ctl_table;
			int used;
			int count;
			int nreg;
		};
		struct callback_head rcu;
	};
	struct completion *unregistering;
	struct ctl_table *ctl_table_arg;
	struct ctl_table_root *root;
	struct ctl_table_set *set;
	struct ctl_dir *parent;
	struct ctl_node *node;
	struct hlist_head inodes;
};

struct ctl_dir {
	struct ctl_table_header header;
	struct rb_root root;
};

struct ctl_table_set {
	int (*is_seen)(struct ctl_table_set *);
	struct ctl_dir dir;
};

struct ucounts;

struct user_namespace {
	struct uid_gid_map uid_map;
	struct uid_gid_map gid_map;
	struct uid_gid_map projid_map;
	struct user_namespace *parent;
	int level;
	kuid_t owner;
	kgid_t group;
	struct ns_common ns;
	long unsigned int flags;
	bool parent_could_setfcap;
	struct work_struct work;
	struct ctl_table_set set;
	struct ctl_table_header *sysctls;
	struct ucounts *ucounts;
	long int ucount_max[14];
};

struct kstat {
	u32 result_mask;
	umode_t mode;
	unsigned int nlink;
	uint32_t blksize;
	u64 attributes;
	u64 attributes_mask;
	u64 ino;
	dev_t dev;
	dev_t rdev;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	struct timespec64 btime;
	u64 blocks;
	u64 mnt_id;
};

struct kernel_symbol {
	long unsigned int value;
	const char *name;
	const char *namespace;
};

typedef int (*initcall_t)();

typedef initcall_t initcall_entry_t;

struct lock_class_key {};

struct fs_context;

struct fs_parameter_spec;

struct dentry;

struct super_block;

struct module;

struct file_system_type {
	const char *name;
	int fs_flags;
	int (*init_fs_context)(struct fs_context *);
	const struct fs_parameter_spec *parameters;
	struct dentry * (*mount)(struct file_system_type *, int, const char *, void *);
	void (*kill_sb)(struct super_block *);
	struct module *owner;
	struct file_system_type *next;
	struct hlist_head fs_supers;
	struct lock_class_key s_lock_key;
	struct lock_class_key s_umount_key;
	struct lock_class_key s_vfs_rename_key;
	struct lock_class_key s_writers_key[3];
	struct lock_class_key i_lock_key;
	struct lock_class_key i_mutex_key;
	struct lock_class_key invalidate_lock_key;
	struct lock_class_key i_mutex_dir_key;
};

struct obs_kernel_param {
	const char *str;
	int (*setup_func)(char *);
	int early;
};

typedef struct {} arch_rwlock_t;

struct lockdep_map {};

struct ratelimit_state {
	raw_spinlock_t lock;
	int interval;
	int burst;
	int printed;
	int missed;
	long unsigned int begin;
	long unsigned int flags;
};

typedef void *fl_owner_t;

struct file;

struct kiocb;

struct iov_iter;

struct io_comp_batch;

struct dir_context;

struct poll_table_struct;

struct inode;

struct file_lock;

struct seq_file;

struct file_operations {
	struct module *owner;
	loff_t (*llseek)(struct file *, loff_t, int);
	ssize_t (*read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*write)(struct file *, const char *, size_t, loff_t *);
	ssize_t (*read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*write_iter)(struct kiocb *, struct iov_iter *);
	int (*iopoll)(struct kiocb *, struct io_comp_batch *, unsigned int);
	int (*iterate)(struct file *, struct dir_context *);
	int (*iterate_shared)(struct file *, struct dir_context *);
	__poll_t (*poll)(struct file *, struct poll_table_struct *);
	long int (*unlocked_ioctl)(struct file *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*mmap)(struct file *, struct vm_area_struct *);
	long unsigned int mmap_supported_flags;
	int (*open)(struct inode *, struct file *);
	int (*flush)(struct file *, fl_owner_t);
	int (*release)(struct inode *, struct file *);
	int (*fsync)(struct file *, loff_t, loff_t, int);
	int (*fasync)(int, struct file *, int);
	int (*lock)(struct file *, int, struct file_lock *);
	ssize_t (*sendpage)(struct file *, struct page *, int, size_t, loff_t *, int);
	long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
	int (*check_flags)(int);
	int (*flock)(struct file *, int, struct file_lock *);
	ssize_t (*splice_write)(struct pipe_inode_info *, struct file *, loff_t *, size_t, unsigned int);
	ssize_t (*splice_read)(struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*setlease)(struct file *, long int, struct file_lock **, void **);
	long int (*fallocate)(struct file *, int, loff_t, loff_t);
	void (*show_fdinfo)(struct seq_file *, struct file *);
	ssize_t (*copy_file_range)(struct file *, loff_t, struct file *, loff_t, size_t, unsigned int);
	loff_t (*remap_file_range)(struct file *, loff_t, struct file *, loff_t, loff_t, unsigned int);
	int (*fadvise)(struct file *, loff_t, loff_t, int);
};

struct static_call_key {
	void *func;
};

enum system_states {
	SYSTEM_BOOTING = 0,
	SYSTEM_SCHEDULING = 1,
	SYSTEM_FREEING_INITMEM = 2,
	SYSTEM_RUNNING = 3,
	SYSTEM_HALT = 4,
	SYSTEM_POWER_OFF = 5,
	SYSTEM_RESTART = 6,
	SYSTEM_SUSPEND = 7,
};

struct pt_regs {
	long unsigned int orig_r0;
	union {
		struct {
			long unsigned int ecr_param: 8;
			long unsigned int ecr_cause: 8;
			long unsigned int ecr_vec: 8;
			long unsigned int state: 8;
		};
		long unsigned int event;
	};
	long unsigned int bta;
	long unsigned int user_r25;
	long unsigned int r26;
	long unsigned int fp;
	long unsigned int sp;
	long unsigned int r12;
	long unsigned int r30;
	long unsigned int r58;
	long unsigned int r59;
	long unsigned int r0;
	long unsigned int r1;
	long unsigned int r2;
	long unsigned int r3;
	long unsigned int r4;
	long unsigned int r5;
	long unsigned int r6;
	long unsigned int r7;
	long unsigned int r8;
	long unsigned int r9;
	long unsigned int r10;
	long unsigned int r11;
	long unsigned int blink;
	long unsigned int lp_end;
	long unsigned int lp_start;
	long unsigned int lp_count;
	long unsigned int ei;
	long unsigned int ldi;
	long unsigned int jli;
	long unsigned int ret;
	long unsigned int status32;
};

typedef struct cpumask cpumask_var_t[1];

typedef struct {
	long unsigned int pgd;
} pgd_t;

typedef struct {
	long unsigned int pte;
} pte_t;

typedef struct {
	long unsigned int pgprot;
} pgprot_t;

typedef struct page *pgtable_t;

struct address_space;

struct page_pool;

struct dev_pagemap;

struct page {
	long unsigned int flags;
	union {
		struct {
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			long unsigned int private;
		};
		struct {
			long unsigned int pp_magic;
			struct page_pool *pp;
			long unsigned int _pp_mapping_pad;
			long unsigned int dma_addr;
			union {
				long unsigned int dma_addr_upper;
				atomic_long_t pp_frag_count;
			};
		};
		struct {
			long unsigned int compound_head;
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
		};
		struct {
			long unsigned int _compound_pad_1;
			long unsigned int _compound_pad_2;
			struct list_head deferred_list;
		};
		struct {
			long unsigned int _pt_pad_1;
			pgtable_t pmd_huge_pte;
			long unsigned int _pt_pad_2;
			union {
				struct mm_struct *pt_mm;
				atomic_t pt_frag_refcount;
			};
			spinlock_t ptl;
		};
		struct {
			struct dev_pagemap *pgmap;
			void *zone_device_data;
		};
		struct callback_head callback_head;
	};
	union {
		atomic_t _mapcount;
		unsigned int page_type;
	};
	atomic_t _refcount;
	void *virtual;
};

struct vm_userfaultfd_ctx {};

struct anon_vma_name;

struct anon_vma;

struct vm_operations_struct;

struct vm_area_struct {
	long unsigned int vm_start;
	long unsigned int vm_end;
	struct vm_area_struct *vm_next;
	struct vm_area_struct *vm_prev;
	struct rb_node vm_rb;
	long unsigned int rb_subtree_gap;
	struct mm_struct *vm_mm;
	pgprot_t vm_page_prot;
	long unsigned int vm_flags;
	union {
		struct {
			struct rb_node rb;
			long unsigned int rb_subtree_last;
		} shared;
		struct anon_vma_name *anon_name;
	};
	struct list_head anon_vma_chain;
	struct anon_vma *anon_vma;
	const struct vm_operations_struct *vm_ops;
	long unsigned int vm_pgoff;
	struct file *vm_file;
	void *vm_private_data;
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
};

struct mm_rss_stat {
	atomic_long_t count[4];
};

struct pollfd {
	int fd;
	short int events;
	short int revents;
};

struct thread_info {
	long unsigned int flags;
	int preempt_count;
	struct task_struct *task;
	__u32 cpu;
	long unsigned int thr_ptr;
};

struct llist_node {
	struct llist_node *next;
};

struct __call_single_node {
	struct llist_node llist;
	union {
		unsigned int u_flags;
		atomic_t a_flags;
	};
};

typedef struct {
	arch_rwlock_t raw_lock;
} rwlock_t;

enum refcount_saturation_type {
	REFCOUNT_ADD_NOT_ZERO_OVF = 0,
	REFCOUNT_ADD_OVF = 1,
	REFCOUNT_ADD_UAF = 2,
	REFCOUNT_SUB_UAF = 3,
	REFCOUNT_DEC_LEAK = 4,
};

struct kref {
	refcount_t refcount;
};

struct rw_semaphore {
	atomic_long_t count;
	atomic_long_t owner;
	raw_spinlock_t wait_lock;
	struct list_head wait_list;
};

struct wait_queue_entry;

typedef int (*wait_queue_func_t)(struct wait_queue_entry *, unsigned int, int, void *);

struct wait_queue_entry {
	unsigned int flags;
	void *private;
	wait_queue_func_t func;
	struct list_head entry;
};

typedef struct wait_queue_entry wait_queue_entry_t;

struct wait_queue_head {
	spinlock_t lock;
	struct list_head head;
};

typedef struct wait_queue_head wait_queue_head_t;

struct swait_queue_head {
	raw_spinlock_t lock;
	struct list_head task_list;
};

struct completion {
	unsigned int done;
	struct swait_queue_head wait;
};

struct seqcount {
	unsigned int sequence;
};

typedef struct seqcount seqcount_t;

typedef struct {
	long unsigned int asid[1];
} mm_context_t;

struct uprobes_state {};

struct linux_binfmt;

struct kioctx_table;

struct mm_struct {
	struct {
		struct vm_area_struct *mmap;
		struct rb_root mm_rb;
		u64 vmacache_seqnum;
		long unsigned int (*get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
		long unsigned int mmap_base;
		long unsigned int mmap_legacy_base;
		long unsigned int task_size;
		long unsigned int highest_vm_end;
		pgd_t *pgd;
		atomic_t membarrier_state;
		atomic_t mm_users;
		atomic_t mm_count;
		atomic_long_t pgtables_bytes;
		int map_count;
		spinlock_t page_table_lock;
		struct rw_semaphore mmap_lock;
		struct list_head mmlist;
		long unsigned int hiwater_rss;
		long unsigned int hiwater_vm;
		long unsigned int total_vm;
		long unsigned int locked_vm;
		int: 32;
		atomic64_t pinned_vm;
		long unsigned int data_vm;
		long unsigned int exec_vm;
		long unsigned int stack_vm;
		long unsigned int def_flags;
		seqcount_t write_protect_seq;
		spinlock_t arg_lock;
		long unsigned int start_code;
		long unsigned int end_code;
		long unsigned int start_data;
		long unsigned int end_data;
		long unsigned int start_brk;
		long unsigned int brk;
		long unsigned int start_stack;
		long unsigned int arg_start;
		long unsigned int arg_end;
		long unsigned int env_start;
		long unsigned int env_end;
		long unsigned int saved_auxv[42];
		struct mm_rss_stat rss_stat;
		struct linux_binfmt *binfmt;
		mm_context_t context;
		long unsigned int flags;
		spinlock_t ioctx_lock;
		struct kioctx_table *ioctx_table;
		struct user_namespace *user_ns;
		struct file *exe_file;
		atomic_t tlb_flush_pending;
		struct uprobes_state uprobes_state;
		struct work_struct async_put_work;
		int: 32;
	};
	long unsigned int cpu_bitmap[0];
};

struct workqueue_struct;

struct delayed_work {
	struct work_struct work;
	struct timer_list timer;
	struct workqueue_struct *wq;
	int cpu;
};

struct seqcount_raw_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_raw_spinlock seqcount_raw_spinlock_t;

struct seqcount_spinlock {
	seqcount_t seqcount;
};

typedef struct seqcount_spinlock seqcount_spinlock_t;

typedef struct {
	seqcount_spinlock_t seqcount;
	spinlock_t lock;
} seqlock_t;

struct xarray {
	spinlock_t xa_lock;
	gfp_t xa_flags;
	void *xa_head;
};

typedef u32 errseq_t;

struct address_space_operations;

struct address_space {
	struct inode *host;
	struct xarray i_pages;
	struct rw_semaphore invalidate_lock;
	gfp_t gfp_mask;
	atomic_t i_mmap_writable;
	struct rb_root_cached i_mmap;
	struct rw_semaphore i_mmap_rwsem;
	long unsigned int nrpages;
	long unsigned int writeback_index;
	const struct address_space_operations *a_ops;
	long unsigned int flags;
	errseq_t wb_err;
	spinlock_t private_lock;
	struct list_head private_list;
	void *private_data;
};

enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};

struct device;

struct page_pool_params {
	unsigned int flags;
	unsigned int order;
	unsigned int pool_size;
	int nid;
	struct device *dev;
	enum dma_data_direction dma_dir;
	unsigned int max_len;
	unsigned int offset;
	void (*init_callback)(struct page *, void *);
	void *init_arg;
};

struct pp_alloc_cache {
	u32 count;
	struct page *cache[128];
};

struct ptr_ring {
	int producer;
	spinlock_t producer_lock;
	int consumer_head;
	int consumer_tail;
	spinlock_t consumer_lock;
	int size;
	int batch;
	void **queue;
};

struct page_pool {
	struct page_pool_params p;
	struct delayed_work release_dw;
	void (*disconnect)(void *);
	long unsigned int defer_start;
	long unsigned int defer_warn;
	u32 pages_state_hold_cnt;
	unsigned int frag_offset;
	struct page *frag_page;
	long int frag_users;
	u32 xdp_mem_id;
	struct pp_alloc_cache alloc;
	struct ptr_ring ring;
	atomic_t pages_state_release_cnt;
	refcount_t user_cnt;
	u64 destroy_cnt;
};

struct folio {
	union {
		struct {
			long unsigned int flags;
			union {
				struct list_head lru;
				struct {
					void *__filler;
					unsigned int mlock_count;
				};
			};
			struct address_space *mapping;
			long unsigned int index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
		};
		struct page page;
	};
};

struct vfsmount;

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

enum pid_type {
	PIDTYPE_PID = 0,
	PIDTYPE_TGID = 1,
	PIDTYPE_PGID = 2,
	PIDTYPE_SID = 3,
	PIDTYPE_MAX = 4,
};

struct fown_struct {
	rwlock_t lock;
	struct pid *pid;
	enum pid_type pid_type;
	kuid_t uid;
	kuid_t euid;
	int signum;
};

struct file_ra_state {
	long unsigned int start;
	unsigned int size;
	unsigned int async_size;
	unsigned int ra_pages;
	unsigned int mmap_miss;
	loff_t prev_pos;
};

struct file {
	union {
		struct llist_node fu_llist;
		struct callback_head fu_rcuhead;
	} f_u;
	struct path f_path;
	struct inode *f_inode;
	const struct file_operations *f_op;
	spinlock_t f_lock;
	atomic_long_t f_count;
	unsigned int f_flags;
	fmode_t f_mode;
	struct mutex f_pos_lock;
	loff_t f_pos;
	struct fown_struct f_owner;
	const struct cred *f_cred;
	struct file_ra_state f_ra;
	u64 f_version;
	void *private_data;
	struct hlist_head *f_ep;
	struct address_space *f_mapping;
	errseq_t f_wb_err;
	errseq_t f_sb_err;
};

struct anon_vma_name {
	struct kref kref;
	char name[0];
};

struct anon_vma {
	struct anon_vma *root;
	struct rw_semaphore rwsem;
	atomic_t refcount;
	unsigned int degree;
	struct anon_vma *parent;
	struct rb_root_cached rb_root;
};

typedef unsigned int vm_fault_t;

enum page_entry_size {
	PE_SIZE_PTE = 0,
	PE_SIZE_PMD = 1,
	PE_SIZE_PUD = 2,
};

struct vm_fault;

struct vm_operations_struct {
	void (*open)(struct vm_area_struct *);
	void (*close)(struct vm_area_struct *);
	int (*may_split)(struct vm_area_struct *, long unsigned int);
	int (*mremap)(struct vm_area_struct *);
	int (*mprotect)(struct vm_area_struct *, long unsigned int, long unsigned int, long unsigned int);
	vm_fault_t (*fault)(struct vm_fault *);
	vm_fault_t (*huge_fault)(struct vm_fault *, enum page_entry_size);
	vm_fault_t (*map_pages)(struct vm_fault *, long unsigned int, long unsigned int);
	long unsigned int (*pagesize)(struct vm_area_struct *);
	vm_fault_t (*page_mkwrite)(struct vm_fault *);
	vm_fault_t (*pfn_mkwrite)(struct vm_fault *);
	int (*access)(struct vm_area_struct *, long unsigned int, void *, int, int);
	const char * (*name)(struct vm_area_struct *);
	struct page * (*find_special_page)(struct vm_area_struct *, long unsigned int);
};

struct linux_binprm;

struct coredump_params;

struct linux_binfmt {
	struct list_head lh;
	struct module *module;
	int (*load_binary)(struct linux_binprm *);
	int (*load_shlib)(struct file *);
	int (*core_dump)(struct coredump_params *);
	long unsigned int min_coredump;
};

enum fault_flag {
	FAULT_FLAG_WRITE = 1,
	FAULT_FLAG_MKWRITE = 2,
	FAULT_FLAG_ALLOW_RETRY = 4,
	FAULT_FLAG_RETRY_NOWAIT = 8,
	FAULT_FLAG_KILLABLE = 16,
	FAULT_FLAG_TRIED = 32,
	FAULT_FLAG_USER = 64,
	FAULT_FLAG_REMOTE = 128,
	FAULT_FLAG_INSTRUCTION = 256,
	FAULT_FLAG_INTERRUPTIBLE = 512,
};

typedef struct {
	pgd_t pgd;
} p4d_t;

typedef struct {
	p4d_t p4d;
} pud_t;

typedef struct {
	pud_t pud;
} pmd_t;

struct vm_fault {
	const struct {
		struct vm_area_struct *vma;
		gfp_t gfp_mask;
		long unsigned int pgoff;
		long unsigned int address;
		long unsigned int real_address;
	};
	enum fault_flag flags;
	pmd_t *pmd;
	pud_t *pud;
	union {
		pte_t orig_pte;
		pmd_t orig_pmd;
	};
	struct page *cow_page;
	struct page *page;
	pte_t *pte;
	spinlock_t *ptl;
	pgtable_t prealloc_pte;
};

typedef struct {
	long unsigned int bits[1];
} nodemask_t;

enum node_states {
	N_POSSIBLE = 0,
	N_ONLINE = 1,
	N_NORMAL_MEMORY = 2,
	N_HIGH_MEMORY = 2,
	N_MEMORY = 3,
	N_CPU = 4,
	N_GENERIC_INITIATOR = 5,
	NR_NODE_STATES = 6,
};

struct free_area {
	struct list_head free_list[4];
	long unsigned int nr_free;
};

enum node_stat_item {
	NR_LRU_BASE = 0,
	NR_INACTIVE_ANON = 0,
	NR_ACTIVE_ANON = 1,
	NR_INACTIVE_FILE = 2,
	NR_ACTIVE_FILE = 3,
	NR_UNEVICTABLE = 4,
	NR_SLAB_RECLAIMABLE_B = 5,
	NR_SLAB_UNRECLAIMABLE_B = 6,
	NR_ISOLATED_ANON = 7,
	NR_ISOLATED_FILE = 8,
	WORKINGSET_NODES = 9,
	WORKINGSET_REFAULT_BASE = 10,
	WORKINGSET_REFAULT_ANON = 10,
	WORKINGSET_REFAULT_FILE = 11,
	WORKINGSET_ACTIVATE_BASE = 12,
	WORKINGSET_ACTIVATE_ANON = 12,
	WORKINGSET_ACTIVATE_FILE = 13,
	WORKINGSET_RESTORE_BASE = 14,
	WORKINGSET_RESTORE_ANON = 14,
	WORKINGSET_RESTORE_FILE = 15,
	WORKINGSET_NODERECLAIM = 16,
	NR_ANON_MAPPED = 17,
	NR_FILE_MAPPED = 18,
	NR_FILE_PAGES = 19,
	NR_FILE_DIRTY = 20,
	NR_WRITEBACK = 21,
	NR_WRITEBACK_TEMP = 22,
	NR_SHMEM = 23,
	NR_SHMEM_THPS = 24,
	NR_SHMEM_PMDMAPPED = 25,
	NR_FILE_THPS = 26,
	NR_FILE_PMDMAPPED = 27,
	NR_ANON_THPS = 28,
	NR_VMSCAN_WRITE = 29,
	NR_VMSCAN_IMMEDIATE = 30,
	NR_DIRTIED = 31,
	NR_WRITTEN = 32,
	NR_THROTTLED_WRITTEN = 33,
	NR_KERNEL_MISC_RECLAIMABLE = 34,
	NR_FOLL_PIN_ACQUIRED = 35,
	NR_FOLL_PIN_RELEASED = 36,
	NR_KERNEL_STACK_KB = 37,
	NR_PAGETABLE = 38,
	NR_VM_NODE_STAT_ITEMS = 39,
};

struct lruvec {
	struct list_head lists[5];
	spinlock_t lru_lock;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	atomic_long_t nonresident_age;
	long unsigned int refaults[2];
	long unsigned int flags;
};

typedef unsigned int isolate_mode_t;

struct per_cpu_pages {
	int count;
	int high;
	int batch;
	short int free_factor;
	struct list_head lists[12];
};

struct per_cpu_zonestat {};

struct per_cpu_nodestat {
	s8 stat_threshold;
	s8 vm_node_stat_diff[39];
};

enum zone_type {
	ZONE_NORMAL = 0,
	ZONE_MOVABLE = 1,
	__MAX_NR_ZONES = 2,
};

struct pglist_data;

struct zone {
	long unsigned int _watermark[4];
	long unsigned int watermark_boost;
	long unsigned int nr_reserved_highatomic;
	long int lowmem_reserve[2];
	struct pglist_data *zone_pgdat;
	struct per_cpu_pages *per_cpu_pageset;
	struct per_cpu_zonestat *per_cpu_zonestats;
	int pageset_high;
	int pageset_batch;
	long unsigned int *pageblock_flags;
	long unsigned int zone_start_pfn;
	atomic_long_t managed_pages;
	long unsigned int spanned_pages;
	long unsigned int present_pages;
	const char *name;
	int initialized;
	struct free_area free_area[11];
	long unsigned int flags;
	spinlock_t lock;
	long unsigned int percpu_drift_mark;
	bool contiguous;
	atomic_long_t vm_stat[10];
	atomic_long_t vm_numa_event[0];
};

struct zoneref {
	struct zone *zone;
	int zone_idx;
};

struct zonelist {
	struct zoneref _zonerefs[3];
};

struct pglist_data {
	struct zone node_zones[2];
	struct zonelist node_zonelists[1];
	int nr_zones;
	struct page *node_mem_map;
	long unsigned int node_start_pfn;
	long unsigned int node_present_pages;
	long unsigned int node_spanned_pages;
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;
	wait_queue_head_t reclaim_wait[4];
	atomic_t nr_writeback_throttled;
	long unsigned int nr_reclaim_start;
	struct task_struct *kswapd;
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;
	int kswapd_failures;
	long unsigned int totalreserve_pages;
	struct lruvec __lruvec;
	long unsigned int flags;
	struct per_cpu_nodestat *per_cpu_nodestats;
	atomic_long_t vm_stat[39];
};

typedef struct pglist_data pg_data_t;

struct rcu_segcblist {
	struct callback_head *head;
	struct callback_head **tails[4];
	long unsigned int gp_seq[4];
	long int len;
	long int seglen[4];
	u8 flags;
};

struct srcu_node;

struct srcu_struct;

struct srcu_data {
	long unsigned int srcu_lock_count[2];
	long unsigned int srcu_unlock_count[2];
	spinlock_t lock;
	struct rcu_segcblist srcu_cblist;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	bool srcu_cblist_invoking;
	struct timer_list delay_work;
	struct work_struct work;
	struct callback_head srcu_barrier_head;
	struct srcu_node *mynode;
	long unsigned int grpmask;
	int cpu;
	struct srcu_struct *ssp;
};

struct srcu_node {
	spinlock_t lock;
	long unsigned int srcu_have_cbs[4];
	long unsigned int srcu_data_have_cbs[4];
	long unsigned int srcu_gp_seq_needed_exp;
	struct srcu_node *srcu_parent;
	int grplo;
	int grphi;
};

struct srcu_struct {
	struct srcu_node node[1];
	struct srcu_node *level[2];
	struct mutex srcu_cb_mutex;
	spinlock_t lock;
	struct mutex srcu_gp_mutex;
	unsigned int srcu_idx;
	long unsigned int srcu_gp_seq;
	long unsigned int srcu_gp_seq_needed;
	long unsigned int srcu_gp_seq_needed_exp;
	long unsigned int srcu_last_gp_end;
	struct srcu_data *sda;
	long unsigned int srcu_barrier_seq;
	struct mutex srcu_barrier_mutex;
	struct completion srcu_barrier_completion;
	atomic_t srcu_barrier_cpu_cnt;
	struct delayed_work work;
	struct lockdep_map dep_map;
};

struct notifier_block;

typedef int (*notifier_fn_t)(struct notifier_block *, long unsigned int, void *);

struct notifier_block {
	notifier_fn_t notifier_call;
	struct notifier_block *next;
	int priority;
};

struct blocking_notifier_head {
	struct rw_semaphore rwsem;
	struct notifier_block *head;
};

struct raw_notifier_head {
	struct notifier_block *head;
};

typedef int proc_handler(struct ctl_table *, int, void *, size_t *, loff_t *);

struct ctl_table_poll;

struct ctl_table {
	const char *procname;
	void *data;
	int maxlen;
	umode_t mode;
	struct ctl_table *child;
	proc_handler *proc_handler;
	struct ctl_table_poll *poll;
	void *extra1;
	void *extra2;
};

struct ctl_table_poll {
	atomic_t event;
	wait_queue_head_t wait;
};

struct ctl_node {
	struct rb_node node;
	struct ctl_table_header *header;
};

struct ctl_table_root {
	struct ctl_table_set default_set;
	struct ctl_table_set * (*lookup)(struct ctl_table_root *);
	void (*set_ownership)(struct ctl_table_header *, struct ctl_table *, kuid_t *, kgid_t *);
	int (*permissions)(struct ctl_table_header *, struct ctl_table *);
};

struct kernel_cap_struct {
	__u32 cap[2];
};

typedef struct kernel_cap_struct kernel_cap_t;

struct user_struct;

struct group_info;

struct cred {
	atomic_t usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned int securebits;
	kernel_cap_t cap_inheritable;
	kernel_cap_t cap_permitted;
	kernel_cap_t cap_effective;
	kernel_cap_t cap_bset;
	kernel_cap_t cap_ambient;
	struct user_struct *user;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct group_info *group_info;
	union {
		int non_rcu;
		struct callback_head rcu;
	};
};

typedef __u32 Elf32_Addr;

typedef __u16 Elf32_Half;

typedef __u32 Elf32_Word;

struct elf32_sym {
	Elf32_Word st_name;
	Elf32_Addr st_value;
	Elf32_Word st_size;
	unsigned char st_info;
	unsigned char st_other;
	Elf32_Half st_shndx;
};

typedef struct elf32_sym Elf32_Sym;

struct list_lru_node;

struct list_lru {
	struct list_lru_node *node;
};

struct idr {
	struct xarray idr_rt;
	unsigned int idr_base;
	unsigned int idr_next;
};

struct kernfs_root;

struct kernfs_elem_dir {
	long unsigned int subdirs;
	struct rb_root children;
	struct kernfs_root *root;
	long unsigned int rev;
};

struct kernfs_node;

struct kernfs_elem_symlink {
	struct kernfs_node *target_kn;
};

struct kernfs_ops;

struct kernfs_open_node;

struct kernfs_elem_attr {
	const struct kernfs_ops *ops;
	struct kernfs_open_node *open;
	loff_t size;
	struct kernfs_node *notify_next;
};

struct kernfs_iattrs;

struct kernfs_node {
	atomic_t count;
	atomic_t active;
	struct kernfs_node *parent;
	const char *name;
	struct rb_node rb;
	const void *ns;
	unsigned int hash;
	union {
		struct kernfs_elem_dir dir;
		struct kernfs_elem_symlink symlink;
		struct kernfs_elem_attr attr;
	};
	void *priv;
	u64 id;
	short unsigned int flags;
	umode_t mode;
	struct kernfs_iattrs *iattr;
};

struct kernfs_open_file;

struct kernfs_ops {
	int (*open)(struct kernfs_open_file *);
	void (*release)(struct kernfs_open_file *);
	int (*seq_show)(struct seq_file *, void *);
	void * (*seq_start)(struct seq_file *, loff_t *);
	void * (*seq_next)(struct seq_file *, void *, loff_t *);
	void (*seq_stop)(struct seq_file *, void *);
	ssize_t (*read)(struct kernfs_open_file *, char *, size_t, loff_t);
	size_t atomic_write_len;
	bool prealloc;
	ssize_t (*write)(struct kernfs_open_file *, char *, size_t, loff_t);
	__poll_t (*poll)(struct kernfs_open_file *, struct poll_table_struct *);
	int (*mmap)(struct kernfs_open_file *, struct vm_area_struct *);
};

struct seq_operations;

struct seq_file {
	char *buf;
	size_t size;
	size_t from;
	size_t count;
	size_t pad_until;
	loff_t index;
	loff_t read_pos;
	struct mutex lock;
	const struct seq_operations *op;
	int poll_event;
	const struct file *file;
	void *private;
};

struct kernfs_open_file {
	struct kernfs_node *kn;
	struct file *file;
	struct seq_file *seq_file;
	void *priv;
	struct mutex mutex;
	struct mutex prealloc_mutex;
	int event;
	struct list_head list;
	char *prealloc_buf;
	size_t atomic_write_len;
	bool mmapped: 1;
	bool released: 1;
	const struct vm_operations_struct *vm_ops;
};

typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

struct poll_table_struct {
	poll_queue_proc _qproc;
	__poll_t _key;
};

enum kobj_ns_type {
	KOBJ_NS_TYPE_NONE = 0,
	KOBJ_NS_TYPE_NET = 1,
	KOBJ_NS_TYPES = 2,
};

struct sock;

struct kobj_ns_type_operations {
	enum kobj_ns_type type;
	bool (*current_may_mount)();
	void * (*grab_current_ns)();
	const void * (*netlink_ns)(struct sock *);
	const void * (*initial_ns)();
	void (*drop_ns)(void *);
};

struct attribute {
	const char *name;
	umode_t mode;
};

struct kobject;

struct bin_attribute;

struct attribute_group {
	const char *name;
	umode_t (*is_visible)(struct kobject *, struct attribute *, int);
	umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int);
	struct attribute **attrs;
	struct bin_attribute **bin_attrs;
};

struct kset;

struct kobj_type;

struct kobject {
	const char *name;
	struct list_head entry;
	struct kobject *parent;
	struct kset *kset;
	const struct kobj_type *ktype;
	struct kernfs_node *sd;
	struct kref kref;
	unsigned int state_initialized: 1;
	unsigned int state_in_sysfs: 1;
	unsigned int state_add_uevent_sent: 1;
	unsigned int state_remove_uevent_sent: 1;
	unsigned int uevent_suppress: 1;
};

struct bin_attribute {
	struct attribute attr;
	size_t size;
	void *private;
	struct address_space * (*f_mapping)();
	ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
	int (*mmap)(struct file *, struct kobject *, struct bin_attribute *, struct vm_area_struct *);
};

struct sysfs_ops {
	ssize_t (*show)(struct kobject *, struct attribute *, char *);
	ssize_t (*store)(struct kobject *, struct attribute *, const char *, size_t);
};

struct kset_uevent_ops;

struct kset {
	struct list_head list;
	spinlock_t list_lock;
	struct kobject kobj;
	const struct kset_uevent_ops *uevent_ops;
};

struct kobj_type {
	void (*release)(struct kobject *);
	const struct sysfs_ops *sysfs_ops;
	const struct attribute_group **default_groups;
	const struct kobj_ns_type_operations * (*child_ns_type)(struct kobject *);
	const void * (*namespace)(struct kobject *);
	void (*get_ownership)(struct kobject *, kuid_t *, kgid_t *);
};

struct kobj_uevent_env {
	char *argv[3];
	char *envp[64];
	int envp_idx;
	char buf[2048];
	int buflen;
};

struct kset_uevent_ops {
	int (* const filter)(struct kobject *);
	const char * (* const name)(struct kobject *);
	int (* const uevent)(struct kobject *, struct kobj_uevent_env *);
};

struct kernel_param;

struct kernel_param_ops {
	unsigned int flags;
	int (*set)(const char *, const struct kernel_param *);
	int (*get)(char *, const struct kernel_param *);
	void (*free)(void *);
};

struct kparam_string;

struct kparam_array;

struct kernel_param {
	const char *name;
	struct module *mod;
	const struct kernel_param_ops *ops;
	const u16 perm;
	s8 level;
	u8 flags;
	union {
		void *arg;
		const struct kparam_string *str;
		const struct kparam_array *arr;
	};
};

struct kparam_string {
	unsigned int maxlen;
	char *string;
};

struct kparam_array {
	unsigned int max;
	unsigned int elemsize;
	unsigned int *num;
	const struct kernel_param_ops *ops;
	void *elem;
};

enum module_state {
	MODULE_STATE_LIVE = 0,
	MODULE_STATE_COMING = 1,
	MODULE_STATE_GOING = 2,
	MODULE_STATE_UNFORMED = 3,
};

struct module_param_attrs;

struct module_kobject {
	struct kobject kobj;
	struct module *mod;
	struct kobject *drivers_dir;
	struct module_param_attrs *mp;
	struct completion *kobj_completion;
};

struct latch_tree_node {
	struct rb_node node[2];
};

struct mod_tree_node {
	struct module *mod;
	struct latch_tree_node node;
};

struct module_layout {
	void *base;
	unsigned int size;
	unsigned int text_size;
	unsigned int ro_size;
	unsigned int ro_after_init_size;
	struct mod_tree_node mtn;
};

struct mod_arch_specific {
	void *unw_info;
	int unw_sec_idx;
	const char *secstr;
};

struct mod_kallsyms {
	Elf32_Sym *symtab;
	unsigned int num_symtab;
	char *strtab;
	char *typetab;
};

struct module_attribute;

struct exception_table_entry;

struct module_sect_attrs;

struct module_notes_attrs;

struct tracepoint;

typedef struct tracepoint * const tracepoint_ptr_t;

struct bpf_raw_event_map;

struct trace_event_call;

struct trace_eval_map;

struct module {
	enum module_state state;
	struct list_head list;
	char name[60];
	struct module_kobject mkobj;
	struct module_attribute *modinfo_attrs;
	const char *version;
	const char *srcversion;
	struct kobject *holders_dir;
	const struct kernel_symbol *syms;
	const s32 *crcs;
	unsigned int num_syms;
	struct mutex param_lock;
	struct kernel_param *kp;
	unsigned int num_kp;
	unsigned int num_gpl_syms;
	const struct kernel_symbol *gpl_syms;
	const s32 *gpl_crcs;
	bool using_gplonly_symbols;
	bool async_probe_requested;
	unsigned int num_exentries;
	struct exception_table_entry *extable;
	int (*init)();
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct module_layout core_layout;
	struct module_layout init_layout;
	struct mod_arch_specific arch;
	long unsigned int taints;
	struct mod_kallsyms *kallsyms;
	struct mod_kallsyms core_kallsyms;
	struct module_sect_attrs *sect_attrs;
	struct module_notes_attrs *notes_attrs;
	char *args;
	void *noinstr_text_start;
	unsigned int noinstr_text_size;
	unsigned int num_tracepoints;
	tracepoint_ptr_t *tracepoints_ptrs;
	unsigned int num_srcu_structs;
	struct srcu_struct **srcu_struct_ptrs;
	unsigned int num_bpf_raw_events;
	struct bpf_raw_event_map *bpf_raw_events;
	unsigned int btf_data_size;
	void *btf_data;
	unsigned int num_trace_bprintk_fmt;
	const char **trace_bprintk_fmt_start;
	struct trace_event_call **trace_events;
	unsigned int num_trace_events;
	struct trace_eval_map **trace_evals;
	unsigned int num_trace_evals;
	void *kprobes_text_start;
	unsigned int kprobes_text_size;
	long unsigned int *kprobe_blacklist;
	unsigned int num_kprobe_blacklist;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct static_key {
	atomic_t enabled;
};

struct static_key_false {
	struct static_key key;
};

struct tracepoint_func {
	void *func;
	void *data;
	int prio;
};

struct tracepoint {
	const char *name;
	struct static_key key;
	struct static_call_key *static_call_key;
	void *static_call_tramp;
	void *iterator;
	int (*regfunc)();
	void (*unregfunc)();
	struct tracepoint_func *funcs;
};

struct bpf_raw_event_map {
	struct tracepoint *tp;
	void *bpf_func;
	u32 num_args;
	u32 writable_size;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct module_attribute {
	struct attribute attr;
	ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
	ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t);
	void (*setup)(struct module *, const char *);
	int (*test)(struct module *);
	void (*free)(struct module *);
};

struct exception_table_entry {
	long unsigned int insn;
	long unsigned int fixup;
};

struct trace_event_functions;

struct trace_event {
	struct hlist_node node;
	struct list_head list;
	int type;
	struct trace_event_functions *funcs;
};

struct trace_event_class;

struct event_filter;

struct bpf_prog_array;

struct perf_event;

struct trace_event_call {
	struct list_head list;
	struct trace_event_class *class;
	union {
		char *name;
		struct tracepoint *tp;
	};
	struct trace_event event;
	char *print_fmt;
	struct event_filter *filter;
	union {
		void *module;
		atomic_t refcnt;
	};
	void *data;
	int flags;
	int perf_refcount;
	struct hlist_head *perf_events;
	struct bpf_prog_array *prog_array;
	int (*perf_perm)(struct trace_event_call *, struct perf_event *);
};

struct trace_eval_map {
	const char *system;
	const char *eval_string;
	long unsigned int eval_value;
};

struct hlist_bl_node;

struct hlist_bl_head {
	struct hlist_bl_node *first;
};

struct hlist_bl_node {
	struct hlist_bl_node *next;
	struct hlist_bl_node **pprev;
};

struct lockref {
	union {
		struct {
			spinlock_t lock;
			int count;
		};
	};
};

struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

struct dentry_operations;

struct dentry {
	unsigned int d_flags;
	seqcount_spinlock_t d_seq;
	struct hlist_bl_node d_hash;
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
	unsigned char d_iname[40];
	struct lockref d_lockref;
	const struct dentry_operations *d_op;
	struct super_block *d_sb;
	long unsigned int d_time;
	void *d_fsdata;
	union {
		struct list_head d_lru;
		wait_queue_head_t *d_wait;
	};
	struct list_head d_child;
	struct list_head d_subdirs;
	union {
		struct hlist_node d_alias;
		struct hlist_bl_node d_in_lookup_hash;
		struct callback_head d_rcu;
	} d_u;
};

struct inode_operations;

struct file_lock_context;

struct cdev;

struct fsnotify_mark_connector;

struct inode {
	umode_t i_mode;
	short unsigned int i_opflags;
	kuid_t i_uid;
	kgid_t i_gid;
	unsigned int i_flags;
	const struct inode_operations *i_op;
	struct super_block *i_sb;
	struct address_space *i_mapping;
	long unsigned int i_ino;
	union {
		const unsigned int i_nlink;
		unsigned int __i_nlink;
	};
	dev_t i_rdev;
	loff_t i_size;
	struct timespec64 i_atime;
	struct timespec64 i_mtime;
	struct timespec64 i_ctime;
	spinlock_t i_lock;
	short unsigned int i_bytes;
	u8 i_blkbits;
	u8 i_write_hint;
	blkcnt_t i_blocks;
	long unsigned int i_state;
	struct rw_semaphore i_rwsem;
	long unsigned int dirtied_when;
	long unsigned int dirtied_time_when;
	struct hlist_node i_hash;
	struct list_head i_io_list;
	struct list_head i_lru;
	struct list_head i_sb_list;
	struct list_head i_wb_list;
	union {
		struct hlist_head i_dentry;
		struct callback_head i_rcu;
	};
	int: 32;
	atomic64_t i_version;
	atomic64_t i_sequence;
	atomic_t i_count;
	atomic_t i_dio_count;
	atomic_t i_writecount;
	atomic_t i_readcount;
	union {
		const struct file_operations *i_fop;
		void (*free_inode)(struct inode *);
	};
	struct file_lock_context *i_flctx;
	struct address_space i_data;
	struct list_head i_devices;
	union {
		struct pipe_inode_info *i_pipe;
		struct cdev *i_cdev;
		char *i_link;
		unsigned int i_dir_seq;
	};
	__u32 i_generation;
	__u32 i_fsnotify_mask;
	struct fsnotify_mark_connector *i_fsnotify_marks;
	void *i_private;
};

struct dentry_operations {
	int (*d_revalidate)(struct dentry *, unsigned int);
	int (*d_weak_revalidate)(struct dentry *, unsigned int);
	int (*d_hash)(const struct dentry *, struct qstr *);
	int (*d_compare)(const struct dentry *, unsigned int, const char *, const struct qstr *);
	int (*d_delete)(const struct dentry *);
	int (*d_init)(struct dentry *);
	void (*d_release)(struct dentry *);
	void (*d_prune)(struct dentry *);
	void (*d_iput)(struct dentry *, struct inode *);
	char * (*d_dname)(struct dentry *, char *, int);
	struct vfsmount * (*d_automount)(struct path *);
	int (*d_manage)(const struct path *, bool);
	struct dentry * (*d_real)(struct dentry *, const struct inode *);
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct mtd_info;

typedef long long int qsize_t;

struct quota_format_type;

struct mem_dqinfo {
	struct quota_format_type *dqi_format;
	int dqi_fmt_id;
	struct list_head dqi_dirty_list;
	long unsigned int dqi_flags;
	unsigned int dqi_bgrace;
	unsigned int dqi_igrace;
	qsize_t dqi_max_spc_limit;
	qsize_t dqi_max_ino_limit;
	void *dqi_priv;
};

struct quota_format_ops;

struct quota_info {
	unsigned int flags;
	struct rw_semaphore dqio_sem;
	struct inode *files[3];
	struct mem_dqinfo info[3];
	const struct quota_format_ops *ops[3];
};

struct rcu_sync {
	int gp_state;
	int gp_count;
	wait_queue_head_t gp_wait;
	struct callback_head cb_head;
};

struct rcuwait {
	struct task_struct *task;
};

struct percpu_rw_semaphore {
	struct rcu_sync rss;
	unsigned int *read_count;
	struct rcuwait writer;
	wait_queue_head_t waiters;
	atomic_t block;
};

struct sb_writers {
	int frozen;
	wait_queue_head_t wait_unfrozen;
	struct percpu_rw_semaphore rw_sem[3];
};

typedef struct {
	__u8 b[16];
} uuid_t;

struct shrink_control;

struct shrinker {
	long unsigned int (*count_objects)(struct shrinker *, struct shrink_control *);
	long unsigned int (*scan_objects)(struct shrinker *, struct shrink_control *);
	long int batch;
	int seeks;
	unsigned int flags;
	struct list_head list;
	atomic_long_t *nr_deferred;
};

struct super_operations;

struct dquot_operations;

struct quotactl_ops;

struct export_operations;

struct xattr_handler;

struct block_device;

struct super_block {
	struct list_head s_list;
	dev_t s_dev;
	unsigned char s_blocksize_bits;
	long unsigned int s_blocksize;
	loff_t s_maxbytes;
	struct file_system_type *s_type;
	const struct super_operations *s_op;
	const struct dquot_operations *dq_op;
	const struct quotactl_ops *s_qcop;
	const struct export_operations *s_export_op;
	long unsigned int s_flags;
	long unsigned int s_iflags;
	long unsigned int s_magic;
	struct dentry *s_root;
	struct rw_semaphore s_umount;
	int s_count;
	atomic_t s_active;
	const struct xattr_handler **s_xattr;
	struct hlist_bl_head s_roots;
	struct list_head s_mounts;
	struct block_device *s_bdev;
	struct backing_dev_info *s_bdi;
	struct mtd_info *s_mtd;
	struct hlist_node s_instances;
	unsigned int s_quota_types;
	struct quota_info s_dquot;
	struct sb_writers s_writers;
	void *s_fs_info;
	u32 s_time_gran;
	time64_t s_time_min;
	time64_t s_time_max;
	__u32 s_fsnotify_mask;
	struct fsnotify_mark_connector *s_fsnotify_marks;
	char s_id[32];
	uuid_t s_uuid;
	unsigned int s_max_links;
	fmode_t s_mode;
	struct mutex s_vfs_rename_mutex;
	const char *s_subtype;
	const struct dentry_operations *s_d_op;
	struct shrinker s_shrink;
	atomic_long_t s_remove_count;
	atomic_long_t s_fsnotify_connectors;
	int s_readonly_remount;
	errseq_t s_wb_err;
	struct workqueue_struct *s_dio_done_wq;
	struct hlist_head s_pins;
	struct user_namespace *s_user_ns;
	struct list_lru s_dentry_lru;
	struct list_lru s_inode_lru;
	struct callback_head rcu;
	struct work_struct destroy_work;
	struct mutex s_sync_lock;
	int s_stack_depth;
	spinlock_t s_inode_list_lock;
	struct list_head s_inodes;
	spinlock_t s_inode_wblist_lock;
	struct list_head s_inodes_wb;
};

struct vfsmount {
	struct dentry *mnt_root;
	struct super_block *mnt_sb;
	int mnt_flags;
	struct user_namespace *mnt_userns;
};

struct mem_cgroup;

struct shrink_control {
	gfp_t gfp_mask;
	int nid;
	long unsigned int nr_to_scan;
	long unsigned int nr_scanned;
	struct mem_cgroup *memcg;
};

struct list_lru_one {
	struct list_head list;
	long int nr_items;
};

struct list_lru_node {
	spinlock_t lock;
	struct list_lru_one lru;
	long int nr_items;
};

struct pid_namespace;

struct upid {
	int nr;
	struct pid_namespace *ns;
};

struct kmem_cache;

struct pid_namespace {
	struct idr idr;
	struct callback_head rcu;
	unsigned int pid_allocated;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	int reboot;
	struct ns_common ns;
};

struct pid {
	refcount_t count;
	unsigned int level;
	spinlock_t lock;
	struct hlist_head tasks[4];
	struct hlist_head inodes;
	wait_queue_head_t wait_pidfd;
	struct callback_head rcu;
	struct upid numbers[1];
};

enum migrate_mode {
	MIGRATE_ASYNC = 0,
	MIGRATE_SYNC_LIGHT = 1,
	MIGRATE_SYNC = 2,
	MIGRATE_SYNC_NO_COPY = 3,
};

typedef void __signalfn_t(int);

typedef __signalfn_t *__sighandler_t;

typedef void __restorefn_t();

typedef __restorefn_t *__sigrestore_t;

union sigval {
	int sival_int;
	void *sival_ptr;
};

typedef union sigval sigval_t;

union __sifields {
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
	} _kill;
	struct {
		__kernel_timer_t _tid;
		int _overrun;
		sigval_t _sigval;
		int _sys_private;
	} _timer;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		sigval_t _sigval;
	} _rt;
	struct {
		__kernel_pid_t _pid;
		__kernel_uid32_t _uid;
		int _status;
		__kernel_clock_t _utime;
		__kernel_clock_t _stime;
	} _sigchld;
	struct {
		void *_addr;
		union {
			int _trapno;
			short int _addr_lsb;
			struct {
				char _dummy_bnd[4];
				void *_lower;
				void *_upper;
			} _addr_bnd;
			struct {
				char _dummy_pkey[4];
				__u32 _pkey;
			} _addr_pkey;
			struct {
				long unsigned int _data;
				__u32 _type;
			} _perf;
		};
	} _sigfault;
	struct {
		long int _band;
		int _fd;
	} _sigpoll;
	struct {
		void *_call_addr;
		int _syscall;
		unsigned int _arch;
	} _sigsys;
};

struct kernel_siginfo {
	struct {
		int si_signo;
		int si_errno;
		int si_code;
		union __sifields _sifields;
	};
};

struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[14];
};

struct sigaction {
	__sighandler_t sa_handler;
	long unsigned int sa_flags;
	__sigrestore_t sa_restorer;
	sigset_t sa_mask;
};

struct k_sigaction {
	struct sigaction sa;
};

struct rhash_head {
	struct rhash_head *next;
};

struct rhashtable;

struct rhashtable_compare_arg {
	struct rhashtable *ht;
	const void *key;
};

typedef u32 (*rht_hashfn_t)(const void *, u32, u32);

typedef u32 (*rht_obj_hashfn_t)(const void *, u32, u32);

typedef int (*rht_obj_cmpfn_t)(struct rhashtable_compare_arg *, const void *);

struct rhashtable_params {
	u16 nelem_hint;
	u16 key_len;
	u16 key_offset;
	u16 head_offset;
	unsigned int max_size;
	u16 min_size;
	bool automatic_shrinking;
	rht_hashfn_t hashfn;
	rht_obj_hashfn_t obj_hashfn;
	rht_obj_cmpfn_t obj_cmpfn;
};

struct bucket_table;

struct rhashtable {
	struct bucket_table *tbl;
	unsigned int key_len;
	unsigned int max_elems;
	struct rhashtable_params p;
	bool rhlist;
	struct work_struct run_work;
	struct mutex mutex;
	spinlock_t lock;
	atomic_t nelems;
};

struct plist_node {
	int prio;
	struct list_head prio_list;
	struct list_head node_list;
};

struct hrtimer_cpu_base;

struct hrtimer_clock_base {
	struct hrtimer_cpu_base *cpu_base;
	unsigned int index;
	clockid_t clockid;
	seqcount_raw_spinlock_t seq;
	struct hrtimer *running;
	struct timerqueue_head active;
	ktime_t (*get_time)();
	ktime_t offset;
};

struct hrtimer_cpu_base {
	raw_spinlock_t lock;
	unsigned int cpu;
	unsigned int active_bases;
	unsigned int clock_was_set_seq;
	unsigned int hres_active: 1;
	unsigned int in_hrtirq: 1;
	unsigned int hang_detected: 1;
	unsigned int softirq_activated: 1;
	unsigned int nr_events;
	short unsigned int nr_retries;
	short unsigned int nr_hangs;
	unsigned int max_hang_time;
	ktime_t expires_next;
	struct hrtimer *next_timer;
	ktime_t softirq_expires_next;
	struct hrtimer *softirq_next_timer;
	struct hrtimer_clock_base clock_base[8];
	int: 32;
	int: 32;
	int: 32;
};

struct rlimit {
	__kernel_ulong_t rlim_cur;
	__kernel_ulong_t rlim_max;
};

struct cpu_itimer {
	u64 expires;
	u64 incr;
};

struct task_cputime_atomic {
	atomic64_t utime;
	atomic64_t stime;
	atomic64_t sum_exec_runtime;
};

struct thread_group_cputimer {
	struct task_cputime_atomic cputime_atomic;
};

struct core_state;

struct tty_struct;

struct signal_struct {
	refcount_t sigcnt;
	atomic_t live;
	int nr_threads;
	struct list_head thread_head;
	wait_queue_head_t wait_chldexit;
	struct task_struct *curr_target;
	struct sigpending shared_pending;
	struct hlist_head multiprocess;
	int group_exit_code;
	int notify_count;
	struct task_struct *group_exec_task;
	int group_stop_count;
	unsigned int flags;
	struct core_state *core_state;
	unsigned int is_child_subreaper: 1;
	unsigned int has_child_subreaper: 1;
	int posix_timer_id;
	struct list_head posix_timers;
	struct hrtimer real_timer;
	ktime_t it_real_incr;
	struct cpu_itimer it[2];
	int: 32;
	struct thread_group_cputimer cputimer;
	struct posix_cputimers posix_cputimers;
	struct pid *pids[4];
	struct pid *tty_old_pgrp;
	int leader;
	struct tty_struct *tty;
	seqlock_t stats_lock;
	u64 utime;
	u64 stime;
	u64 cutime;
	u64 cstime;
	u64 gtime;
	u64 cgtime;
	struct prev_cputime prev_cputime;
	long unsigned int nvcsw;
	long unsigned int nivcsw;
	long unsigned int cnvcsw;
	long unsigned int cnivcsw;
	long unsigned int min_flt;
	long unsigned int maj_flt;
	long unsigned int cmin_flt;
	long unsigned int cmaj_flt;
	long unsigned int inblock;
	long unsigned int oublock;
	long unsigned int cinblock;
	long unsigned int coublock;
	long unsigned int maxrss;
	long unsigned int cmaxrss;
	struct task_io_accounting ioac;
	long long unsigned int sum_sched_runtime;
	struct rlimit rlim[16];
	bool oom_flag_origin;
	short int oom_score_adj;
	short int oom_score_adj_min;
	struct mm_struct *oom_mm;
	struct mutex cred_guard_mutex;
	struct rw_semaphore exec_update_lock;
};

struct rq;

struct sched_class {
	void (*enqueue_task)(struct rq *, struct task_struct *, int);
	void (*dequeue_task)(struct rq *, struct task_struct *, int);
	void (*yield_task)(struct rq *);
	bool (*yield_to_task)(struct rq *, struct task_struct *);
	void (*check_preempt_curr)(struct rq *, struct task_struct *, int);
	struct task_struct * (*pick_next_task)(struct rq *);
	void (*put_prev_task)(struct rq *, struct task_struct *);
	void (*set_next_task)(struct rq *, struct task_struct *, bool);
	void (*task_tick)(struct rq *, struct task_struct *, int);
	void (*task_fork)(struct task_struct *);
	void (*task_dead)(struct task_struct *);
	void (*switched_from)(struct rq *, struct task_struct *);
	void (*switched_to)(struct rq *, struct task_struct *);
	void (*prio_changed)(struct rq *, struct task_struct *, int);
	unsigned int (*get_rr_interval)(struct rq *, struct task_struct *);
	void (*update_curr)(struct rq *);
};

struct uts_namespace;

struct ipc_namespace;

struct mnt_namespace;

struct net;

struct time_namespace;

struct cgroup_namespace;

struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net *net_ns;
	struct time_namespace *time_ns;
	struct time_namespace *time_ns_for_children;
	struct cgroup_namespace *cgroup_ns;
};

struct sighand_struct {
	spinlock_t siglock;
	refcount_t count;
	wait_queue_head_t signalfd_wqh;
	struct k_sigaction action[64];
};

struct bio;

struct bio_list {
	struct bio *head;
	struct bio *tail;
};

struct request;

struct blk_plug {
	struct request *mq_list;
	struct request *cached_rq;
	short unsigned int nr_ios;
	short unsigned int rq_count;
	bool multiple_queues;
	bool has_elevator;
	bool nowait;
	struct list_head cb_list;
};

struct reclaim_state {
	long unsigned int reclaimed_slab;
};

struct percpu_counter {
	s64 count;
};

struct fprop_local_percpu {
	struct percpu_counter events;
	unsigned int period;
	raw_spinlock_t lock;
};

enum wb_reason {
	WB_REASON_BACKGROUND = 0,
	WB_REASON_VMSCAN = 1,
	WB_REASON_SYNC = 2,
	WB_REASON_PERIODIC = 3,
	WB_REASON_LAPTOP_TIMER = 4,
	WB_REASON_FS_FREE_SPACE = 5,
	WB_REASON_FORKER_THREAD = 6,
	WB_REASON_FOREIGN_FLUSH = 7,
	WB_REASON_MAX = 8,
};

struct bdi_writeback {
	struct backing_dev_info *bdi;
	long unsigned int state;
	long unsigned int last_old_flush;
	struct list_head b_dirty;
	struct list_head b_io;
	struct list_head b_more_io;
	struct list_head b_dirty_time;
	spinlock_t list_lock;
	atomic_t writeback_inodes;
	struct percpu_counter stat[4];
	long unsigned int congested;
	long unsigned int bw_time_stamp;
	long unsigned int dirtied_stamp;
	long unsigned int written_stamp;
	long unsigned int write_bandwidth;
	long unsigned int avg_write_bandwidth;
	long unsigned int dirty_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	struct fprop_local_percpu completions;
	int dirty_exceeded;
	enum wb_reason start_all_reason;
	spinlock_t work_lock;
	struct list_head work_list;
	struct delayed_work dwork;
	struct delayed_work bw_dwork;
	long unsigned int dirty_sleep;
	struct list_head bdi_node;
};

struct backing_dev_info {
	u64 id;
	struct rb_node rb_node;
	struct list_head bdi_list;
	long unsigned int ra_pages;
	long unsigned int io_pages;
	struct kref refcnt;
	unsigned int capabilities;
	unsigned int min_ratio;
	unsigned int max_ratio;
	unsigned int max_prop_frac;
	atomic_long_t tot_write_bandwidth;
	struct bdi_writeback wb;
	struct list_head wb_list;
	wait_queue_head_t wb_waitq;
	struct device *dev;
	char dev_name[64];
	struct device *owner;
	struct timer_list laptop_mode_wb_timer;
	struct dentry *debug_dir;
};

struct io_context {
	atomic_long_t refcount;
	atomic_t active_ref;
	short unsigned int ioprio;
};

struct perf_event_groups {
	struct rb_root tree;
	u64 index;
};

struct pmu;

struct perf_event_context {
	struct pmu *pmu;
	raw_spinlock_t lock;
	struct mutex mutex;
	struct list_head active_ctx_list;
	struct perf_event_groups pinned_groups;
	struct perf_event_groups flexible_groups;
	struct list_head event_list;
	struct list_head pinned_active;
	struct list_head flexible_active;
	int nr_events;
	int nr_active;
	int nr_user;
	int is_active;
	int nr_stat;
	int nr_freq;
	int rotate_disable;
	int rotate_necessary;
	refcount_t refcount;
	struct task_struct *task;
	u64 time;
	u64 timestamp;
	u64 timeoffset;
	struct perf_event_context *parent_ctx;
	u64 parent_gen;
	u64 generation;
	int pin_count;
	void *task_ctx_data;
	struct callback_head callback_head;
};

struct fasync_struct;

struct pipe_buffer;

struct pipe_inode_info {
	struct mutex mutex;
	wait_queue_head_t rd_wait;
	wait_queue_head_t wr_wait;
	unsigned int head;
	unsigned int tail;
	unsigned int max_usage;
	unsigned int ring_size;
	unsigned int nr_accounted;
	unsigned int readers;
	unsigned int writers;
	unsigned int files;
	unsigned int r_counter;
	unsigned int w_counter;
	unsigned int poll_usage;
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;
	struct user_struct *user;
};

struct css_set;

struct user_struct {
	refcount_t __count;
	struct percpu_counter epoll_watches;
	long unsigned int unix_inflight;
	atomic_long_t pipe_bufs;
	struct hlist_node uidhash_node;
	kuid_t uid;
	atomic_long_t locked_vm;
	struct ratelimit_state ratelimit;
};

struct group_info {
	atomic_t usage;
	int ngroups;
	kgid_t gid[0];
};

struct core_thread {
	struct task_struct *task;
	struct core_thread *next;
};

struct core_state {
	atomic_t nr_threads;
	struct core_thread dumper;
	struct completion startup;
};

struct delayed_call {
	void (*fn)(void *);
	void *arg;
};

struct percpu_ref_data;

struct percpu_ref {
	long unsigned int percpu_count_ptr;
	struct percpu_ref_data *data;
};

enum blk_bounce {
	BLK_BOUNCE_NONE = 0,
	BLK_BOUNCE_HIGH = 1,
};

enum blk_zoned_model {
	BLK_ZONED_NONE = 0,
	BLK_ZONED_HA = 1,
	BLK_ZONED_HM = 2,
};

struct queue_limits {
	enum blk_bounce bounce;
	long unsigned int seg_boundary_mask;
	long unsigned int virt_boundary_mask;
	unsigned int max_hw_sectors;
	unsigned int max_dev_sectors;
	unsigned int chunk_sectors;
	unsigned int max_sectors;
	unsigned int max_segment_size;
	unsigned int physical_block_size;
	unsigned int logical_block_size;
	unsigned int alignment_offset;
	unsigned int io_min;
	unsigned int io_opt;
	unsigned int max_discard_sectors;
	unsigned int max_hw_discard_sectors;
	unsigned int max_write_zeroes_sectors;
	unsigned int max_zone_append_sectors;
	unsigned int discard_granularity;
	unsigned int discard_alignment;
	unsigned int zone_write_granularity;
	short unsigned int max_segments;
	short unsigned int max_integrity_segments;
	short unsigned int max_discard_segments;
	unsigned char misaligned;
	unsigned char discard_misaligned;
	unsigned char raid_partial_stripes_expensive;
	enum blk_zoned_model zoned;
};

typedef void *mempool_alloc_t(gfp_t, void *);

typedef void mempool_free_t(void *, void *);

struct mempool_s {
	spinlock_t lock;
	int min_nr;
	int curr_nr;
	void **elements;
	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
};

typedef struct mempool_s mempool_t;

struct bio_alloc_cache;

struct bio_set {
	struct kmem_cache *bio_slab;
	unsigned int front_pad;
	struct bio_alloc_cache *cache;
	mempool_t bio_pool;
	mempool_t bvec_pool;
	unsigned int back_pad;
	spinlock_t rescue_lock;
	struct bio_list rescue_list;
	struct work_struct rescue_work;
	struct workqueue_struct *rescue_workqueue;
	struct hlist_node cpuhp_dead;
};

struct elevator_queue;

struct blk_queue_stats;

struct rq_qos;

struct blk_mq_ops;

struct blk_mq_ctx;

struct gendisk;

struct blk_stat_callback;

struct blk_rq_stat;

struct blk_mq_tags;

struct blk_flush_queue;

struct blk_mq_tag_set;

struct blk_independent_access_ranges;

struct request_queue {
	struct request *last_merge;
	struct elevator_queue *elevator;
	struct percpu_ref q_usage_counter;
	struct blk_queue_stats *stats;
	struct rq_qos *rq_qos;
	const struct blk_mq_ops *mq_ops;
	struct blk_mq_ctx *queue_ctx;
	unsigned int queue_depth;
	struct xarray hctx_table;
	unsigned int nr_hw_queues;
	void *queuedata;
	long unsigned int queue_flags;
	atomic_t pm_only;
	int id;
	spinlock_t queue_lock;
	struct gendisk *disk;
	struct kobject kobj;
	struct kobject *mq_kobj;
	long unsigned int nr_requests;
	unsigned int dma_pad_mask;
	unsigned int dma_alignment;
	unsigned int rq_timeout;
	int poll_nsec;
	struct blk_stat_callback *poll_cb;
	struct blk_rq_stat *poll_stat;
	struct timer_list timeout;
	struct work_struct timeout_work;
	atomic_t nr_active_requests_shared_tags;
	struct blk_mq_tags *sched_shared_tags;
	struct list_head icq_list;
	struct queue_limits limits;
	unsigned int required_elevator_features;
	int node;
	struct mutex debugfs_mutex;
	struct blk_flush_queue *fq;
	struct list_head requeue_list;
	spinlock_t requeue_lock;
	struct delayed_work requeue_work;
	struct mutex sysfs_lock;
	struct mutex sysfs_dir_lock;
	struct list_head unused_hctx_list;
	spinlock_t unused_hctx_lock;
	int mq_freeze_depth;
	struct callback_head callback_head;
	wait_queue_head_t mq_freeze_wq;
	struct mutex mq_freeze_lock;
	int quiesce_depth;
	struct blk_mq_tag_set *tag_set;
	struct list_head tag_set_list;
	struct bio_set bio_split;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct dentry *rqos_debugfs_dir;
	bool mq_sysfs_init_done;
	struct blk_independent_access_ranges *ia_ranges;
	struct srcu_struct srcu[0];
};

typedef void percpu_ref_func_t(struct percpu_ref *);

struct percpu_ref_data {
	atomic_long_t count;
	percpu_ref_func_t *release;
	percpu_ref_func_t *confirm_switch;
	bool force_atomic: 1;
	bool allow_reinit: 1;
	struct callback_head rcu;
	struct percpu_ref *ref;
};

enum kmalloc_cache_type {
	KMALLOC_NORMAL = 0,
	KMALLOC_DMA = 0,
	KMALLOC_CGROUP = 0,
	KMALLOC_RECLAIM = 1,
	NR_KMALLOC_TYPES = 2,
};

struct wait_page_queue;

struct kiocb {
	struct file *ki_filp;
	loff_t ki_pos;
	void (*ki_complete)(struct kiocb *, long int);
	void *private;
	int ki_flags;
	u16 ki_ioprio;
	struct wait_page_queue *ki_waitq;
};

struct iattr {
	unsigned int ia_valid;
	umode_t ia_mode;
	kuid_t ia_uid;
	kgid_t ia_gid;
	loff_t ia_size;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct file *ia_file;
};

typedef __kernel_uid32_t projid_t;

typedef struct {
	projid_t val;
} kprojid_t;

enum quota_type {
	USRQUOTA = 0,
	GRPQUOTA = 1,
	PRJQUOTA = 2,
};

struct kqid {
	union {
		kuid_t uid;
		kgid_t gid;
		kprojid_t projid;
	};
	enum quota_type type;
};

struct mem_dqblk {
	qsize_t dqb_bhardlimit;
	qsize_t dqb_bsoftlimit;
	qsize_t dqb_curspace;
	qsize_t dqb_rsvspace;
	qsize_t dqb_ihardlimit;
	qsize_t dqb_isoftlimit;
	qsize_t dqb_curinodes;
	time64_t dqb_btime;
	time64_t dqb_itime;
};

struct dquot {
	struct hlist_node dq_hash;
	struct list_head dq_inuse;
	struct list_head dq_free;
	struct list_head dq_dirty;
	struct mutex dq_lock;
	spinlock_t dq_dqb_lock;
	atomic_t dq_count;
	struct super_block *dq_sb;
	struct kqid dq_id;
	loff_t dq_off;
	long unsigned int dq_flags;
	struct mem_dqblk dq_dqb;
};

struct quota_format_type {
	int qf_fmt_id;
	const struct quota_format_ops *qf_ops;
	struct module *qf_owner;
	struct quota_format_type *qf_next;
};

struct quota_format_ops {
	int (*check_quota_file)(struct super_block *, int);
	int (*read_file_info)(struct super_block *, int);
	int (*write_file_info)(struct super_block *, int);
	int (*free_file_info)(struct super_block *, int);
	int (*read_dqblk)(struct dquot *);
	int (*commit_dqblk)(struct dquot *);
	int (*release_dqblk)(struct dquot *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct dquot_operations {
	int (*write_dquot)(struct dquot *);
	struct dquot * (*alloc_dquot)(struct super_block *, int);
	void (*destroy_dquot)(struct dquot *);
	int (*acquire_dquot)(struct dquot *);
	int (*release_dquot)(struct dquot *);
	int (*mark_dirty)(struct dquot *);
	int (*write_info)(struct super_block *, int);
	qsize_t * (*get_reserved_space)(struct inode *);
	int (*get_projid)(struct inode *, kprojid_t *);
	int (*get_inode_usage)(struct inode *, qsize_t *);
	int (*get_next_id)(struct super_block *, struct kqid *);
};

struct qc_dqblk {
	int d_fieldmask;
	u64 d_spc_hardlimit;
	u64 d_spc_softlimit;
	u64 d_ino_hardlimit;
	u64 d_ino_softlimit;
	u64 d_space;
	u64 d_ino_count;
	s64 d_ino_timer;
	s64 d_spc_timer;
	int d_ino_warns;
	int d_spc_warns;
	u64 d_rt_spc_hardlimit;
	u64 d_rt_spc_softlimit;
	u64 d_rt_space;
	s64 d_rt_spc_timer;
	int d_rt_spc_warns;
};

struct qc_type_state {
	unsigned int flags;
	unsigned int spc_timelimit;
	unsigned int ino_timelimit;
	unsigned int rt_spc_timelimit;
	unsigned int spc_warnlimit;
	unsigned int ino_warnlimit;
	unsigned int rt_spc_warnlimit;
	long long unsigned int ino;
	blkcnt_t blocks;
	blkcnt_t nextents;
};

struct qc_state {
	unsigned int s_incoredqs;
	struct qc_type_state s_state[3];
};

struct qc_info {
	int i_fieldmask;
	unsigned int i_flags;
	unsigned int i_spc_timelimit;
	unsigned int i_ino_timelimit;
	unsigned int i_rt_spc_timelimit;
	unsigned int i_spc_warnlimit;
	unsigned int i_ino_warnlimit;
	unsigned int i_rt_spc_warnlimit;
};

struct quotactl_ops {
	int (*quota_on)(struct super_block *, int, int, const struct path *);
	int (*quota_off)(struct super_block *, int);
	int (*quota_enable)(struct super_block *, unsigned int);
	int (*quota_disable)(struct super_block *, unsigned int);
	int (*quota_sync)(struct super_block *, int);
	int (*set_info)(struct super_block *, int, struct qc_info *);
	int (*get_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_nextdqblk)(struct super_block *, struct kqid *, struct qc_dqblk *);
	int (*set_dqblk)(struct super_block *, struct kqid, struct qc_dqblk *);
	int (*get_state)(struct super_block *, struct qc_state *);
	int (*rm_xquota)(struct super_block *, unsigned int);
};

struct wait_page_queue {
	struct folio *folio;
	int bit_nr;
	wait_queue_entry_t wait;
};

struct writeback_control;

struct readahead_control;

struct swap_info_struct;

struct address_space_operations {
	int (*writepage)(struct page *, struct writeback_control *);
	int (*readpage)(struct file *, struct page *);
	int (*writepages)(struct address_space *, struct writeback_control *);
	bool (*dirty_folio)(struct address_space *, struct folio *);
	void (*readahead)(struct readahead_control *);
	int (*write_begin)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct page **, void **);
	int (*write_end)(struct file *, struct address_space *, loff_t, unsigned int, unsigned int, struct page *, void *);
	sector_t (*bmap)(struct address_space *, sector_t);
	void (*invalidate_folio)(struct folio *, size_t, size_t);
	int (*releasepage)(struct page *, gfp_t);
	void (*freepage)(struct page *);
	ssize_t (*direct_IO)(struct kiocb *, struct iov_iter *);
	int (*migratepage)(struct address_space *, struct page *, struct page *, enum migrate_mode);
	bool (*isolate_page)(struct page *, isolate_mode_t);
	void (*putback_page)(struct page *);
	int (*launder_folio)(struct folio *);
	bool (*is_partially_uptodate)(struct folio *, size_t, size_t);
	void (*is_dirty_writeback)(struct page *, bool *, bool *);
	int (*error_remove_page)(struct address_space *, struct page *);
	int (*swap_activate)(struct swap_info_struct *, struct file *, sector_t *);
	void (*swap_deactivate)(struct file *);
};

enum writeback_sync_modes {
	WB_SYNC_NONE = 0,
	WB_SYNC_ALL = 1,
};

struct writeback_control {
	long int nr_to_write;
	long int pages_skipped;
	loff_t range_start;
	loff_t range_end;
	enum writeback_sync_modes sync_mode;
	unsigned int for_kupdate: 1;
	unsigned int for_background: 1;
	unsigned int tagged_writepages: 1;
	unsigned int for_reclaim: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_sync: 1;
	unsigned int unpinned_fscache_wb: 1;
	unsigned int no_cgroup_owner: 1;
	unsigned int punt_to_cgroup: 1;
};

struct readahead_control {
	struct file *file;
	struct address_space *mapping;
	struct file_ra_state *ra;
	long unsigned int _index;
	unsigned int _nr_pages;
	unsigned int _batch_count;
};

struct iovec;

struct kvec;

struct bio_vec;

struct iov_iter {
	u8 iter_type;
	bool nofault;
	bool data_source;
	size_t iov_offset;
	size_t count;
	union {
		const struct iovec *iov;
		const struct kvec *kvec;
		const struct bio_vec *bvec;
		struct xarray *xarray;
		struct pipe_inode_info *pipe;
	};
	union {
		long unsigned int nr_segs;
		struct {
			unsigned int head;
			unsigned int start_head;
		};
		loff_t xarray_start;
	};
};

struct swap_cluster_info {
	spinlock_t lock;
	unsigned int data: 24;
	unsigned int flags: 8;
};

struct swap_cluster_list {
	struct swap_cluster_info head;
	struct swap_cluster_info tail;
};

struct percpu_cluster;

struct swap_info_struct {
	struct percpu_ref users;
	long unsigned int flags;
	short int prio;
	struct plist_node list;
	signed char type;
	unsigned int max;
	unsigned char *swap_map;
	struct swap_cluster_info *cluster_info;
	struct swap_cluster_list free_clusters;
	unsigned int lowest_bit;
	unsigned int highest_bit;
	unsigned int pages;
	unsigned int inuse_pages;
	unsigned int cluster_next;
	unsigned int cluster_nr;
	unsigned int *cluster_next_cpu;
	struct percpu_cluster *percpu_cluster;
	struct rb_root swap_extent_root;
	struct block_device *bdev;
	struct file *swap_file;
	unsigned int old_block_size;
	struct completion comp;
	spinlock_t lock;
	spinlock_t cont_lock;
	struct work_struct discard_work;
	struct swap_cluster_list discard_clusters;
	struct plist_node avail_lists[0];
};

struct cdev {
	struct kobject kobj;
	struct module *owner;
	const struct file_operations *ops;
	struct list_head list;
	dev_t dev;
	unsigned int count;
};

struct posix_acl;

struct fiemap_extent_info;

struct fileattr;

struct inode_operations {
	struct dentry * (*lookup)(struct inode *, struct dentry *, unsigned int);
	const char * (*get_link)(struct dentry *, struct inode *, struct delayed_call *);
	int (*permission)(struct user_namespace *, struct inode *, int);
	struct posix_acl * (*get_acl)(struct inode *, int, bool);
	int (*readlink)(struct dentry *, char *, int);
	int (*create)(struct user_namespace *, struct inode *, struct dentry *, umode_t, bool);
	int (*link)(struct dentry *, struct inode *, struct dentry *);
	int (*unlink)(struct inode *, struct dentry *);
	int (*symlink)(struct user_namespace *, struct inode *, struct dentry *, const char *);
	int (*mkdir)(struct user_namespace *, struct inode *, struct dentry *, umode_t);
	int (*rmdir)(struct inode *, struct dentry *);
	int (*mknod)(struct user_namespace *, struct inode *, struct dentry *, umode_t, dev_t);
	int (*rename)(struct user_namespace *, struct inode *, struct dentry *, struct inode *, struct dentry *, unsigned int);
	int (*setattr)(struct user_namespace *, struct dentry *, struct iattr *);
	int (*getattr)(struct user_namespace *, const struct path *, struct kstat *, u32, unsigned int);
	ssize_t (*listxattr)(struct dentry *, char *, size_t);
	int (*fiemap)(struct inode *, struct fiemap_extent_info *, u64, u64);
	int (*update_time)(struct inode *, struct timespec64 *, int);
	int (*atomic_open)(struct inode *, struct dentry *, struct file *, unsigned int, umode_t);
	int (*tmpfile)(struct user_namespace *, struct inode *, struct dentry *, umode_t);
	int (*set_acl)(struct user_namespace *, struct inode *, struct posix_acl *, int);
	int (*fileattr_set)(struct user_namespace *, struct dentry *, struct fileattr *);
	int (*fileattr_get)(struct dentry *, struct fileattr *);
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct file_lock_context {
	spinlock_t flc_lock;
	struct list_head flc_flock;
	struct list_head flc_posix;
	struct list_head flc_lease;
};

struct file_lock_operations {
	void (*fl_copy_lock)(struct file_lock *, struct file_lock *);
	void (*fl_release_private)(struct file_lock *);
};

struct nlm_lockowner;

struct nfs_lock_info {
	u32 state;
	struct nlm_lockowner *owner;
	struct list_head list;
};

struct nfs4_lock_state;

struct nfs4_lock_info {
	struct nfs4_lock_state *owner;
};

struct lock_manager_operations;

struct file_lock {
	struct file_lock *fl_blocker;
	struct list_head fl_list;
	struct hlist_node fl_link;
	struct list_head fl_blocked_requests;
	struct list_head fl_blocked_member;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	unsigned int fl_pid;
	int fl_link_cpu;
	wait_queue_head_t fl_wait;
	struct file *fl_file;
	loff_t fl_start;
	loff_t fl_end;
	struct fasync_struct *fl_fasync;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	const struct file_lock_operations *fl_ops;
	const struct lock_manager_operations *fl_lmops;
	union {
		struct nfs_lock_info nfs_fl;
		struct nfs4_lock_info nfs4_fl;
		struct {
			struct list_head link;
			int state;
			unsigned int debug_id;
		} afs;
	} fl_u;
};

struct lock_manager_operations {
	fl_owner_t (*lm_get_owner)(fl_owner_t);
	void (*lm_put_owner)(fl_owner_t);
	void (*lm_notify)(struct file_lock *);
	int (*lm_grant)(struct file_lock *, int);
	bool (*lm_break)(struct file_lock *);
	int (*lm_change)(struct file_lock *, int, struct list_head *);
	void (*lm_setup)(struct file_lock *, void **);
	bool (*lm_breaker_owns_lease)(struct file_lock *);
};

struct fasync_struct {
	rwlock_t fa_lock;
	int magic;
	int fa_fd;
	struct fasync_struct *fa_next;
	struct file *fa_file;
	struct callback_head fa_rcu;
};

struct kstatfs;

struct super_operations {
	struct inode * (*alloc_inode)(struct super_block *);
	void (*destroy_inode)(struct inode *);
	void (*free_inode)(struct inode *);
	void (*dirty_inode)(struct inode *, int);
	int (*write_inode)(struct inode *, struct writeback_control *);
	int (*drop_inode)(struct inode *);
	void (*evict_inode)(struct inode *);
	void (*put_super)(struct super_block *);
	int (*sync_fs)(struct super_block *, int);
	int (*freeze_super)(struct super_block *);
	int (*freeze_fs)(struct super_block *);
	int (*thaw_super)(struct super_block *);
	int (*unfreeze_fs)(struct super_block *);
	int (*statfs)(struct dentry *, struct kstatfs *);
	int (*remount_fs)(struct super_block *, int *, char *);
	void (*umount_begin)(struct super_block *);
	int (*show_options)(struct seq_file *, struct dentry *);
	int (*show_devname)(struct seq_file *, struct dentry *);
	int (*show_path)(struct seq_file *, struct dentry *);
	int (*show_stats)(struct seq_file *, struct dentry *);
	long int (*nr_cached_objects)(struct super_block *, struct shrink_control *);
	long int (*free_cached_objects)(struct super_block *, struct shrink_control *);
};

struct iomap;

struct fid;

struct export_operations {
	int (*encode_fh)(struct inode *, __u32 *, int *, struct inode *);
	struct dentry * (*fh_to_dentry)(struct super_block *, struct fid *, int, int);
	struct dentry * (*fh_to_parent)(struct super_block *, struct fid *, int, int);
	int (*get_name)(struct dentry *, char *, struct dentry *);
	struct dentry * (*get_parent)(struct dentry *);
	int (*commit_metadata)(struct inode *);
	int (*get_uuid)(struct super_block *, u8 *, u32 *, u64 *);
	int (*map_blocks)(struct inode *, loff_t, u64, struct iomap *, bool, u32 *);
	int (*commit_blocks)(struct inode *, struct iomap *, int, struct iattr *);
	u64 (*fetch_iversion)(struct inode *);
	long unsigned int flags;
};

struct xattr_handler {
	const char *name;
	const char *prefix;
	int flags;
	bool (*list)(struct dentry *);
	int (*get)(const struct xattr_handler *, struct dentry *, struct inode *, const char *, void *, size_t);
	int (*set)(const struct xattr_handler *, struct user_namespace *, struct dentry *, struct inode *, const char *, const void *, size_t, int);
};

enum dl_dev_state {
	DL_DEV_NO_DRIVER = 0,
	DL_DEV_PROBING = 1,
	DL_DEV_DRIVER_BOUND = 2,
	DL_DEV_UNBINDING = 3,
};

struct dev_links_info {
	struct list_head suppliers;
	struct list_head consumers;
	struct list_head defer_sync;
	enum dl_dev_state status;
};

struct pm_message {
	int event;
};

typedef struct pm_message pm_message_t;

struct pm_subsys_data;

struct dev_pm_qos;

struct dev_pm_info {
	pm_message_t power_state;
	unsigned int can_wakeup: 1;
	unsigned int async_suspend: 1;
	bool in_dpm_list: 1;
	bool is_prepared: 1;
	bool is_suspended: 1;
	bool is_noirq_suspended: 1;
	bool is_late_suspended: 1;
	bool no_pm: 1;
	bool early_init: 1;
	bool direct_complete: 1;
	u32 driver_flags;
	spinlock_t lock;
	unsigned int should_wakeup: 1;
	struct pm_subsys_data *subsys_data;
	void (*set_latency_tolerance)(struct device *, s32);
	struct dev_pm_qos *qos;
};

struct dev_msi_info {};

struct dev_archdata {};

struct iommu_group;

struct dev_iommu;

enum device_removable {
	DEVICE_REMOVABLE_NOT_SUPPORTED = 0,
	DEVICE_REMOVABLE_UNKNOWN = 1,
	DEVICE_FIXED = 2,
	DEVICE_REMOVABLE = 3,
};

struct device_private;

struct device_type;

struct bus_type;

struct device_driver;

struct dev_pm_domain;

struct bus_dma_region;

struct device_dma_parameters;

struct dma_coherent_mem;

struct device_node;

struct fwnode_handle;

struct class;

struct device {
	struct kobject kobj;
	struct device *parent;
	struct device_private *p;
	const char *init_name;
	const struct device_type *type;
	struct bus_type *bus;
	struct device_driver *driver;
	void *platform_data;
	void *driver_data;
	struct mutex mutex;
	struct dev_links_info links;
	struct dev_pm_info power;
	struct dev_pm_domain *pm_domain;
	struct dev_msi_info msi;
	u64 *dma_mask;
	u64 coherent_dma_mask;
	u64 bus_dma_limit;
	const struct bus_dma_region *dma_range_map;
	struct device_dma_parameters *dma_parms;
	struct list_head dma_pools;
	struct dma_coherent_mem *dma_mem;
	struct dev_archdata archdata;
	struct device_node *of_node;
	struct fwnode_handle *fwnode;
	dev_t devt;
	u32 id;
	spinlock_t devres_lock;
	struct list_head devres_head;
	struct class *class;
	const struct attribute_group **groups;
	void (*release)(struct device *);
	struct iommu_group *iommu_group;
	struct dev_iommu *iommu;
	enum device_removable removable;
	bool offline_disabled: 1;
	bool offline: 1;
	bool of_node_reused: 1;
	bool state_synced: 1;
	bool can_match: 1;
	bool dma_coherent: 1;
};

struct disk_stats;

struct partition_meta_info;

struct block_device {
	sector_t bd_start_sect;
	sector_t bd_nr_sectors;
	struct disk_stats *bd_stats;
	long unsigned int bd_stamp;
	bool bd_read_only;
	dev_t bd_dev;
	int bd_openers;
	struct inode *bd_inode;
	struct super_block *bd_super;
	void *bd_claiming;
	struct device bd_device;
	void *bd_holder;
	int bd_holders;
	bool bd_write_holder;
	struct kobject *bd_holder_dir;
	u8 bd_partno;
	spinlock_t bd_size_lock;
	struct gendisk *bd_disk;
	struct request_queue *bd_queue;
	int bd_fsfreeze_count;
	struct mutex bd_fsfreeze_mutex;
	struct super_block *bd_fsfreeze_sb;
	struct partition_meta_info *bd_meta_info;
};

typedef int (*filldir_t)(struct dir_context *, const char *, int, loff_t, u64, unsigned int);

struct dir_context {
	filldir_t actor;
	loff_t pos;
};

struct io_comp_batch {
	struct request *req_list;
	bool need_ts;
	void (*complete)(struct io_comp_batch *);
};

struct fc_log;

struct p_log {
	const char *prefix;
	struct fc_log *log;
};

enum fs_context_purpose {
	FS_CONTEXT_FOR_MOUNT = 0,
	FS_CONTEXT_FOR_SUBMOUNT = 1,
	FS_CONTEXT_FOR_RECONFIGURE = 2,
};

enum fs_context_phase {
	FS_CONTEXT_CREATE_PARAMS = 0,
	FS_CONTEXT_CREATING = 1,
	FS_CONTEXT_AWAITING_MOUNT = 2,
	FS_CONTEXT_AWAITING_RECONF = 3,
	FS_CONTEXT_RECONF_PARAMS = 4,
	FS_CONTEXT_RECONFIGURING = 5,
	FS_CONTEXT_FAILED = 6,
};

struct fs_context_operations;

struct fs_context {
	const struct fs_context_operations *ops;
	struct mutex uapi_mutex;
	struct file_system_type *fs_type;
	void *fs_private;
	void *sget_key;
	struct dentry *root;
	struct user_namespace *user_ns;
	struct net *net_ns;
	const struct cred *cred;
	struct p_log log;
	const char *source;
	void *security;
	void *s_fs_info;
	unsigned int sb_flags;
	unsigned int sb_flags_mask;
	unsigned int s_iflags;
	unsigned int lsm_flags;
	enum fs_context_purpose purpose: 8;
	enum fs_context_phase phase: 8;
	bool need_free: 1;
	bool global: 1;
	bool oldapi: 1;
};

struct fs_parameter;

struct fs_parse_result;

typedef int fs_param_type(struct p_log *, const struct fs_parameter_spec *, struct fs_parameter *, struct fs_parse_result *);

struct fs_parameter_spec {
	const char *name;
	fs_param_type *type;
	u8 opt;
	short unsigned int flags;
	const void *data;
};

struct audit_names;

struct filename {
	const char *name;
	const char *uptr;
	int refcnt;
	struct audit_names *aname;
	const char iname[0];
};

typedef u8 blk_status_t;

struct bvec_iter {
	sector_t bi_sector;
	unsigned int bi_size;
	unsigned int bi_idx;
	unsigned int bi_bvec_done;
};

typedef unsigned int blk_qc_t;

typedef void bio_end_io_t(struct bio *);

struct bio_vec {
	struct page *bv_page;
	unsigned int bv_len;
	unsigned int bv_offset;
};

struct bio {
	struct bio *bi_next;
	struct block_device *bi_bdev;
	unsigned int bi_opf;
	short unsigned int bi_flags;
	short unsigned int bi_ioprio;
	blk_status_t bi_status;
	atomic_t __bi_remaining;
	struct bvec_iter bi_iter;
	blk_qc_t bi_cookie;
	bio_end_io_t *bi_end_io;
	void *bi_private;
	union {};
	short unsigned int bi_vcnt;
	short unsigned int bi_max_vecs;
	atomic_t __bi_cnt;
	struct bio_vec *bi_io_vec;
	struct bio_set *bi_pool;
	struct bio_vec bi_inline_vecs[0];
};

struct linux_binprm {
	struct vm_area_struct *vma;
	long unsigned int vma_pages;
	struct mm_struct *mm;
	long unsigned int p;
	long unsigned int argmin;
	unsigned int have_execfd: 1;
	unsigned int execfd_creds: 1;
	unsigned int secureexec: 1;
	unsigned int point_of_no_return: 1;
	struct file *executable;
	struct file *interpreter;
	struct file *file;
	struct cred *cred;
	int unsafe;
	unsigned int per_clear;
	int argc;
	int envc;
	const char *filename;
	const char *interp;
	const char *fdpath;
	unsigned int interp_flags;
	int execfd;
	long unsigned int loader;
	long unsigned int exec;
	struct rlimit rlim_stack;
	char buf[256];
};

struct dev_pm_ops {
	int (*prepare)(struct device *);
	void (*complete)(struct device *);
	int (*suspend)(struct device *);
	int (*resume)(struct device *);
	int (*freeze)(struct device *);
	int (*thaw)(struct device *);
	int (*poweroff)(struct device *);
	int (*restore)(struct device *);
	int (*suspend_late)(struct device *);
	int (*resume_early)(struct device *);
	int (*freeze_late)(struct device *);
	int (*thaw_early)(struct device *);
	int (*poweroff_late)(struct device *);
	int (*restore_early)(struct device *);
	int (*suspend_noirq)(struct device *);
	int (*resume_noirq)(struct device *);
	int (*freeze_noirq)(struct device *);
	int (*thaw_noirq)(struct device *);
	int (*poweroff_noirq)(struct device *);
	int (*restore_noirq)(struct device *);
	int (*runtime_suspend)(struct device *);
	int (*runtime_resume)(struct device *);
	int (*runtime_idle)(struct device *);
};

struct pm_subsys_data {
	spinlock_t lock;
	unsigned int refcount;
};

struct dev_pm_domain {
	struct dev_pm_ops ops;
	int (*start)(struct device *);
	void (*detach)(struct device *, bool);
	int (*activate)(struct device *);
	void (*sync)(struct device *);
	void (*dismiss)(struct device *);
};

struct iommu_ops;

struct subsys_private;

struct bus_type {
	const char *name;
	const char *dev_name;
	struct device *dev_root;
	const struct attribute_group **bus_groups;
	const struct attribute_group **dev_groups;
	const struct attribute_group **drv_groups;
	int (*match)(struct device *, struct device_driver *);
	int (*uevent)(struct device *, struct kobj_uevent_env *);
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	void (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*online)(struct device *);
	int (*offline)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	int (*num_vf)(struct device *);
	int (*dma_configure)(struct device *);
	const struct dev_pm_ops *pm;
	const struct iommu_ops *iommu_ops;
	struct subsys_private *p;
	struct lock_class_key lock_key;
	bool need_parent_lock;
};

enum probe_type {
	PROBE_DEFAULT_STRATEGY = 0,
	PROBE_PREFER_ASYNCHRONOUS = 1,
	PROBE_FORCE_SYNCHRONOUS = 2,
};

struct of_device_id;

struct acpi_device_id;

struct driver_private;

struct device_driver {
	const char *name;
	struct bus_type *bus;
	struct module *owner;
	const char *mod_name;
	bool suppress_bind_attrs;
	enum probe_type probe_type;
	const struct of_device_id *of_match_table;
	const struct acpi_device_id *acpi_match_table;
	int (*probe)(struct device *);
	void (*sync_state)(struct device *);
	int (*remove)(struct device *);
	void (*shutdown)(struct device *);
	int (*suspend)(struct device *, pm_message_t);
	int (*resume)(struct device *);
	const struct attribute_group **groups;
	const struct attribute_group **dev_groups;
	const struct dev_pm_ops *pm;
	void (*coredump)(struct device *);
	struct driver_private *p;
};

struct device_type {
	const char *name;
	const struct attribute_group **groups;
	int (*uevent)(struct device *, struct kobj_uevent_env *);
	char * (*devnode)(struct device *, umode_t *, kuid_t *, kgid_t *);
	void (*release)(struct device *);
	const struct dev_pm_ops *pm;
};

struct class {
	const char *name;
	struct module *owner;
	const struct attribute_group **class_groups;
	const struct attribute_group **dev_groups;
	struct kobject *dev_kobj;
	int (*dev_uevent)(struct device *, struct kobj_uevent_env *);
	char * (*devnode)(struct device *, umode_t *);
	void (*class_release)(struct class *);
	void (*dev_release)(struct device *);
	int (*shutdown_pre)(struct device *);
	const struct kobj_ns_type_operations *ns_type;
	const void * (*namespace)(struct device *);
	void (*get_ownership)(struct device *, kuid_t *, kgid_t *);
	const struct dev_pm_ops *pm;
	struct subsys_private *p;
};

struct of_device_id {
	char name[32];
	char type[32];
	char compatible[128];
	const void *data;
};

typedef long unsigned int kernel_ulong_t;

struct acpi_device_id {
	__u8 id[16];
	kernel_ulong_t driver_data;
	__u32 cls;
	__u32 cls_msk;
};

struct device_dma_parameters {
	unsigned int max_segment_size;
	unsigned int min_align_mask;
	long unsigned int segment_boundary_mask;
};

typedef u32 dma_addr_t;

struct bus_dma_region {
	phys_addr_t cpu_start;
	dma_addr_t dma_start;
	u64 size;
	u64 offset;
};

typedef u32 phandle;

struct fwnode_operations;

struct fwnode_handle {
	struct fwnode_handle *secondary;
	const struct fwnode_operations *ops;
	struct device *dev;
	struct list_head suppliers;
	struct list_head consumers;
	u8 flags;
};

struct property;

struct device_node {
	const char *name;
	phandle phandle;
	const char *full_name;
	struct fwnode_handle fwnode;
	struct property *properties;
	struct property *deadprops;
	struct device_node *parent;
	struct device_node *child;
	struct device_node *sibling;
	struct kobject kobj;
	long unsigned int _flags;
	void *data;
};

enum cpuhp_state {
	CPUHP_INVALID = 4294967295,
	CPUHP_OFFLINE = 0,
	CPUHP_CREATE_THREADS = 1,
	CPUHP_PERF_PREPARE = 2,
	CPUHP_PERF_X86_PREPARE = 3,
	CPUHP_PERF_X86_AMD_UNCORE_PREP = 4,
	CPUHP_PERF_POWER = 5,
	CPUHP_PERF_SUPERH = 6,
	CPUHP_X86_HPET_DEAD = 7,
	CPUHP_X86_APB_DEAD = 8,
	CPUHP_X86_MCE_DEAD = 9,
	CPUHP_VIRT_NET_DEAD = 10,
	CPUHP_SLUB_DEAD = 11,
	CPUHP_DEBUG_OBJ_DEAD = 12,
	CPUHP_MM_WRITEBACK_DEAD = 13,
	CPUHP_MM_DEMOTION_DEAD = 14,
	CPUHP_MM_VMSTAT_DEAD = 15,
	CPUHP_SOFTIRQ_DEAD = 16,
	CPUHP_NET_MVNETA_DEAD = 17,
	CPUHP_CPUIDLE_DEAD = 18,
	CPUHP_ARM64_FPSIMD_DEAD = 19,
	CPUHP_ARM_OMAP_WAKE_DEAD = 20,
	CPUHP_IRQ_POLL_DEAD = 21,
	CPUHP_BLOCK_SOFTIRQ_DEAD = 22,
	CPUHP_BIO_DEAD = 23,
	CPUHP_ACPI_CPUDRV_DEAD = 24,
	CPUHP_S390_PFAULT_DEAD = 25,
	CPUHP_BLK_MQ_DEAD = 26,
	CPUHP_FS_BUFF_DEAD = 27,
	CPUHP_PRINTK_DEAD = 28,
	CPUHP_MM_MEMCQ_DEAD = 29,
	CPUHP_XFS_DEAD = 30,
	CPUHP_PERCPU_CNT_DEAD = 31,
	CPUHP_RADIX_DEAD = 32,
	CPUHP_PAGE_ALLOC = 33,
	CPUHP_NET_DEV_DEAD = 34,
	CPUHP_PCI_XGENE_DEAD = 35,
	CPUHP_IOMMU_IOVA_DEAD = 36,
	CPUHP_LUSTRE_CFS_DEAD = 37,
	CPUHP_AP_ARM_CACHE_B15_RAC_DEAD = 38,
	CPUHP_PADATA_DEAD = 39,
	CPUHP_AP_DTPM_CPU_DEAD = 40,
	CPUHP_RANDOM_PREPARE = 41,
	CPUHP_WORKQUEUE_PREP = 42,
	CPUHP_POWER_NUMA_PREPARE = 43,
	CPUHP_HRTIMERS_PREPARE = 44,
	CPUHP_PROFILE_PREPARE = 45,
	CPUHP_X2APIC_PREPARE = 46,
	CPUHP_SMPCFD_PREPARE = 47,
	CPUHP_RELAY_PREPARE = 48,
	CPUHP_SLAB_PREPARE = 49,
	CPUHP_MD_RAID5_PREPARE = 50,
	CPUHP_RCUTREE_PREP = 51,
	CPUHP_CPUIDLE_COUPLED_PREPARE = 52,
	CPUHP_POWERPC_PMAC_PREPARE = 53,
	CPUHP_POWERPC_MMU_CTX_PREPARE = 54,
	CPUHP_XEN_PREPARE = 55,
	CPUHP_XEN_EVTCHN_PREPARE = 56,
	CPUHP_ARM_SHMOBILE_SCU_PREPARE = 57,
	CPUHP_SH_SH3X_PREPARE = 58,
	CPUHP_NET_FLOW_PREPARE = 59,
	CPUHP_TOPOLOGY_PREPARE = 60,
	CPUHP_NET_IUCV_PREPARE = 61,
	CPUHP_ARM_BL_PREPARE = 62,
	CPUHP_TRACE_RB_PREPARE = 63,
	CPUHP_MM_ZS_PREPARE = 64,
	CPUHP_MM_ZSWP_MEM_PREPARE = 65,
	CPUHP_MM_ZSWP_POOL_PREPARE = 66,
	CPUHP_KVM_PPC_BOOK3S_PREPARE = 67,
	CPUHP_ZCOMP_PREPARE = 68,
	CPUHP_TIMERS_PREPARE = 69,
	CPUHP_MIPS_SOC_PREPARE = 70,
	CPUHP_BP_PREPARE_DYN = 71,
	CPUHP_BP_PREPARE_DYN_END = 91,
	CPUHP_BRINGUP_CPU = 92,
	CPUHP_AP_IDLE_DEAD = 93,
	CPUHP_AP_OFFLINE = 94,
	CPUHP_AP_SCHED_STARTING = 95,
	CPUHP_AP_RCUTREE_DYING = 96,
	CPUHP_AP_CPU_PM_STARTING = 97,
	CPUHP_AP_IRQ_GIC_STARTING = 98,
	CPUHP_AP_IRQ_HIP04_STARTING = 99,
	CPUHP_AP_IRQ_APPLE_AIC_STARTING = 100,
	CPUHP_AP_IRQ_ARMADA_XP_STARTING = 101,
	CPUHP_AP_IRQ_BCM2836_STARTING = 102,
	CPUHP_AP_IRQ_MIPS_GIC_STARTING = 103,
	CPUHP_AP_IRQ_RISCV_STARTING = 104,
	CPUHP_AP_IRQ_SIFIVE_PLIC_STARTING = 105,
	CPUHP_AP_ARM_MVEBU_COHERENCY = 106,
	CPUHP_AP_MICROCODE_LOADER = 107,
	CPUHP_AP_PERF_X86_AMD_UNCORE_STARTING = 108,
	CPUHP_AP_PERF_X86_STARTING = 109,
	CPUHP_AP_PERF_X86_AMD_IBS_STARTING = 110,
	CPUHP_AP_PERF_X86_CQM_STARTING = 111,
	CPUHP_AP_PERF_X86_CSTATE_STARTING = 112,
	CPUHP_AP_PERF_XTENSA_STARTING = 113,
	CPUHP_AP_MIPS_OP_LOONGSON3_STARTING = 114,
	CPUHP_AP_ARM_SDEI_STARTING = 115,
	CPUHP_AP_ARM_VFP_STARTING = 116,
	CPUHP_AP_ARM64_DEBUG_MONITORS_STARTING = 117,
	CPUHP_AP_PERF_ARM_HW_BREAKPOINT_STARTING = 118,
	CPUHP_AP_PERF_ARM_ACPI_STARTING = 119,
	CPUHP_AP_PERF_ARM_STARTING = 120,
	CPUHP_AP_PERF_RISCV_STARTING = 121,
	CPUHP_AP_ARM_L2X0_STARTING = 122,
	CPUHP_AP_EXYNOS4_MCT_TIMER_STARTING = 123,
	CPUHP_AP_ARM_ARCH_TIMER_STARTING = 124,
	CPUHP_AP_ARM_GLOBAL_TIMER_STARTING = 125,
	CPUHP_AP_JCORE_TIMER_STARTING = 126,
	CPUHP_AP_ARM_TWD_STARTING = 127,
	CPUHP_AP_QCOM_TIMER_STARTING = 128,
	CPUHP_AP_TEGRA_TIMER_STARTING = 129,
	CPUHP_AP_ARMADA_TIMER_STARTING = 130,
	CPUHP_AP_MARCO_TIMER_STARTING = 131,
	CPUHP_AP_MIPS_GIC_TIMER_STARTING = 132,
	CPUHP_AP_ARC_TIMER_STARTING = 133,
	CPUHP_AP_RISCV_TIMER_STARTING = 134,
	CPUHP_AP_CLINT_TIMER_STARTING = 135,
	CPUHP_AP_CSKY_TIMER_STARTING = 136,
	CPUHP_AP_TI_GP_TIMER_STARTING = 137,
	CPUHP_AP_HYPERV_TIMER_STARTING = 138,
	CPUHP_AP_KVM_STARTING = 139,
	CPUHP_AP_KVM_ARM_VGIC_INIT_STARTING = 140,
	CPUHP_AP_KVM_ARM_VGIC_STARTING = 141,
	CPUHP_AP_KVM_ARM_TIMER_STARTING = 142,
	CPUHP_AP_DUMMY_TIMER_STARTING = 143,
	CPUHP_AP_ARM_XEN_STARTING = 144,
	CPUHP_AP_ARM_CORESIGHT_STARTING = 145,
	CPUHP_AP_ARM_CORESIGHT_CTI_STARTING = 146,
	CPUHP_AP_ARM64_ISNDEP_STARTING = 147,
	CPUHP_AP_SMPCFD_DYING = 148,
	CPUHP_AP_X86_TBOOT_DYING = 149,
	CPUHP_AP_ARM_CACHE_B15_RAC_DYING = 150,
	CPUHP_AP_ONLINE = 151,
	CPUHP_TEARDOWN_CPU = 152,
	CPUHP_AP_ONLINE_IDLE = 153,
	CPUHP_AP_SCHED_WAIT_EMPTY = 154,
	CPUHP_AP_SMPBOOT_THREADS = 155,
	CPUHP_AP_X86_VDSO_VMA_ONLINE = 156,
	CPUHP_AP_IRQ_AFFINITY_ONLINE = 157,
	CPUHP_AP_BLK_MQ_ONLINE = 158,
	CPUHP_AP_ARM_MVEBU_SYNC_CLOCKS = 159,
	CPUHP_AP_X86_INTEL_EPB_ONLINE = 160,
	CPUHP_AP_PERF_ONLINE = 161,
	CPUHP_AP_PERF_X86_ONLINE = 162,
	CPUHP_AP_PERF_X86_UNCORE_ONLINE = 163,
	CPUHP_AP_PERF_X86_AMD_UNCORE_ONLINE = 164,
	CPUHP_AP_PERF_X86_AMD_POWER_ONLINE = 165,
	CPUHP_AP_PERF_X86_RAPL_ONLINE = 166,
	CPUHP_AP_PERF_X86_CQM_ONLINE = 167,
	CPUHP_AP_PERF_X86_CSTATE_ONLINE = 168,
	CPUHP_AP_PERF_X86_IDXD_ONLINE = 169,
	CPUHP_AP_PERF_S390_CF_ONLINE = 170,
	CPUHP_AP_PERF_S390_SF_ONLINE = 171,
	CPUHP_AP_PERF_ARM_CCI_ONLINE = 172,
	CPUHP_AP_PERF_ARM_CCN_ONLINE = 173,
	CPUHP_AP_PERF_ARM_HISI_DDRC_ONLINE = 174,
	CPUHP_AP_PERF_ARM_HISI_HHA_ONLINE = 175,
	CPUHP_AP_PERF_ARM_HISI_L3_ONLINE = 176,
	CPUHP_AP_PERF_ARM_HISI_PA_ONLINE = 177,
	CPUHP_AP_PERF_ARM_HISI_SLLC_ONLINE = 178,
	CPUHP_AP_PERF_ARM_HISI_PCIE_PMU_ONLINE = 179,
	CPUHP_AP_PERF_ARM_L2X0_ONLINE = 180,
	CPUHP_AP_PERF_ARM_QCOM_L2_ONLINE = 181,
	CPUHP_AP_PERF_ARM_QCOM_L3_ONLINE = 182,
	CPUHP_AP_PERF_ARM_APM_XGENE_ONLINE = 183,
	CPUHP_AP_PERF_ARM_CAVIUM_TX2_UNCORE_ONLINE = 184,
	CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE = 185,
	CPUHP_AP_PERF_POWERPC_NEST_IMC_ONLINE = 186,
	CPUHP_AP_PERF_POWERPC_CORE_IMC_ONLINE = 187,
	CPUHP_AP_PERF_POWERPC_THREAD_IMC_ONLINE = 188,
	CPUHP_AP_PERF_POWERPC_TRACE_IMC_ONLINE = 189,
	CPUHP_AP_PERF_POWERPC_HV_24x7_ONLINE = 190,
	CPUHP_AP_PERF_POWERPC_HV_GPCI_ONLINE = 191,
	CPUHP_AP_PERF_CSKY_ONLINE = 192,
	CPUHP_AP_WATCHDOG_ONLINE = 193,
	CPUHP_AP_WORKQUEUE_ONLINE = 194,
	CPUHP_AP_RANDOM_ONLINE = 195,
	CPUHP_AP_RCUTREE_ONLINE = 196,
	CPUHP_AP_BASE_CACHEINFO_ONLINE = 197,
	CPUHP_AP_ONLINE_DYN = 198,
	CPUHP_AP_ONLINE_DYN_END = 228,
	CPUHP_AP_MM_DEMOTION_ONLINE = 229,
	CPUHP_AP_X86_HPET_ONLINE = 230,
	CPUHP_AP_X86_KVM_CLK_ONLINE = 231,
	CPUHP_AP_ACTIVE = 232,
	CPUHP_ONLINE = 233,
};

struct seq_operations {
	void * (*start)(struct seq_file *, loff_t *);
	void (*stop)(struct seq_file *, void *);
	void * (*next)(struct seq_file *, void *, loff_t *);
	int (*show)(struct seq_file *, void *);
};

struct ring_buffer_event {
	u32 type_len: 5;
	u32 time_delta: 27;
	u32 array[0];
};

struct seq_buf {
	char *buffer;
	size_t size;
	size_t len;
	loff_t readpos;
};

struct trace_seq {
	char buffer[8192];
	struct seq_buf seq;
	int full;
};

struct fwnode_reference_args;

struct fwnode_endpoint;

struct fwnode_operations {
	struct fwnode_handle * (*get)(struct fwnode_handle *);
	void (*put)(struct fwnode_handle *);
	bool (*device_is_available)(const struct fwnode_handle *);
	const void * (*device_get_match_data)(const struct fwnode_handle *, const struct device *);
	bool (*property_present)(const struct fwnode_handle *, const char *);
	int (*property_read_int_array)(const struct fwnode_handle *, const char *, unsigned int, void *, size_t);
	int (*property_read_string_array)(const struct fwnode_handle *, const char *, const char **, size_t);
	const char * (*get_name)(const struct fwnode_handle *);
	const char * (*get_name_prefix)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_parent)(const struct fwnode_handle *);
	struct fwnode_handle * (*get_next_child_node)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*get_named_child_node)(const struct fwnode_handle *, const char *);
	int (*get_reference_args)(const struct fwnode_handle *, const char *, const char *, unsigned int, unsigned int, struct fwnode_reference_args *);
	struct fwnode_handle * (*graph_get_next_endpoint)(const struct fwnode_handle *, struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_remote_endpoint)(const struct fwnode_handle *);
	struct fwnode_handle * (*graph_get_port_parent)(struct fwnode_handle *);
	int (*graph_parse_endpoint)(const struct fwnode_handle *, struct fwnode_endpoint *);
	int (*add_links)(struct fwnode_handle *);
};

struct fwnode_endpoint {
	unsigned int port;
	unsigned int id;
	const struct fwnode_handle *local_fwnode;
};

struct fwnode_reference_args {
	struct fwnode_handle *fwnode;
	unsigned int nargs;
	u64 args[8];
};

enum perf_sw_ids {
	PERF_COUNT_SW_CPU_CLOCK = 0,
	PERF_COUNT_SW_TASK_CLOCK = 1,
	PERF_COUNT_SW_PAGE_FAULTS = 2,
	PERF_COUNT_SW_CONTEXT_SWITCHES = 3,
	PERF_COUNT_SW_CPU_MIGRATIONS = 4,
	PERF_COUNT_SW_PAGE_FAULTS_MIN = 5,
	PERF_COUNT_SW_PAGE_FAULTS_MAJ = 6,
	PERF_COUNT_SW_ALIGNMENT_FAULTS = 7,
	PERF_COUNT_SW_EMULATION_FAULTS = 8,
	PERF_COUNT_SW_DUMMY = 9,
	PERF_COUNT_SW_BPF_OUTPUT = 10,
	PERF_COUNT_SW_CGROUP_SWITCHES = 11,
	PERF_COUNT_SW_MAX = 12,
};

struct perf_event_attr {
	__u32 type;
	__u32 size;
	__u64 config;
	union {
		__u64 sample_period;
		__u64 sample_freq;
	};
	__u64 sample_type;
	__u64 read_format;
	__u64 disabled: 1;
	__u64 inherit: 1;
	__u64 pinned: 1;
	__u64 exclusive: 1;
	__u64 exclude_user: 1;
	__u64 exclude_kernel: 1;
	__u64 exclude_hv: 1;
	__u64 exclude_idle: 1;
	__u64 mmap: 1;
	__u64 comm: 1;
	__u64 freq: 1;
	__u64 inherit_stat: 1;
	__u64 enable_on_exec: 1;
	__u64 task: 1;
	__u64 watermark: 1;
	__u64 precise_ip: 2;
	__u64 mmap_data: 1;
	__u64 sample_id_all: 1;
	__u64 exclude_host: 1;
	__u64 exclude_guest: 1;
	__u64 exclude_callchain_kernel: 1;
	__u64 exclude_callchain_user: 1;
	__u64 mmap2: 1;
	__u64 comm_exec: 1;
	__u64 use_clockid: 1;
	__u64 context_switch: 1;
	__u64 write_backward: 1;
	__u64 namespaces: 1;
	__u64 ksymbol: 1;
	__u64 bpf_event: 1;
	__u64 aux_output: 1;
	__u64 cgroup: 1;
	__u64 text_poke: 1;
	__u64 build_id: 1;
	__u64 inherit_thread: 1;
	__u64 remove_on_exec: 1;
	__u64 sigtrap: 1;
	__u64 __reserved_1: 26;
	union {
		__u32 wakeup_events;
		__u32 wakeup_watermark;
	};
	__u32 bp_type;
	union {
		__u64 bp_addr;
		__u64 kprobe_func;
		__u64 uprobe_path;
		__u64 config1;
	};
	union {
		__u64 bp_len;
		__u64 kprobe_addr;
		__u64 probe_offset;
		__u64 config2;
	};
	__u64 branch_sample_type;
	__u64 sample_regs_user;
	__u32 sample_stack_user;
	__s32 clockid;
	__u64 sample_regs_intr;
	__u32 aux_watermark;
	__u16 sample_max_stack;
	__u16 __reserved_2;
	__u32 aux_sample_size;
	__u32 __reserved_3;
	__u64 sig_data;
};

union perf_mem_data_src {
	__u64 val;
	struct {
		__u64 mem_op: 5;
		__u64 mem_lvl: 14;
		__u64 mem_snoop: 5;
		__u64 mem_lock: 2;
		__u64 mem_dtlb: 7;
		__u64 mem_lvl_num: 4;
		__u64 mem_remote: 1;
		__u64 mem_snoopx: 2;
		__u64 mem_blk: 3;
		__u64 mem_hops: 3;
		__u64 mem_rsvd: 18;
	};
};

struct perf_branch_entry {
	__u64 from;
	__u64 to;
	__u64 mispred: 1;
	__u64 predicted: 1;
	__u64 in_tx: 1;
	__u64 abort: 1;
	__u64 cycles: 16;
	__u64 type: 4;
	__u64 reserved: 40;
};

union perf_sample_weight {
	__u64 full;
	struct {
		__u32 var1_dw;
		__u16 var2_w;
		__u16 var3_w;
	};
};

typedef struct {
	atomic64_t a;
} local64_t;

struct new_utsname {
	char sysname[65];
	char nodename[65];
	char release[65];
	char version[65];
	char machine[65];
	char domainname[65];
};

struct uts_namespace {
	struct new_utsname name;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
};

struct ref_tracker_dir {};

struct prot_inuse;

struct netns_core {
	struct ctl_table_header *sysctl_hdr;
	int sysctl_somaxconn;
	u8 sysctl_txrehash;
	struct prot_inuse *prot_inuse;
};

struct ipstats_mib;

struct tcp_mib;

struct linux_mib;

struct udp_mib;

struct icmp_mib;

struct icmpmsg_mib;

struct netns_mib {
	struct ipstats_mib *ip_statistics;
	struct tcp_mib *tcp_statistics;
	struct linux_mib *net_statistics;
	struct udp_mib *udp_statistics;
	struct udp_mib *udplite_statistics;
	struct icmp_mib *icmp_statistics;
	struct icmpmsg_mib *icmpmsg_statistics;
};

struct netns_packet {
	struct mutex sklist_lock;
	struct hlist_head sklist;
};

struct netns_unix {
	int sysctl_max_dgram_qlen;
	struct ctl_table_header *ctl;
};

struct netns_nexthop {
	struct rb_root rb_root;
	struct hlist_head *devhash;
	unsigned int seq;
	u32 last_id_allocated;
	struct blocking_notifier_head notifier_chain;
};

struct local_ports {
	seqlock_t lock;
	int range[2];
	bool warned;
};

struct ping_group_range {
	seqlock_t lock;
	kgid_t range[2];
};

typedef struct {
	u64 key[2];
} siphash_key_t;

struct inet_timewait_death_row;

struct ipv4_devconf;

struct ip_ra_chain;

struct inet_peer_base;

struct fqdir;

struct tcp_congestion_ops;

struct tcp_fastopen_context;

struct fib_notifier_ops;

struct netns_ipv4 {
	struct inet_timewait_death_row *tcp_death_row;
	struct ctl_table_header *forw_hdr;
	struct ctl_table_header *frags_hdr;
	struct ctl_table_header *ipv4_hdr;
	struct ctl_table_header *route_hdr;
	struct ctl_table_header *xfrm4_hdr;
	struct ipv4_devconf *devconf_all;
	struct ipv4_devconf *devconf_dflt;
	struct ip_ra_chain *ra_chain;
	struct mutex ra_mutex;
	bool fib_has_custom_local_routes;
	bool fib_offload_disabled;
	struct hlist_head *fib_table_hash;
	struct sock *fibnl;
	struct sock *mc_autojoin_sk;
	struct inet_peer_base *peers;
	struct fqdir *fqdir;
	u8 sysctl_icmp_echo_ignore_all;
	u8 sysctl_icmp_echo_enable_probe;
	u8 sysctl_icmp_echo_ignore_broadcasts;
	u8 sysctl_icmp_ignore_bogus_error_responses;
	u8 sysctl_icmp_errors_use_inbound_ifaddr;
	int sysctl_icmp_ratelimit;
	int sysctl_icmp_ratemask;
	u32 ip_rt_min_pmtu;
	int ip_rt_mtu_expires;
	int ip_rt_min_advmss;
	struct local_ports ip_local_ports;
	u8 sysctl_tcp_ecn;
	u8 sysctl_tcp_ecn_fallback;
	u8 sysctl_ip_default_ttl;
	u8 sysctl_ip_no_pmtu_disc;
	u8 sysctl_ip_fwd_use_pmtu;
	u8 sysctl_ip_fwd_update_priority;
	u8 sysctl_ip_nonlocal_bind;
	u8 sysctl_ip_autobind_reuse;
	u8 sysctl_ip_dynaddr;
	u8 sysctl_ip_early_demux;
	u8 sysctl_tcp_early_demux;
	u8 sysctl_udp_early_demux;
	u8 sysctl_nexthop_compat_mode;
	u8 sysctl_fwmark_reflect;
	u8 sysctl_tcp_fwmark_accept;
	u8 sysctl_tcp_mtu_probing;
	int sysctl_tcp_mtu_probe_floor;
	int sysctl_tcp_base_mss;
	int sysctl_tcp_min_snd_mss;
	int sysctl_tcp_probe_threshold;
	u32 sysctl_tcp_probe_interval;
	int sysctl_tcp_keepalive_time;
	int sysctl_tcp_keepalive_intvl;
	u8 sysctl_tcp_keepalive_probes;
	u8 sysctl_tcp_syn_retries;
	u8 sysctl_tcp_synack_retries;
	u8 sysctl_tcp_syncookies;
	u8 sysctl_tcp_migrate_req;
	u8 sysctl_tcp_comp_sack_nr;
	int sysctl_tcp_reordering;
	u8 sysctl_tcp_retries1;
	u8 sysctl_tcp_retries2;
	u8 sysctl_tcp_orphan_retries;
	u8 sysctl_tcp_tw_reuse;
	int sysctl_tcp_fin_timeout;
	unsigned int sysctl_tcp_notsent_lowat;
	u8 sysctl_tcp_sack;
	u8 sysctl_tcp_window_scaling;
	u8 sysctl_tcp_timestamps;
	u8 sysctl_tcp_early_retrans;
	u8 sysctl_tcp_recovery;
	u8 sysctl_tcp_thin_linear_timeouts;
	u8 sysctl_tcp_slow_start_after_idle;
	u8 sysctl_tcp_retrans_collapse;
	u8 sysctl_tcp_stdurg;
	u8 sysctl_tcp_rfc1337;
	u8 sysctl_tcp_abort_on_overflow;
	u8 sysctl_tcp_fack;
	int sysctl_tcp_max_reordering;
	int sysctl_tcp_adv_win_scale;
	u8 sysctl_tcp_dsack;
	u8 sysctl_tcp_app_win;
	u8 sysctl_tcp_frto;
	u8 sysctl_tcp_nometrics_save;
	u8 sysctl_tcp_no_ssthresh_metrics_save;
	u8 sysctl_tcp_moderate_rcvbuf;
	u8 sysctl_tcp_tso_win_divisor;
	u8 sysctl_tcp_workaround_signed_windows;
	int sysctl_tcp_limit_output_bytes;
	int sysctl_tcp_challenge_ack_limit;
	int sysctl_tcp_min_rtt_wlen;
	u8 sysctl_tcp_min_tso_segs;
	u8 sysctl_tcp_tso_rtt_log;
	u8 sysctl_tcp_autocorking;
	u8 sysctl_tcp_reflect_tos;
	int sysctl_tcp_invalid_ratelimit;
	int sysctl_tcp_pacing_ss_ratio;
	int sysctl_tcp_pacing_ca_ratio;
	int sysctl_tcp_wmem[3];
	int sysctl_tcp_rmem[3];
	long unsigned int sysctl_tcp_comp_sack_delay_ns;
	long unsigned int sysctl_tcp_comp_sack_slack_ns;
	int sysctl_max_syn_backlog;
	int sysctl_tcp_fastopen;
	const struct tcp_congestion_ops *tcp_congestion_control;
	struct tcp_fastopen_context *tcp_fastopen_ctx;
	unsigned int sysctl_tcp_fastopen_blackhole_timeout;
	atomic_t tfo_active_disable_times;
	long unsigned int tfo_active_disable_stamp;
	int sysctl_udp_wmem_min;
	int sysctl_udp_rmem_min;
	u8 sysctl_fib_notify_on_flag_change;
	u8 sysctl_igmp_llm_reports;
	int sysctl_igmp_max_memberships;
	int sysctl_igmp_max_msf;
	int sysctl_igmp_qrv;
	struct ping_group_range ping_group_range;
	atomic_t dev_addr_genid;
	long unsigned int *sysctl_local_reserved_ports;
	int sysctl_ip_prot_sock;
	struct fib_notifier_ops *notifier_ops;
	unsigned int fib_seq;
	struct fib_notifier_ops *ipmr_notifier_ops;
	unsigned int ipmr_seq;
	atomic_t rt_genid;
	siphash_key_t ip_id_key;
};

struct bpf_prog;

struct netns_bpf {
	struct bpf_prog_array *run_array[2];
	struct bpf_prog *progs[2];
	struct list_head links[2];
};

struct xfrm_policy_hash {
	struct hlist_head *table;
	unsigned int hmask;
	u8 dbits4;
	u8 sbits4;
	u8 dbits6;
	u8 sbits6;
};

struct xfrm_policy_hthresh {
	struct work_struct work;
	seqlock_t lock;
	u8 lbits4;
	u8 rbits4;
	u8 lbits6;
	u8 rbits6;
};

struct dst_entry;

struct net_device;

struct sk_buff;

struct neighbour;

struct dst_ops {
	short unsigned int family;
	unsigned int gc_thresh;
	int (*gc)(struct dst_ops *);
	struct dst_entry * (*check)(struct dst_entry *, __u32);
	unsigned int (*default_advmss)(const struct dst_entry *);
	unsigned int (*mtu)(const struct dst_entry *);
	u32 * (*cow_metrics)(struct dst_entry *, long unsigned int);
	void (*destroy)(struct dst_entry *);
	void (*ifdown)(struct dst_entry *, struct net_device *, int);
	struct dst_entry * (*negative_advice)(struct dst_entry *);
	void (*link_failure)(struct sk_buff *);
	void (*update_pmtu)(struct dst_entry *, struct sock *, struct sk_buff *, u32, bool);
	void (*redirect)(struct dst_entry *, struct sock *, struct sk_buff *);
	int (*local_out)(struct net *, struct sock *, struct sk_buff *);
	struct neighbour * (*neigh_lookup)(const struct dst_entry *, struct sk_buff *, const void *);
	void (*confirm_neigh)(const struct dst_entry *, const void *);
	struct kmem_cache *kmem_cachep;
	struct percpu_counter pcpuc_entries;
};

struct netns_xfrm {
	struct list_head state_all;
	struct hlist_head *state_bydst;
	struct hlist_head *state_bysrc;
	struct hlist_head *state_byspi;
	struct hlist_head *state_byseq;
	unsigned int state_hmask;
	unsigned int state_num;
	struct work_struct state_hash_work;
	struct list_head policy_all;
	struct hlist_head *policy_byidx;
	unsigned int policy_idx_hmask;
	struct hlist_head policy_inexact[3];
	struct xfrm_policy_hash policy_bydst[3];
	unsigned int policy_count[6];
	struct work_struct policy_hash_work;
	struct xfrm_policy_hthresh policy_hthresh;
	struct list_head inexact_bins;
	struct sock *nlsk;
	struct sock *nlsk_stash;
	u32 sysctl_aevent_etime;
	u32 sysctl_aevent_rseqth;
	int sysctl_larval_drop;
	u32 sysctl_acq_expires;
	u8 policy_default[3];
	struct ctl_table_header *sysctl_hdr;
	struct dst_ops xfrm4_dst_ops;
	spinlock_t xfrm_state_lock;
	seqcount_spinlock_t xfrm_state_hash_generation;
	seqcount_spinlock_t xfrm_policy_hash_generation;
	spinlock_t xfrm_policy_lock;
	struct mutex xfrm_cfg_mutex;
};

struct proc_dir_entry;

struct uevent_sock;

struct net_generic;

struct net {
	refcount_t passive;
	spinlock_t rules_mod_lock;
	atomic_t dev_unreg_count;
	unsigned int dev_base_seq;
	int ifindex;
	spinlock_t nsid_lock;
	atomic_t fnhe_genid;
	struct list_head list;
	struct list_head exit_list;
	struct llist_node cleanup_list;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct idr netns_ids;
	struct ns_common ns;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head dev_base_head;
	struct proc_dir_entry *proc_net;
	struct proc_dir_entry *proc_net_stat;
	struct ctl_table_set sysctls;
	struct sock *rtnl;
	struct sock *genl_sock;
	struct uevent_sock *uevent_sock;
	struct hlist_head *dev_name_head;
	struct hlist_head *dev_index_head;
	struct raw_notifier_head netdev_chain;
	u32 hash_mix;
	struct net_device *loopback_dev;
	struct list_head rules_ops;
	struct netns_core core;
	struct netns_mib mib;
	struct netns_packet packet;
	struct netns_unix unx;
	struct netns_nexthop nexthop;
	struct netns_ipv4 ipv4;
	struct net_generic *gen;
	struct netns_bpf bpf;
	struct netns_xfrm xfrm;
	u64 net_cookie;
	struct sock *diag_nlsk;
};

struct cgroup_namespace {
	struct ns_common ns;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct css_set *root_cset;
};

struct nsset {
	unsigned int flags;
	struct nsproxy *nsproxy;
	struct fs_struct *fs;
	const struct cred *cred;
};

struct proc_ns_operations {
	const char *name;
	const char *real_ns_name;
	int type;
	struct ns_common * (*get)(struct task_struct *);
	void (*put)(struct ns_common *);
	int (*install)(struct nsset *, struct ns_common *);
	struct user_namespace * (*owner)(struct ns_common *);
	struct ns_common * (*get_parent)(struct ns_common *);
};

struct irq_work {
	struct __call_single_node node;
	void (*func)(struct irq_work *);
	struct rcuwait irqwait;
};

struct perf_regs {
	__u64 abi;
	struct pt_regs *regs;
};

struct u64_stats_sync {};

struct perf_callchain_entry {
	__u64 nr;
	__u64 ip[0];
};

typedef long unsigned int (*perf_copy_f)(void *, const void *, long unsigned int, long unsigned int);

struct perf_raw_frag {
	union {
		struct perf_raw_frag *next;
		long unsigned int pad;
	};
	perf_copy_f copy;
	void *data;
	u32 size;
};

struct perf_raw_record {
	struct perf_raw_frag frag;
	u32 size;
};

struct perf_branch_stack {
	__u64 nr;
	__u64 hw_idx;
	struct perf_branch_entry entries[0];
};

struct hw_perf_event_extra {
	u64 config;
	unsigned int reg;
	int alloc;
	int idx;
};

struct hw_perf_event {
	union {
		struct {
			u64 config;
			u64 last_tag;
			long unsigned int config_base;
			long unsigned int event_base;
			int event_base_rdpmc;
			int idx;
			int last_cpu;
			int flags;
			struct hw_perf_event_extra extra_reg;
			struct hw_perf_event_extra branch_reg;
		};
		struct {
			struct hrtimer hrtimer;
		};
		struct {
			struct list_head tp_list;
		};
		struct {
			u64 pwr_acc;
			u64 ptsc;
		};
		struct {
			u8 iommu_bank;
			u8 iommu_cntr;
			u16 padding;
			u64 conf;
			u64 conf1;
		};
	};
	struct task_struct *target;
	void *addr_filters;
	long unsigned int addr_filters_gen;
	int state;
	local64_t prev_count;
	u64 sample_period;
	union {
		struct {
			u64 last_period;
			local64_t period_left;
		};
		struct {
			u64 saved_metric;
			u64 saved_slots;
		};
	};
	u64 interrupts_seq;
	u64 interrupts;
	u64 freq_time_stamp;
	u64 freq_count_stamp;
};

struct perf_cpu_context;

struct perf_output_handle;

struct pmu {
	struct list_head entry;
	struct module *module;
	struct device *dev;
	const struct attribute_group **attr_groups;
	const struct attribute_group **attr_update;
	const char *name;
	int type;
	int capabilities;
	int *pmu_disable_count;
	struct perf_cpu_context *pmu_cpu_context;
	atomic_t exclusive_cnt;
	int task_ctx_nr;
	int hrtimer_interval_ms;
	unsigned int nr_addr_filters;
	void (*pmu_enable)(struct pmu *);
	void (*pmu_disable)(struct pmu *);
	int (*event_init)(struct perf_event *);
	void (*event_mapped)(struct perf_event *, struct mm_struct *);
	void (*event_unmapped)(struct perf_event *, struct mm_struct *);
	int (*add)(struct perf_event *, int);
	void (*del)(struct perf_event *, int);
	void (*start)(struct perf_event *, int);
	void (*stop)(struct perf_event *, int);
	void (*read)(struct perf_event *);
	void (*start_txn)(struct pmu *, unsigned int);
	int (*commit_txn)(struct pmu *);
	void (*cancel_txn)(struct pmu *);
	int (*event_idx)(struct perf_event *);
	void (*sched_task)(struct perf_event_context *, bool);
	struct kmem_cache *task_ctx_cache;
	void (*swap_task_ctx)(struct perf_event_context *, struct perf_event_context *);
	void * (*setup_aux)(struct perf_event *, void **, int, bool);
	void (*free_aux)(void *);
	long int (*snapshot_aux)(struct perf_event *, struct perf_output_handle *, long unsigned int);
	int (*addr_filters_validate)(struct list_head *);
	void (*addr_filters_sync)(struct perf_event *);
	int (*aux_output_match)(struct perf_event *);
	int (*filter_match)(struct perf_event *);
	int (*check_period)(struct perf_event *, u64);
};

struct perf_cpu_context {
	struct perf_event_context ctx;
	struct perf_event_context *task_ctx;
	int active_oncpu;
	int exclusive;
	raw_spinlock_t hrtimer_lock;
	struct hrtimer hrtimer;
	ktime_t hrtimer_interval;
	unsigned int hrtimer_active;
	struct list_head sched_cb_entry;
	int sched_cb_usage;
	int online;
	int heap_size;
	struct perf_event **heap;
	struct perf_event *heap_default[2];
};

enum perf_event_state {
	PERF_EVENT_STATE_DEAD = 4294967292,
	PERF_EVENT_STATE_EXIT = 4294967293,
	PERF_EVENT_STATE_ERROR = 4294967294,
	PERF_EVENT_STATE_OFF = 4294967295,
	PERF_EVENT_STATE_INACTIVE = 0,
	PERF_EVENT_STATE_ACTIVE = 1,
};

struct perf_addr_filters_head {
	struct list_head list;
	raw_spinlock_t lock;
	unsigned int nr_file_filters;
};

struct perf_sample_data;

typedef void (*perf_overflow_handler_t)(struct perf_event *, struct perf_sample_data *, struct pt_regs *);

struct perf_buffer;

struct perf_addr_filter_range;

struct perf_event {
	struct list_head event_entry;
	struct list_head sibling_list;
	struct list_head active_list;
	struct rb_node group_node;
	u64 group_index;
	struct list_head migrate_entry;
	struct hlist_node hlist_entry;
	struct list_head active_entry;
	int nr_siblings;
	int event_caps;
	int group_caps;
	struct perf_event *group_leader;
	struct pmu *pmu;
	void *pmu_private;
	enum perf_event_state state;
	unsigned int attach_state;
	int: 32;
	local64_t count;
	atomic64_t child_count;
	u64 total_time_enabled;
	u64 total_time_running;
	u64 tstamp;
	struct perf_event_attr attr;
	u16 header_size;
	u16 id_header_size;
	u16 read_size;
	struct hw_perf_event hw;
	struct perf_event_context *ctx;
	atomic_long_t refcount;
	atomic64_t child_total_time_enabled;
	atomic64_t child_total_time_running;
	struct mutex child_mutex;
	struct list_head child_list;
	struct perf_event *parent;
	int oncpu;
	int cpu;
	struct list_head owner_entry;
	struct task_struct *owner;
	struct mutex mmap_mutex;
	atomic_t mmap_count;
	struct perf_buffer *rb;
	struct list_head rb_entry;
	long unsigned int rcu_batches;
	int rcu_pending;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
	int pending_wakeup;
	int pending_kill;
	int pending_disable;
	long unsigned int pending_addr;
	struct irq_work pending;
	atomic_t event_limit;
	struct perf_addr_filters_head addr_filters;
	struct perf_addr_filter_range *addr_filter_ranges;
	long unsigned int addr_filters_gen;
	struct perf_event *aux_event;
	void (*destroy)(struct perf_event *);
	struct callback_head callback_head;
	struct pid_namespace *ns;
	u64 id;
	u64 (*clock)();
	perf_overflow_handler_t overflow_handler;
	void *overflow_handler_context;
	perf_overflow_handler_t orig_overflow_handler;
	struct bpf_prog *prog;
	u64 bpf_cookie;
	struct trace_event_call *tp_event;
	struct event_filter *filter;
	struct list_head sb_list;
	int: 32;
};

struct perf_output_handle {
	struct perf_event *event;
	struct perf_buffer *rb;
	long unsigned int wakeup;
	long unsigned int size;
	u64 aux_flags;
	union {
		void *addr;
		long unsigned int head;
	};
	int page;
};

struct perf_addr_filter_range {
	long unsigned int start;
	long unsigned int size;
};

struct perf_sample_data {
	u64 addr;
	struct perf_raw_record *raw;
	struct perf_branch_stack *br_stack;
	u64 period;
	union perf_sample_weight weight;
	u64 txn;
	union perf_mem_data_src data_src;
	u64 type;
	u64 ip;
	struct {
		u32 pid;
		u32 tid;
	} tid_entry;
	u64 time;
	u64 id;
	u64 stream_id;
	struct {
		u32 cpu;
		u32 reserved;
	} cpu_entry;
	struct perf_callchain_entry *callchain;
	u64 aux_size;
	struct perf_regs regs_user;
	struct perf_regs regs_intr;
	u64 stack_user_size;
	u64 phys_addr;
	u64 cgroup;
	u64 data_page_size;
	u64 code_page_size;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_array;

struct tracer;

struct array_buffer;

struct ring_buffer_iter;

struct trace_iterator {
	struct trace_array *tr;
	struct tracer *trace;
	struct array_buffer *array_buffer;
	void *private;
	int cpu_file;
	struct mutex mutex;
	struct ring_buffer_iter **buffer_iter;
	long unsigned int iter_flags;
	void *temp;
	unsigned int temp_size;
	char *fmt;
	unsigned int fmt_size;
	struct trace_seq tmp_seq;
	cpumask_var_t started;
	bool snapshot;
	struct trace_seq seq;
	struct trace_entry *ent;
	long unsigned int lost_events;
	int leftover;
	int ent_size;
	int cpu;
	u64 ts;
	loff_t pos;
	long int idx;
};

enum print_line_t {
	TRACE_TYPE_PARTIAL_LINE = 0,
	TRACE_TYPE_HANDLED = 1,
	TRACE_TYPE_UNHANDLED = 2,
	TRACE_TYPE_NO_CONSUME = 3,
};

typedef enum print_line_t (*trace_print_func)(struct trace_iterator *, int, struct trace_event *);

struct trace_event_functions {
	trace_print_func trace;
	trace_print_func raw;
	trace_print_func hex;
	trace_print_func binary;
};

enum trace_reg {
	TRACE_REG_REGISTER = 0,
	TRACE_REG_UNREGISTER = 1,
	TRACE_REG_PERF_REGISTER = 2,
	TRACE_REG_PERF_UNREGISTER = 3,
	TRACE_REG_PERF_OPEN = 4,
	TRACE_REG_PERF_CLOSE = 5,
	TRACE_REG_PERF_ADD = 6,
	TRACE_REG_PERF_DEL = 7,
};

struct trace_event_fields {
	const char *type;
	union {
		struct {
			const char *name;
			const int size;
			const int align;
			const int is_signed;
			const int filter_type;
		};
		int (*define_fields)(struct trace_event_call *);
	};
};

struct trace_event_class {
	const char *system;
	void *probe;
	void *perf_probe;
	int (*reg)(struct trace_event_call *, enum trace_reg, void *);
	struct trace_event_fields *fields_array;
	struct list_head * (*get_fields)(struct trace_event_call *);
	struct list_head fields;
	int (*raw_init)(struct trace_event_call *);
};

struct trace_buffer;

struct trace_event_file;

struct trace_event_buffer {
	struct trace_buffer *buffer;
	struct ring_buffer_event *event;
	struct trace_event_file *trace_file;
	void *entry;
	unsigned int trace_ctx;
	struct pt_regs *regs;
};

struct trace_subsystem_dir;

struct trace_event_file {
	struct list_head list;
	struct trace_event_call *event_call;
	struct event_filter *filter;
	struct dentry *dir;
	struct trace_array *tr;
	struct trace_subsystem_dir *system;
	struct list_head triggers;
	long unsigned int flags;
	atomic_t sm_ref;
	atomic_t tm_ref;
};

enum {
	TRACE_EVENT_FL_FILTERED_BIT = 0,
	TRACE_EVENT_FL_CAP_ANY_BIT = 1,
	TRACE_EVENT_FL_NO_SET_FILTER_BIT = 2,
	TRACE_EVENT_FL_IGNORE_ENABLE_BIT = 3,
	TRACE_EVENT_FL_TRACEPOINT_BIT = 4,
	TRACE_EVENT_FL_DYNAMIC_BIT = 5,
	TRACE_EVENT_FL_KPROBE_BIT = 6,
	TRACE_EVENT_FL_UPROBE_BIT = 7,
	TRACE_EVENT_FL_EPROBE_BIT = 8,
	TRACE_EVENT_FL_CUSTOM_BIT = 9,
};

enum {
	TRACE_EVENT_FL_FILTERED = 1,
	TRACE_EVENT_FL_CAP_ANY = 2,
	TRACE_EVENT_FL_NO_SET_FILTER = 4,
	TRACE_EVENT_FL_IGNORE_ENABLE = 8,
	TRACE_EVENT_FL_TRACEPOINT = 16,
	TRACE_EVENT_FL_DYNAMIC = 32,
	TRACE_EVENT_FL_KPROBE = 64,
	TRACE_EVENT_FL_UPROBE = 128,
	TRACE_EVENT_FL_EPROBE = 256,
	TRACE_EVENT_FL_CUSTOM = 512,
};

enum {
	EVENT_FILE_FL_ENABLED_BIT = 0,
	EVENT_FILE_FL_RECORDED_CMD_BIT = 1,
	EVENT_FILE_FL_RECORDED_TGID_BIT = 2,
	EVENT_FILE_FL_FILTERED_BIT = 3,
	EVENT_FILE_FL_NO_SET_FILTER_BIT = 4,
	EVENT_FILE_FL_SOFT_MODE_BIT = 5,
	EVENT_FILE_FL_SOFT_DISABLED_BIT = 6,
	EVENT_FILE_FL_TRIGGER_MODE_BIT = 7,
	EVENT_FILE_FL_TRIGGER_COND_BIT = 8,
	EVENT_FILE_FL_PID_FILTER_BIT = 9,
	EVENT_FILE_FL_WAS_ENABLED_BIT = 10,
};

enum {
	EVENT_FILE_FL_ENABLED = 1,
	EVENT_FILE_FL_RECORDED_CMD = 2,
	EVENT_FILE_FL_RECORDED_TGID = 4,
	EVENT_FILE_FL_FILTERED = 8,
	EVENT_FILE_FL_NO_SET_FILTER = 16,
	EVENT_FILE_FL_SOFT_MODE = 32,
	EVENT_FILE_FL_SOFT_DISABLED = 64,
	EVENT_FILE_FL_TRIGGER_MODE = 128,
	EVENT_FILE_FL_TRIGGER_COND = 256,
	EVENT_FILE_FL_PID_FILTER = 512,
	EVENT_FILE_FL_WAS_ENABLED = 1024,
};

enum {
	FILTER_OTHER = 0,
	FILTER_STATIC_STRING = 1,
	FILTER_DYN_STRING = 2,
	FILTER_RDYN_STRING = 3,
	FILTER_PTR_STRING = 4,
	FILTER_TRACE_FN = 5,
	FILTER_COMM = 6,
	FILTER_CPU = 7,
};

struct property {
	char *name;
	int length;
	void *value;
	struct property *next;
	struct bin_attribute attr;
};

struct xbc_node {
	uint16_t next;
	uint16_t child;
	uint16_t parent;
	uint16_t data;
};

enum wb_stat_item {
	WB_RECLAIMABLE = 0,
	WB_WRITEBACK = 1,
	WB_DIRTIED = 2,
	WB_WRITTEN = 3,
	NR_WB_STAT_ITEMS = 4,
};

struct block_device_operations;

struct timer_rand_state;

struct disk_events;

struct badblocks;

struct gendisk {
	int major;
	int first_minor;
	int minors;
	char disk_name[32];
	short unsigned int events;
	short unsigned int event_flags;
	struct xarray part_tbl;
	struct block_device *part0;
	const struct block_device_operations *fops;
	struct request_queue *queue;
	void *private_data;
	int flags;
	long unsigned int state;
	struct mutex open_mutex;
	unsigned int open_partitions;
	struct backing_dev_info *bdi;
	struct kobject *slave_dir;
	struct timer_rand_state *random;
	atomic_t sync_io;
	struct disk_events *ev;
	int node_id;
	struct badblocks *bb;
	struct lockdep_map lockdep_map;
	u64 diskseq;
};

struct partition_meta_info {
	char uuid[37];
	u8 volname[64];
};

struct blk_rq_stat {
	u64 mean;
	u64 min;
	u64 max;
	u32 nr_samples;
	u64 batch;
};

struct percpu_cluster {
	struct swap_cluster_info index;
	unsigned int next;
};

enum fs_value_type {
	fs_value_is_undefined = 0,
	fs_value_is_flag = 1,
	fs_value_is_string = 2,
	fs_value_is_blob = 3,
	fs_value_is_filename = 4,
	fs_value_is_file = 5,
};

struct fs_parameter {
	const char *key;
	enum fs_value_type type: 8;
	union {
		char *string;
		void *blob;
		struct filename *name;
		struct file *file;
	};
	size_t size;
	int dirfd;
};

struct fc_log {
	refcount_t usage;
	u8 head;
	u8 tail;
	u8 need_free;
	struct module *owner;
	char *buffer[8];
};

struct fs_context_operations {
	void (*free)(struct fs_context *);
	int (*dup)(struct fs_context *, struct fs_context *);
	int (*parse_param)(struct fs_context *, struct fs_parameter *);
	int (*parse_monolithic)(struct fs_context *, void *);
	int (*get_tree)(struct fs_context *);
	int (*reconfigure)(struct fs_context *);
};

struct fs_parse_result {
	bool negated;
	union {
		bool boolean;
		int int_32;
		unsigned int uint_32;
		u64 uint_64;
	};
};

struct iovec {
	void *iov_base;
	__kernel_size_t iov_len;
};

struct kvec {
	void *iov_base;
	size_t iov_len;
};

struct blk_zone {
	__u64 start;
	__u64 len;
	__u64 wp;
	__u8 type;
	__u8 cond;
	__u8 non_seq;
	__u8 reset;
	__u8 resv[4];
	__u64 capacity;
	__u8 reserved[24];
};

typedef int (*report_zones_cb)(struct blk_zone *, unsigned int, void *);

enum blk_unique_id {
	BLK_UID_T10 = 1,
	BLK_UID_EUI64 = 2,
	BLK_UID_NAA = 3,
};

struct hd_geometry;

struct pr_ops;

struct block_device_operations {
	void (*submit_bio)(struct bio *);
	int (*poll_bio)(struct bio *, struct io_comp_batch *, unsigned int);
	int (*open)(struct block_device *, fmode_t);
	void (*release)(struct gendisk *, fmode_t);
	int (*rw_page)(struct block_device *, sector_t, struct page *, unsigned int);
	int (*ioctl)(struct block_device *, fmode_t, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct block_device *, fmode_t, unsigned int, long unsigned int);
	unsigned int (*check_events)(struct gendisk *, unsigned int);
	void (*unlock_native_capacity)(struct gendisk *);
	int (*getgeo)(struct block_device *, struct hd_geometry *);
	int (*set_read_only)(struct block_device *, bool);
	void (*free_disk)(struct gendisk *);
	void (*swap_slot_free_notify)(struct block_device *, long unsigned int);
	int (*report_zones)(struct gendisk *, sector_t, unsigned int, report_zones_cb, void *);
	char * (*devnode)(struct gendisk *, umode_t *);
	int (*get_unique_id)(struct gendisk *, u8 *, enum blk_unique_id);
	struct module *owner;
	const struct pr_ops *pr_ops;
	int (*alternative_gpt_sector)(struct gendisk *, sector_t *);
};

struct blk_independent_access_range {
	struct kobject kobj;
	struct request_queue *queue;
	sector_t sector;
	sector_t nr_sectors;
};

struct blk_independent_access_ranges {
	struct kobject kobj;
	bool sysfs_registered;
	unsigned int nr_ia_ranges;
	struct blk_independent_access_range ia_range[0];
};

enum blk_eh_timer_return {
	BLK_EH_DONE = 0,
	BLK_EH_RESET_TIMER = 1,
};

struct blk_mq_hw_ctx;

struct blk_mq_queue_data;

struct blk_mq_ops {
	blk_status_t (*queue_rq)(struct blk_mq_hw_ctx *, const struct blk_mq_queue_data *);
	void (*commit_rqs)(struct blk_mq_hw_ctx *);
	void (*queue_rqs)(struct request **);
	int (*get_budget)(struct request_queue *);
	void (*put_budget)(struct request_queue *, int);
	void (*set_rq_budget_token)(struct request *, int);
	int (*get_rq_budget_token)(struct request *);
	enum blk_eh_timer_return (*timeout)(struct request *, bool);
	int (*poll)(struct blk_mq_hw_ctx *, struct io_comp_batch *);
	void (*complete)(struct request *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, void *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	int (*init_request)(struct blk_mq_tag_set *, struct request *, unsigned int, unsigned int);
	void (*exit_request)(struct blk_mq_tag_set *, struct request *, unsigned int);
	void (*cleanup_rq)(struct request *);
	bool (*busy)(struct request_queue *);
	int (*map_queues)(struct blk_mq_tag_set *);
	void (*show_rq)(struct seq_file *, struct request *);
};

enum pr_type {
	PR_WRITE_EXCLUSIVE = 1,
	PR_EXCLUSIVE_ACCESS = 2,
	PR_WRITE_EXCLUSIVE_REG_ONLY = 3,
	PR_EXCLUSIVE_ACCESS_REG_ONLY = 4,
	PR_WRITE_EXCLUSIVE_ALL_REGS = 5,
	PR_EXCLUSIVE_ACCESS_ALL_REGS = 6,
};

struct pr_ops {
	int (*pr_register)(struct block_device *, u64, u64, u32);
	int (*pr_reserve)(struct block_device *, u64, enum pr_type, u32);
	int (*pr_release)(struct block_device *, u64, enum pr_type);
	int (*pr_preempt)(struct block_device *, u64, u64, enum pr_type, bool);
	int (*pr_clear)(struct block_device *, u64);
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__be16 u6_addr16[8];
		__be32 u6_addr32[4];
	} in6_u;
};

enum flow_dissector_key_id {
	FLOW_DISSECTOR_KEY_CONTROL = 0,
	FLOW_DISSECTOR_KEY_BASIC = 1,
	FLOW_DISSECTOR_KEY_IPV4_ADDRS = 2,
	FLOW_DISSECTOR_KEY_IPV6_ADDRS = 3,
	FLOW_DISSECTOR_KEY_PORTS = 4,
	FLOW_DISSECTOR_KEY_PORTS_RANGE = 5,
	FLOW_DISSECTOR_KEY_ICMP = 6,
	FLOW_DISSECTOR_KEY_ETH_ADDRS = 7,
	FLOW_DISSECTOR_KEY_TIPC = 8,
	FLOW_DISSECTOR_KEY_ARP = 9,
	FLOW_DISSECTOR_KEY_VLAN = 10,
	FLOW_DISSECTOR_KEY_FLOW_LABEL = 11,
	FLOW_DISSECTOR_KEY_GRE_KEYID = 12,
	FLOW_DISSECTOR_KEY_MPLS_ENTROPY = 13,
	FLOW_DISSECTOR_KEY_ENC_KEYID = 14,
	FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS = 15,
	FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS = 16,
	FLOW_DISSECTOR_KEY_ENC_CONTROL = 17,
	FLOW_DISSECTOR_KEY_ENC_PORTS = 18,
	FLOW_DISSECTOR_KEY_MPLS = 19,
	FLOW_DISSECTOR_KEY_TCP = 20,
	FLOW_DISSECTOR_KEY_IP = 21,
	FLOW_DISSECTOR_KEY_CVLAN = 22,
	FLOW_DISSECTOR_KEY_ENC_IP = 23,
	FLOW_DISSECTOR_KEY_ENC_OPTS = 24,
	FLOW_DISSECTOR_KEY_META = 25,
	FLOW_DISSECTOR_KEY_CT = 26,
	FLOW_DISSECTOR_KEY_HASH = 27,
	FLOW_DISSECTOR_KEY_MAX = 28,
};

typedef unsigned char *sk_buff_data_t;

struct skb_ext;

struct sk_buff {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
			union {
				struct net_device *dev;
				long unsigned int dev_scratch;
			};
		};
		struct rb_node rbnode;
		struct list_head list;
		struct llist_node ll_node;
	};
	union {
		struct sock *sk;
		int ip_defrag_offset;
	};
	union {
		ktime_t tstamp;
		u64 skb_mstamp_ns;
	};
	char cb[48];
	union {
		struct {
			long unsigned int _skb_refdst;
			void (*destructor)(struct sk_buff *);
		};
		struct list_head tcp_tsorted_anchor;
		long unsigned int _sk_redir;
	};
	unsigned int len;
	unsigned int data_len;
	__u16 mac_len;
	__u16 hdr_len;
	__u16 queue_mapping;
	__u8 __cloned_offset[0];
	__u8 cloned: 1;
	__u8 nohdr: 1;
	__u8 fclone: 2;
	__u8 peeked: 1;
	__u8 head_frag: 1;
	__u8 pfmemalloc: 1;
	__u8 pp_recycle: 1;
	__u8 active_extensions;
	union {
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		};
		struct {
			__u8 __pkt_type_offset[0];
			__u8 pkt_type: 3;
			__u8 ignore_df: 1;
			__u8 nf_trace: 1;
			__u8 ip_summed: 2;
			__u8 ooo_okay: 1;
			__u8 l4_hash: 1;
			__u8 sw_hash: 1;
			__u8 wifi_acked_valid: 1;
			__u8 wifi_acked: 1;
			__u8 no_fcs: 1;
			__u8 encapsulation: 1;
			__u8 encap_hdr_csum: 1;
			__u8 csum_valid: 1;
			__u8 __pkt_vlan_present_offset[0];
			__u8 vlan_present: 1;
			__u8 csum_complete_sw: 1;
			__u8 csum_level: 2;
			__u8 dst_pending_confirm: 1;
			__u8 mono_delivery_time: 1;
			__u8 ipvs_property: 1;
			__u8 inner_protocol_type: 1;
			__u8 remcsum_offload: 1;
			__u8 redirected: 1;
			__u8 slow_gro: 1;
			__u8 csum_not_inet: 1;
			union {
				__wsum csum;
				struct {
					__u16 csum_start;
					__u16 csum_offset;
				};
			};
			__u32 priority;
			int skb_iif;
			__u32 hash;
			__be16 vlan_proto;
			__u16 vlan_tci;
			union {
				unsigned int napi_id;
				unsigned int sender_cpu;
			};
			union {
				__u32 mark;
				__u32 reserved_tailroom;
			};
			union {
				__be16 inner_protocol;
				__u8 inner_ipproto;
			};
			__u16 inner_transport_header;
			__u16 inner_network_header;
			__u16 inner_mac_header;
			__be16 protocol;
			__u16 transport_header;
			__u16 network_header;
			__u16 mac_header;
		} headers;
	};
	sk_buff_data_t tail;
	sk_buff_data_t end;
	unsigned char *head;
	unsigned char *data;
	unsigned int truesize;
	refcount_t users;
	struct skb_ext *extensions;
	int: 32;
};

enum {
	IPSTATS_MIB_NUM = 0,
	IPSTATS_MIB_INPKTS = 1,
	IPSTATS_MIB_INOCTETS = 2,
	IPSTATS_MIB_INDELIVERS = 3,
	IPSTATS_MIB_OUTFORWDATAGRAMS = 4,
	IPSTATS_MIB_OUTPKTS = 5,
	IPSTATS_MIB_OUTOCTETS = 6,
	IPSTATS_MIB_INHDRERRORS = 7,
	IPSTATS_MIB_INTOOBIGERRORS = 8,
	IPSTATS_MIB_INNOROUTES = 9,
	IPSTATS_MIB_INADDRERRORS = 10,
	IPSTATS_MIB_INUNKNOWNPROTOS = 11,
	IPSTATS_MIB_INTRUNCATEDPKTS = 12,
	IPSTATS_MIB_INDISCARDS = 13,
	IPSTATS_MIB_OUTDISCARDS = 14,
	IPSTATS_MIB_OUTNOROUTES = 15,
	IPSTATS_MIB_REASMTIMEOUT = 16,
	IPSTATS_MIB_REASMREQDS = 17,
	IPSTATS_MIB_REASMOKS = 18,
	IPSTATS_MIB_REASMFAILS = 19,
	IPSTATS_MIB_FRAGOKS = 20,
	IPSTATS_MIB_FRAGFAILS = 21,
	IPSTATS_MIB_FRAGCREATES = 22,
	IPSTATS_MIB_INMCASTPKTS = 23,
	IPSTATS_MIB_OUTMCASTPKTS = 24,
	IPSTATS_MIB_INBCASTPKTS = 25,
	IPSTATS_MIB_OUTBCASTPKTS = 26,
	IPSTATS_MIB_INMCASTOCTETS = 27,
	IPSTATS_MIB_OUTMCASTOCTETS = 28,
	IPSTATS_MIB_INBCASTOCTETS = 29,
	IPSTATS_MIB_OUTBCASTOCTETS = 30,
	IPSTATS_MIB_CSUMERRORS = 31,
	IPSTATS_MIB_NOECTPKTS = 32,
	IPSTATS_MIB_ECT1PKTS = 33,
	IPSTATS_MIB_ECT0PKTS = 34,
	IPSTATS_MIB_CEPKTS = 35,
	IPSTATS_MIB_REASM_OVERLAPS = 36,
	__IPSTATS_MIB_MAX = 37,
};

enum {
	ICMP_MIB_NUM = 0,
	ICMP_MIB_INMSGS = 1,
	ICMP_MIB_INERRORS = 2,
	ICMP_MIB_INDESTUNREACHS = 3,
	ICMP_MIB_INTIMEEXCDS = 4,
	ICMP_MIB_INPARMPROBS = 5,
	ICMP_MIB_INSRCQUENCHS = 6,
	ICMP_MIB_INREDIRECTS = 7,
	ICMP_MIB_INECHOS = 8,
	ICMP_MIB_INECHOREPS = 9,
	ICMP_MIB_INTIMESTAMPS = 10,
	ICMP_MIB_INTIMESTAMPREPS = 11,
	ICMP_MIB_INADDRMASKS = 12,
	ICMP_MIB_INADDRMASKREPS = 13,
	ICMP_MIB_OUTMSGS = 14,
	ICMP_MIB_OUTERRORS = 15,
	ICMP_MIB_OUTDESTUNREACHS = 16,
	ICMP_MIB_OUTTIMEEXCDS = 17,
	ICMP_MIB_OUTPARMPROBS = 18,
	ICMP_MIB_OUTSRCQUENCHS = 19,
	ICMP_MIB_OUTREDIRECTS = 20,
	ICMP_MIB_OUTECHOS = 21,
	ICMP_MIB_OUTECHOREPS = 22,
	ICMP_MIB_OUTTIMESTAMPS = 23,
	ICMP_MIB_OUTTIMESTAMPREPS = 24,
	ICMP_MIB_OUTADDRMASKS = 25,
	ICMP_MIB_OUTADDRMASKREPS = 26,
	ICMP_MIB_CSUMERRORS = 27,
	__ICMP_MIB_MAX = 28,
};

enum {
	ICMP6_MIB_NUM = 0,
	ICMP6_MIB_INMSGS = 1,
	ICMP6_MIB_INERRORS = 2,
	ICMP6_MIB_OUTMSGS = 3,
	ICMP6_MIB_OUTERRORS = 4,
	ICMP6_MIB_CSUMERRORS = 5,
	__ICMP6_MIB_MAX = 6,
};

enum {
	TCP_MIB_NUM = 0,
	TCP_MIB_RTOALGORITHM = 1,
	TCP_MIB_RTOMIN = 2,
	TCP_MIB_RTOMAX = 3,
	TCP_MIB_MAXCONN = 4,
	TCP_MIB_ACTIVEOPENS = 5,
	TCP_MIB_PASSIVEOPENS = 6,
	TCP_MIB_ATTEMPTFAILS = 7,
	TCP_MIB_ESTABRESETS = 8,
	TCP_MIB_CURRESTAB = 9,
	TCP_MIB_INSEGS = 10,
	TCP_MIB_OUTSEGS = 11,
	TCP_MIB_RETRANSSEGS = 12,
	TCP_MIB_INERRS = 13,
	TCP_MIB_OUTRSTS = 14,
	TCP_MIB_CSUMERRORS = 15,
	__TCP_MIB_MAX = 16,
};

enum {
	UDP_MIB_NUM = 0,
	UDP_MIB_INDATAGRAMS = 1,
	UDP_MIB_NOPORTS = 2,
	UDP_MIB_INERRORS = 3,
	UDP_MIB_OUTDATAGRAMS = 4,
	UDP_MIB_RCVBUFERRORS = 5,
	UDP_MIB_SNDBUFERRORS = 6,
	UDP_MIB_CSUMERRORS = 7,
	UDP_MIB_IGNOREDMULTI = 8,
	UDP_MIB_MEMERRORS = 9,
	__UDP_MIB_MAX = 10,
};

enum {
	LINUX_MIB_NUM = 0,
	LINUX_MIB_SYNCOOKIESSENT = 1,
	LINUX_MIB_SYNCOOKIESRECV = 2,
	LINUX_MIB_SYNCOOKIESFAILED = 3,
	LINUX_MIB_EMBRYONICRSTS = 4,
	LINUX_MIB_PRUNECALLED = 5,
	LINUX_MIB_RCVPRUNED = 6,
	LINUX_MIB_OFOPRUNED = 7,
	LINUX_MIB_OUTOFWINDOWICMPS = 8,
	LINUX_MIB_LOCKDROPPEDICMPS = 9,
	LINUX_MIB_ARPFILTER = 10,
	LINUX_MIB_TIMEWAITED = 11,
	LINUX_MIB_TIMEWAITRECYCLED = 12,
	LINUX_MIB_TIMEWAITKILLED = 13,
	LINUX_MIB_PAWSACTIVEREJECTED = 14,
	LINUX_MIB_PAWSESTABREJECTED = 15,
	LINUX_MIB_DELAYEDACKS = 16,
	LINUX_MIB_DELAYEDACKLOCKED = 17,
	LINUX_MIB_DELAYEDACKLOST = 18,
	LINUX_MIB_LISTENOVERFLOWS = 19,
	LINUX_MIB_LISTENDROPS = 20,
	LINUX_MIB_TCPHPHITS = 21,
	LINUX_MIB_TCPPUREACKS = 22,
	LINUX_MIB_TCPHPACKS = 23,
	LINUX_MIB_TCPRENORECOVERY = 24,
	LINUX_MIB_TCPSACKRECOVERY = 25,
	LINUX_MIB_TCPSACKRENEGING = 26,
	LINUX_MIB_TCPSACKREORDER = 27,
	LINUX_MIB_TCPRENOREORDER = 28,
	LINUX_MIB_TCPTSREORDER = 29,
	LINUX_MIB_TCPFULLUNDO = 30,
	LINUX_MIB_TCPPARTIALUNDO = 31,
	LINUX_MIB_TCPDSACKUNDO = 32,
	LINUX_MIB_TCPLOSSUNDO = 33,
	LINUX_MIB_TCPLOSTRETRANSMIT = 34,
	LINUX_MIB_TCPRENOFAILURES = 35,
	LINUX_MIB_TCPSACKFAILURES = 36,
	LINUX_MIB_TCPLOSSFAILURES = 37,
	LINUX_MIB_TCPFASTRETRANS = 38,
	LINUX_MIB_TCPSLOWSTARTRETRANS = 39,
	LINUX_MIB_TCPTIMEOUTS = 40,
	LINUX_MIB_TCPLOSSPROBES = 41,
	LINUX_MIB_TCPLOSSPROBERECOVERY = 42,
	LINUX_MIB_TCPRENORECOVERYFAIL = 43,
	LINUX_MIB_TCPSACKRECOVERYFAIL = 44,
	LINUX_MIB_TCPRCVCOLLAPSED = 45,
	LINUX_MIB_TCPDSACKOLDSENT = 46,
	LINUX_MIB_TCPDSACKOFOSENT = 47,
	LINUX_MIB_TCPDSACKRECV = 48,
	LINUX_MIB_TCPDSACKOFORECV = 49,
	LINUX_MIB_TCPABORTONDATA = 50,
	LINUX_MIB_TCPABORTONCLOSE = 51,
	LINUX_MIB_TCPABORTONMEMORY = 52,
	LINUX_MIB_TCPABORTONTIMEOUT = 53,
	LINUX_MIB_TCPABORTONLINGER = 54,
	LINUX_MIB_TCPABORTFAILED = 55,
	LINUX_MIB_TCPMEMORYPRESSURES = 56,
	LINUX_MIB_TCPMEMORYPRESSURESCHRONO = 57,
	LINUX_MIB_TCPSACKDISCARD = 58,
	LINUX_MIB_TCPDSACKIGNOREDOLD = 59,
	LINUX_MIB_TCPDSACKIGNOREDNOUNDO = 60,
	LINUX_MIB_TCPSPURIOUSRTOS = 61,
	LINUX_MIB_TCPMD5NOTFOUND = 62,
	LINUX_MIB_TCPMD5UNEXPECTED = 63,
	LINUX_MIB_TCPMD5FAILURE = 64,
	LINUX_MIB_SACKSHIFTED = 65,
	LINUX_MIB_SACKMERGED = 66,
	LINUX_MIB_SACKSHIFTFALLBACK = 67,
	LINUX_MIB_TCPBACKLOGDROP = 68,
	LINUX_MIB_PFMEMALLOCDROP = 69,
	LINUX_MIB_TCPMINTTLDROP = 70,
	LINUX_MIB_TCPDEFERACCEPTDROP = 71,
	LINUX_MIB_IPRPFILTER = 72,
	LINUX_MIB_TCPTIMEWAITOVERFLOW = 73,
	LINUX_MIB_TCPREQQFULLDOCOOKIES = 74,
	LINUX_MIB_TCPREQQFULLDROP = 75,
	LINUX_MIB_TCPRETRANSFAIL = 76,
	LINUX_MIB_TCPRCVCOALESCE = 77,
	LINUX_MIB_TCPBACKLOGCOALESCE = 78,
	LINUX_MIB_TCPOFOQUEUE = 79,
	LINUX_MIB_TCPOFODROP = 80,
	LINUX_MIB_TCPOFOMERGE = 81,
	LINUX_MIB_TCPCHALLENGEACK = 82,
	LINUX_MIB_TCPSYNCHALLENGE = 83,
	LINUX_MIB_TCPFASTOPENACTIVE = 84,
	LINUX_MIB_TCPFASTOPENACTIVEFAIL = 85,
	LINUX_MIB_TCPFASTOPENPASSIVE = 86,
	LINUX_MIB_TCPFASTOPENPASSIVEFAIL = 87,
	LINUX_MIB_TCPFASTOPENLISTENOVERFLOW = 88,
	LINUX_MIB_TCPFASTOPENCOOKIEREQD = 89,
	LINUX_MIB_TCPFASTOPENBLACKHOLE = 90,
	LINUX_MIB_TCPSPURIOUS_RTX_HOSTQUEUES = 91,
	LINUX_MIB_BUSYPOLLRXPACKETS = 92,
	LINUX_MIB_TCPAUTOCORKING = 93,
	LINUX_MIB_TCPFROMZEROWINDOWADV = 94,
	LINUX_MIB_TCPTOZEROWINDOWADV = 95,
	LINUX_MIB_TCPWANTZEROWINDOWADV = 96,
	LINUX_MIB_TCPSYNRETRANS = 97,
	LINUX_MIB_TCPORIGDATASENT = 98,
	LINUX_MIB_TCPHYSTARTTRAINDETECT = 99,
	LINUX_MIB_TCPHYSTARTTRAINCWND = 100,
	LINUX_MIB_TCPHYSTARTDELAYDETECT = 101,
	LINUX_MIB_TCPHYSTARTDELAYCWND = 102,
	LINUX_MIB_TCPACKSKIPPEDSYNRECV = 103,
	LINUX_MIB_TCPACKSKIPPEDPAWS = 104,
	LINUX_MIB_TCPACKSKIPPEDSEQ = 105,
	LINUX_MIB_TCPACKSKIPPEDFINWAIT2 = 106,
	LINUX_MIB_TCPACKSKIPPEDTIMEWAIT = 107,
	LINUX_MIB_TCPACKSKIPPEDCHALLENGE = 108,
	LINUX_MIB_TCPWINPROBE = 109,
	LINUX_MIB_TCPKEEPALIVE = 110,
	LINUX_MIB_TCPMTUPFAIL = 111,
	LINUX_MIB_TCPMTUPSUCCESS = 112,
	LINUX_MIB_TCPDELIVERED = 113,
	LINUX_MIB_TCPDELIVEREDCE = 114,
	LINUX_MIB_TCPACKCOMPRESSED = 115,
	LINUX_MIB_TCPZEROWINDOWDROP = 116,
	LINUX_MIB_TCPRCVQDROP = 117,
	LINUX_MIB_TCPWQUEUETOOBIG = 118,
	LINUX_MIB_TCPFASTOPENPASSIVEALTKEY = 119,
	LINUX_MIB_TCPTIMEOUTREHASH = 120,
	LINUX_MIB_TCPDUPLICATEDATAREHASH = 121,
	LINUX_MIB_TCPDSACKRECVSEGS = 122,
	LINUX_MIB_TCPDSACKIGNOREDDUBIOUS = 123,
	LINUX_MIB_TCPMIGRATEREQSUCCESS = 124,
	LINUX_MIB_TCPMIGRATEREQFAILURE = 125,
	__LINUX_MIB_MAX = 126,
};

enum {
	LINUX_MIB_XFRMNUM = 0,
	LINUX_MIB_XFRMINERROR = 1,
	LINUX_MIB_XFRMINBUFFERERROR = 2,
	LINUX_MIB_XFRMINHDRERROR = 3,
	LINUX_MIB_XFRMINNOSTATES = 4,
	LINUX_MIB_XFRMINSTATEPROTOERROR = 5,
	LINUX_MIB_XFRMINSTATEMODEERROR = 6,
	LINUX_MIB_XFRMINSTATESEQERROR = 7,
	LINUX_MIB_XFRMINSTATEEXPIRED = 8,
	LINUX_MIB_XFRMINSTATEMISMATCH = 9,
	LINUX_MIB_XFRMINSTATEINVALID = 10,
	LINUX_MIB_XFRMINTMPLMISMATCH = 11,
	LINUX_MIB_XFRMINNOPOLS = 12,
	LINUX_MIB_XFRMINPOLBLOCK = 13,
	LINUX_MIB_XFRMINPOLERROR = 14,
	LINUX_MIB_XFRMOUTERROR = 15,
	LINUX_MIB_XFRMOUTBUNDLEGENERROR = 16,
	LINUX_MIB_XFRMOUTBUNDLECHECKERROR = 17,
	LINUX_MIB_XFRMOUTNOSTATES = 18,
	LINUX_MIB_XFRMOUTSTATEPROTOERROR = 19,
	LINUX_MIB_XFRMOUTSTATEMODEERROR = 20,
	LINUX_MIB_XFRMOUTSTATESEQERROR = 21,
	LINUX_MIB_XFRMOUTSTATEEXPIRED = 22,
	LINUX_MIB_XFRMOUTPOLBLOCK = 23,
	LINUX_MIB_XFRMOUTPOLDEAD = 24,
	LINUX_MIB_XFRMOUTPOLERROR = 25,
	LINUX_MIB_XFRMFWDHDRERROR = 26,
	LINUX_MIB_XFRMOUTSTATEINVALID = 27,
	LINUX_MIB_XFRMACQUIREERROR = 28,
	__LINUX_MIB_XFRMMAX = 29,
};

enum {
	LINUX_MIB_TLSNUM = 0,
	LINUX_MIB_TLSCURRTXSW = 1,
	LINUX_MIB_TLSCURRRXSW = 2,
	LINUX_MIB_TLSCURRTXDEVICE = 3,
	LINUX_MIB_TLSCURRRXDEVICE = 4,
	LINUX_MIB_TLSTXSW = 5,
	LINUX_MIB_TLSRXSW = 6,
	LINUX_MIB_TLSTXDEVICE = 7,
	LINUX_MIB_TLSRXDEVICE = 8,
	LINUX_MIB_TLSDECRYPTERROR = 9,
	LINUX_MIB_TLSRXDEVICERESYNC = 10,
	__LINUX_MIB_TLSMAX = 11,
};

struct ipstats_mib {
	u64 mibs[37];
	struct u64_stats_sync syncp;
};

struct icmp_mib {
	long unsigned int mibs[28];
};

struct icmpmsg_mib {
	atomic_long_t mibs[512];
};

struct tcp_mib {
	long unsigned int mibs[16];
};

struct udp_mib {
	long unsigned int mibs[10];
};

struct linux_mib {
	long unsigned int mibs[126];
};

struct inet_frags;

struct fqdir {
	long int high_thresh;
	long int low_thresh;
	int timeout;
	int max_dist;
	struct inet_frags *f;
	struct net *net;
	bool dead;
	struct rhashtable rhashtable;
	atomic_long_t mem;
	struct work_struct destroy_work;
	struct llist_node free_list;
};

struct inet_frag_queue;

struct inet_frags {
	unsigned int qsize;
	void (*constructor)(struct inet_frag_queue *, const void *);
	void (*destructor)(struct inet_frag_queue *);
	void (*frag_expire)(struct timer_list *);
	struct kmem_cache *frags_cachep;
	const char *frags_cache_name;
	struct rhashtable_params rhash_params;
	refcount_t refcnt;
	struct completion completion;
};

struct frag_v4_compare_key {
	__be32 saddr;
	__be32 daddr;
	u32 user;
	u32 vif;
	__be16 id;
	u16 protocol;
};

struct frag_v6_compare_key {
	struct in6_addr saddr;
	struct in6_addr daddr;
	u32 user;
	__be32 id;
	u32 iif;
};

struct inet_frag_queue {
	struct rhash_head node;
	union {
		struct frag_v4_compare_key v4;
		struct frag_v6_compare_key v6;
	} key;
	struct timer_list timer;
	spinlock_t lock;
	refcount_t refcnt;
	struct rb_root rb_fragments;
	struct sk_buff *fragments_tail;
	struct sk_buff *last_run_head;
	ktime_t stamp;
	int len;
	int meat;
	u8 mono_delivery_time;
	__u8 flags;
	u16 max_size;
	struct fqdir *fqdir;
	struct callback_head rcu;
};

struct inet_hashinfo;

struct inet_timewait_death_row {
	refcount_t tw_refcount;
	struct inet_hashinfo *hashinfo;
	int sysctl_max_tw_buckets;
};

enum tcp_ca_event {
	CA_EVENT_TX_START = 0,
	CA_EVENT_CWND_RESTART = 1,
	CA_EVENT_COMPLETE_CWR = 2,
	CA_EVENT_LOSS = 3,
	CA_EVENT_ECN_NO_CE = 4,
	CA_EVENT_ECN_IS_CE = 5,
};

struct ack_sample;

struct rate_sample;

union tcp_cc_info;

struct tcp_congestion_ops {
	u32 (*ssthresh)(struct sock *);
	void (*cong_avoid)(struct sock *, u32, u32);
	void (*set_state)(struct sock *, u8);
	void (*cwnd_event)(struct sock *, enum tcp_ca_event);
	void (*in_ack_event)(struct sock *, u32);
	void (*pkts_acked)(struct sock *, const struct ack_sample *);
	u32 (*min_tso_segs)(struct sock *);
	void (*cong_control)(struct sock *, const struct rate_sample *);
	u32 (*undo_cwnd)(struct sock *);
	u32 (*sndbuf_expand)(struct sock *);
	size_t (*get_info)(struct sock *, u32, int *, union tcp_cc_info *);
	char name[16];
	struct module *owner;
	struct list_head list;
	u32 key;
	u32 flags;
	void (*init)(struct sock *);
	void (*release)(struct sock *);
};

typedef struct {} netdevice_tracker;

struct xfrm_state;

struct lwtunnel_state;

struct dst_entry {
	struct net_device *dev;
	struct dst_ops *ops;
	long unsigned int _metrics;
	long unsigned int expires;
	struct xfrm_state *xfrm;
	int (*input)(struct sk_buff *);
	int (*output)(struct net *, struct sock *, struct sk_buff *);
	short unsigned int flags;
	short int obsolete;
	short unsigned int header_len;
	short unsigned int trailer_len;
	int __use;
	long unsigned int lastuse;
	struct lwtunnel_state *lwtstate;
	struct callback_head callback_head;
	short int error;
	short int __pad;
	__u32 tclassid;
	atomic_t __refcnt;
	netdevice_tracker dev_tracker;
};

enum nf_inet_hooks {
	NF_INET_PRE_ROUTING = 0,
	NF_INET_LOCAL_IN = 1,
	NF_INET_FORWARD = 2,
	NF_INET_LOCAL_OUT = 3,
	NF_INET_POST_ROUTING = 4,
	NF_INET_NUMHOOKS = 5,
	NF_INET_INGRESS = 5,
};

enum {
	NFPROTO_UNSPEC = 0,
	NFPROTO_INET = 1,
	NFPROTO_IPV4 = 2,
	NFPROTO_ARP = 3,
	NFPROTO_NETDEV = 5,
	NFPROTO_BRIDGE = 7,
	NFPROTO_IPV6 = 10,
	NFPROTO_DECNET = 12,
	NFPROTO_NUMPROTO = 13,
};

enum {
	XFRM_POLICY_IN = 0,
	XFRM_POLICY_OUT = 1,
	XFRM_POLICY_FWD = 2,
	XFRM_POLICY_MASK = 3,
	XFRM_POLICY_MAX = 3,
};

enum netns_bpf_attach_type {
	NETNS_BPF_INVALID = 4294967295,
	NETNS_BPF_FLOW_DISSECTOR = 0,
	NETNS_BPF_SK_LOOKUP = 1,
	MAX_NETNS_BPF_ATTACH_TYPE = 2,
};

struct pipe_buf_operations;

struct pipe_buffer {
	struct page *page;
	unsigned int offset;
	unsigned int len;
	const struct pipe_buf_operations *ops;
	unsigned int flags;
	long unsigned int private;
};

struct pipe_buf_operations {
	int (*confirm)(struct pipe_inode_info *, struct pipe_buffer *);
	void (*release)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*try_steal)(struct pipe_inode_info *, struct pipe_buffer *);
	bool (*get)(struct pipe_inode_info *, struct pipe_buffer *);
};

struct skb_ext {
	refcount_t refcnt;
	u8 offset[1];
	u8 chunks;
	short: 16;
	char data[0];
};

enum skb_ext_id {
	SKB_EXT_SEC_PATH = 0,
	SKB_EXT_NUM = 1,
};

struct trace_event_raw_initcall_level {
	struct trace_entry ent;
	u32 __data_loc_level;
	char __data[0];
};

struct trace_event_raw_initcall_start {
	struct trace_entry ent;
	initcall_t func;
	char __data[0];
};

struct trace_event_raw_initcall_finish {
	struct trace_entry ent;
	initcall_t func;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_initcall_level {
	u32 level;
};

struct trace_event_data_offsets_initcall_start {};

struct trace_event_data_offsets_initcall_finish {};

typedef void (*btf_trace_initcall_level)(void *, const char *);

typedef void (*btf_trace_initcall_start)(void *, initcall_t);

typedef void (*btf_trace_initcall_finish)(void *, initcall_t, int);

struct blacklist_entry {
	struct list_head next;
	char *buf;
};

struct elf32_note {
	Elf32_Word n_namesz;
	Elf32_Word n_descsz;
	Elf32_Word n_type;
};

enum pcpu_fc {
	PCPU_FC_AUTO = 0,
	PCPU_FC_EMBED = 1,
	PCPU_FC_PAGE = 2,
	PCPU_FC_NR = 3,
};

enum hrtimer_base_type {
	HRTIMER_BASE_MONOTONIC = 0,
	HRTIMER_BASE_REALTIME = 1,
	HRTIMER_BASE_BOOTTIME = 2,
	HRTIMER_BASE_TAI = 3,
	HRTIMER_BASE_MONOTONIC_SOFT = 4,
	HRTIMER_BASE_REALTIME_SOFT = 5,
	HRTIMER_BASE_BOOTTIME_SOFT = 6,
	HRTIMER_BASE_TAI_SOFT = 7,
	HRTIMER_MAX_CLOCK_BASES = 8,
};

enum {
	MM_FILEPAGES = 0,
	MM_ANONPAGES = 1,
	MM_SWAPENTS = 2,
	MM_SHMEMPAGES = 3,
	NR_MM_COUNTERS = 4,
};

enum rseq_cs_flags_bit {
	RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT_BIT = 0,
	RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL_BIT = 1,
	RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE_BIT = 2,
};

enum {
	TASK_COMM_LEN = 16,
};

enum perf_event_task_context {
	perf_invalid_context = 4294967295,
	perf_hw_context = 0,
	perf_sw_context = 1,
	perf_nr_task_contexts = 2,
};

enum {
	PROC_ROOT_INO = 1,
	PROC_IPC_INIT_INO = 4026531839,
	PROC_UTS_INIT_INO = 4026531838,
	PROC_USER_INIT_INO = 4026531837,
	PROC_PID_INIT_INO = 4026531836,
	PROC_CGROUP_INIT_INO = 4026531835,
	PROC_TIME_INIT_INO = 4026531834,
};

struct subprocess_info {
	struct work_struct work;
	struct completion *complete;
	const char *path;
	char **argv;
	char **envp;
	int wait;
	int retval;
	int (*init)(struct subprocess_info *, struct cred *);
	void (*cleanup)(struct subprocess_info *);
	void *data;
};

enum {
	Root_NFS = 255,
	Root_CIFS = 254,
	Root_RAM0 = 1048576,
	Root_RAM1 = 1048577,
	Root_FD0 = 2097152,
	Root_HDA1 = 3145729,
	Root_HDA2 = 3145730,
	Root_SDA1 = 8388609,
	Root_SDA2 = 8388610,
	Root_HDC1 = 23068673,
	Root_SR0 = 11534336,
};

typedef unsigned int slab_flags_t;

typedef __u64 __addrpair;

typedef __u32 __portpair;

typedef struct {
	struct net *net;
} possible_net_t;

struct hlist_nulls_node {
	struct hlist_nulls_node *next;
	struct hlist_nulls_node **pprev;
};

struct proto;

struct sock_common {
	union {
		__addrpair skc_addrpair;
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		unsigned int skc_hash;
		__u16 skc_u16hashes[2];
	};
	union {
		__portpair skc_portpair;
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
	volatile unsigned char skc_state;
	unsigned char skc_reuse: 4;
	unsigned char skc_reuseport: 1;
	unsigned char skc_ipv6only: 1;
	unsigned char skc_net_refcnt: 1;
	int skc_bound_dev_if;
	union {
		struct hlist_node skc_bind_node;
		struct hlist_node skc_portaddr_node;
	};
	struct proto *skc_prot;
	possible_net_t skc_net;
	atomic64_t skc_cookie;
	union {
		long unsigned int skc_flags;
		struct sock *skc_listener;
		struct inet_timewait_death_row *skc_tw_dr;
	};
	int skc_dontcopy_begin[0];
	union {
		struct hlist_node skc_node;
		struct hlist_nulls_node skc_nulls_node;
	};
	short unsigned int skc_tx_queue_mapping;
	union {
		int skc_incoming_cpu;
		u32 skc_rcv_wnd;
		u32 skc_tw_rcv_nxt;
	};
	refcount_t skc_refcnt;
	int skc_dontcopy_end[0];
	union {
		u32 skc_rxhash;
		u32 skc_window_clamp;
		u32 skc_tw_snd_nxt;
	};
	int: 32;
};

typedef struct {
	spinlock_t slock;
	int owned;
	wait_queue_head_t wq;
} socket_lock_t;

struct sk_buff_list {
	struct sk_buff *next;
	struct sk_buff *prev;
};

struct sk_buff_head {
	union {
		struct {
			struct sk_buff *next;
			struct sk_buff *prev;
		};
		struct sk_buff_list list;
	};
	__u32 qlen;
	spinlock_t lock;
};

typedef u64 netdev_features_t;

struct sock_cgroup_data {};

typedef struct {} netns_tracker;

struct sk_filter;

struct socket_wq;

struct xfrm_policy;

struct socket;

struct sock_reuseport;

struct sock {
	struct sock_common __sk_common;
	struct dst_entry *sk_rx_dst;
	int sk_rx_dst_ifindex;
	u32 sk_rx_dst_cookie;
	socket_lock_t sk_lock;
	atomic_t sk_drops;
	int sk_rcvlowat;
	struct sk_buff_head sk_error_queue;
	struct sk_buff_head sk_receive_queue;
	struct {
		atomic_t rmem_alloc;
		int len;
		struct sk_buff *head;
		struct sk_buff *tail;
	} sk_backlog;
	struct llist_head defer_list;
	int sk_forward_alloc;
	u32 sk_reserved_mem;
	unsigned int sk_ll_usec;
	unsigned int sk_napi_id;
	int sk_rcvbuf;
	struct sk_filter *sk_filter;
	union {
		struct socket_wq *sk_wq;
		struct socket_wq *sk_wq_raw;
	};
	struct xfrm_policy *sk_policy[2];
	struct dst_entry *sk_dst_cache;
	atomic_t sk_omem_alloc;
	int sk_sndbuf;
	int sk_wmem_queued;
	refcount_t sk_wmem_alloc;
	long unsigned int sk_tsq_flags;
	union {
		struct sk_buff *sk_send_head;
		struct rb_root tcp_rtx_queue;
	};
	struct sk_buff_head sk_write_queue;
	__s32 sk_peek_off;
	int sk_write_pending;
	__u32 sk_dst_pending_confirm;
	u32 sk_pacing_status;
	long int sk_sndtimeo;
	struct timer_list sk_timer;
	__u32 sk_priority;
	__u32 sk_mark;
	long unsigned int sk_pacing_rate;
	long unsigned int sk_max_pacing_rate;
	struct page_frag sk_frag;
	netdev_features_t sk_route_caps;
	int sk_gso_type;
	unsigned int sk_gso_max_size;
	gfp_t sk_allocation;
	__u32 sk_txhash;
	u8 sk_gso_disabled: 1;
	u8 sk_kern_sock: 1;
	u8 sk_no_check_tx: 1;
	u8 sk_no_check_rx: 1;
	u8 sk_userlocks: 4;
	u8 sk_pacing_shift;
	u16 sk_type;
	u16 sk_protocol;
	u16 sk_gso_max_segs;
	long unsigned int sk_lingertime;
	struct proto *sk_prot_creator;
	rwlock_t sk_callback_lock;
	int sk_err;
	int sk_err_soft;
	u32 sk_ack_backlog;
	u32 sk_max_ack_backlog;
	kuid_t sk_uid;
	u8 sk_txrehash;
	u8 sk_prefer_busy_poll;
	u16 sk_busy_poll_budget;
	spinlock_t sk_peer_lock;
	int sk_bind_phc;
	struct pid *sk_peer_pid;
	const struct cred *sk_peer_cred;
	long int sk_rcvtimeo;
	ktime_t sk_stamp;
	seqlock_t sk_stamp_seq;
	u16 sk_tsflags;
	u8 sk_shutdown;
	atomic_t sk_tskey;
	atomic_t sk_zckey;
	u8 sk_clockid;
	u8 sk_txtime_deadline_mode: 1;
	u8 sk_txtime_report_errors: 1;
	u8 sk_txtime_unused: 6;
	struct socket *sk_socket;
	void *sk_user_data;
	struct sock_cgroup_data sk_cgrp_data;
	struct mem_cgroup *sk_memcg;
	void (*sk_state_change)(struct sock *);
	void (*sk_data_ready)(struct sock *);
	void (*sk_write_space)(struct sock *);
	void (*sk_error_report)(struct sock *);
	int (*sk_backlog_rcv)(struct sock *, struct sk_buff *);
	void (*sk_destruct)(struct sock *);
	struct sock_reuseport *sk_reuseport_cb;
	struct bpf_local_storage *sk_bpf_storage;
	struct callback_head sk_rcu;
	netns_tracker ns_tracker;
};

struct fs_struct {
	int users;
	spinlock_t lock;
	seqcount_spinlock_t seq;
	int umask;
	int in_exec;
	struct path root;
	struct path pwd;
};

struct ld_semaphore {
	atomic_long_t count;
	raw_spinlock_t wait_lock;
	unsigned int wait_readers;
	struct list_head read_wait;
	struct list_head write_wait;
};

typedef unsigned int tcflag_t;

typedef unsigned char cc_t;

typedef unsigned int speed_t;

struct ktermios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct winsize {
	short unsigned int ws_row;
	short unsigned int ws_col;
	short unsigned int ws_xpixel;
	short unsigned int ws_ypixel;
};

struct tty_driver;

struct tty_operations;

struct tty_ldisc;

struct tty_port;

struct tty_struct {
	int magic;
	struct kref kref;
	struct device *dev;
	struct tty_driver *driver;
	const struct tty_operations *ops;
	int index;
	struct ld_semaphore ldisc_sem;
	struct tty_ldisc *ldisc;
	struct mutex atomic_write_lock;
	struct mutex legacy_mutex;
	struct mutex throttle_mutex;
	struct rw_semaphore termios_rwsem;
	struct mutex winsize_mutex;
	struct ktermios termios;
	struct ktermios termios_locked;
	char name[64];
	long unsigned int flags;
	int count;
	struct winsize winsize;
	struct {
		spinlock_t lock;
		bool stopped;
		bool tco_stopped;
		long unsigned int unused[0];
	} flow;
	struct {
		spinlock_t lock;
		struct pid *pgrp;
		struct pid *session;
		unsigned char pktstatus;
		bool packet;
		long unsigned int unused[0];
	} ctrl;
	int hw_stopped;
	unsigned int receive_room;
	int flow_change;
	struct tty_struct *link;
	struct fasync_struct *fasync;
	wait_queue_head_t write_wait;
	wait_queue_head_t read_wait;
	struct work_struct hangup_work;
	void *disc_data;
	void *driver_data;
	spinlock_t files_lock;
	struct list_head tty_files;
	int closing;
	unsigned char *write_buf;
	int write_cnt;
	struct work_struct SAK_work;
	struct tty_port *port;
};

struct posix_acl_entry {
	short int e_tag;
	short unsigned int e_perm;
	union {
		kuid_t e_uid;
		kgid_t e_gid;
	};
};

struct posix_acl {
	refcount_t a_refcount;
	struct callback_head a_rcu;
	unsigned int a_count;
	struct posix_acl_entry a_entries[0];
};

struct tty_buffer {
	union {
		struct tty_buffer *next;
		struct llist_node free;
	};
	int used;
	int size;
	int commit;
	int read;
	int flags;
	long unsigned int data[0];
};

struct tty_bufhead {
	struct tty_buffer *head;
	struct work_struct work;
	struct mutex lock;
	atomic_t priority;
	struct tty_buffer sentinel;
	struct llist_head free;
	atomic_t mem_used;
	int mem_limit;
	struct tty_buffer *tail;
};

struct serial_icounter_struct;

struct serial_struct;

struct tty_operations {
	struct tty_struct * (*lookup)(struct tty_driver *, struct file *, int);
	int (*install)(struct tty_driver *, struct tty_struct *);
	void (*remove)(struct tty_driver *, struct tty_struct *);
	int (*open)(struct tty_struct *, struct file *);
	void (*close)(struct tty_struct *, struct file *);
	void (*shutdown)(struct tty_struct *);
	void (*cleanup)(struct tty_struct *);
	int (*write)(struct tty_struct *, const unsigned char *, int);
	int (*put_char)(struct tty_struct *, unsigned char);
	void (*flush_chars)(struct tty_struct *);
	unsigned int (*write_room)(struct tty_struct *);
	unsigned int (*chars_in_buffer)(struct tty_struct *);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, struct ktermios *);
	void (*throttle)(struct tty_struct *);
	void (*unthrottle)(struct tty_struct *);
	void (*stop)(struct tty_struct *);
	void (*start)(struct tty_struct *);
	void (*hangup)(struct tty_struct *);
	int (*break_ctl)(struct tty_struct *, int);
	void (*flush_buffer)(struct tty_struct *);
	void (*set_ldisc)(struct tty_struct *);
	void (*wait_until_sent)(struct tty_struct *, int);
	void (*send_xchar)(struct tty_struct *, char);
	int (*tiocmget)(struct tty_struct *);
	int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);
	int (*resize)(struct tty_struct *, struct winsize *);
	int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *);
	int (*get_serial)(struct tty_struct *, struct serial_struct *);
	int (*set_serial)(struct tty_struct *, struct serial_struct *);
	void (*show_fdinfo)(struct tty_struct *, struct seq_file *);
	int (*proc_show)(struct seq_file *, void *);
};

struct tty_driver {
	int magic;
	struct kref kref;
	struct cdev **cdevs;
	struct module *owner;
	const char *driver_name;
	const char *name;
	int name_base;
	int major;
	int minor_start;
	unsigned int num;
	short int type;
	short int subtype;
	struct ktermios init_termios;
	long unsigned int flags;
	struct proc_dir_entry *proc_entry;
	struct tty_driver *other;
	struct tty_struct **ttys;
	struct tty_port **ports;
	struct ktermios **termios;
	void *driver_state;
	const struct tty_operations *ops;
	struct list_head tty_drivers;
};

struct __kfifo {
	unsigned int in;
	unsigned int out;
	unsigned int mask;
	unsigned int esize;
	void *data;
};

struct tty_port_operations;

struct tty_port_client_operations;

struct tty_port {
	struct tty_bufhead buf;
	struct tty_struct *tty;
	struct tty_struct *itty;
	const struct tty_port_operations *ops;
	const struct tty_port_client_operations *client_ops;
	spinlock_t lock;
	int blocked_open;
	int count;
	wait_queue_head_t open_wait;
	wait_queue_head_t delta_msr_wait;
	long unsigned int flags;
	long unsigned int iflags;
	unsigned char console: 1;
	struct mutex mutex;
	struct mutex buf_mutex;
	unsigned char *xmit_buf;
	struct {
		union {
			struct __kfifo kfifo;
			unsigned char *type;
			const unsigned char *const_type;
			char (*rectype)[0];
			unsigned char *ptr;
			const unsigned char *ptr_const;
		};
		unsigned char buf[0];
	} xmit_fifo;
	unsigned int close_delay;
	unsigned int closing_wait;
	int drain_delay;
	struct kref kref;
	void *client_data;
};

struct tty_ldisc_ops {
	char *name;
	int num;
	int (*open)(struct tty_struct *);
	void (*close)(struct tty_struct *);
	void (*flush_buffer)(struct tty_struct *);
	ssize_t (*read)(struct tty_struct *, struct file *, unsigned char *, size_t, void **, long unsigned int);
	ssize_t (*write)(struct tty_struct *, struct file *, const unsigned char *, size_t);
	int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int);
	void (*set_termios)(struct tty_struct *, struct ktermios *);
	__poll_t (*poll)(struct tty_struct *, struct file *, struct poll_table_struct *);
	void (*hangup)(struct tty_struct *);
	void (*receive_buf)(struct tty_struct *, const unsigned char *, const char *, int);
	void (*write_wakeup)(struct tty_struct *);
	void (*dcd_change)(struct tty_struct *, unsigned int);
	int (*receive_buf2)(struct tty_struct *, const unsigned char *, const char *, int);
	struct module *owner;
};

struct tty_ldisc {
	struct tty_ldisc_ops *ops;
	struct tty_struct *tty;
};

struct tty_port_operations {
	int (*carrier_raised)(struct tty_port *);
	void (*dtr_rts)(struct tty_port *, int);
	void (*shutdown)(struct tty_port *);
	int (*activate)(struct tty_port *, struct tty_struct *);
	void (*destruct)(struct tty_port *);
};

struct tty_port_client_operations {
	int (*receive_buf)(struct tty_port *, const unsigned char *, const unsigned char *, size_t);
	void (*write_wakeup)(struct tty_port *);
};

typedef struct {
	u64 v;
} u64_stats_t;

typedef short unsigned int __kernel_sa_family_t;

typedef __kernel_sa_family_t sa_family_t;

struct sockaddr {
	sa_family_t sa_family;
	char sa_data[14];
};

struct msghdr {
	void *msg_name;
	int msg_namelen;
	struct iov_iter msg_iter;
	union {
		void *msg_control;
		void *msg_control_user;
	};
	bool msg_control_is_user: 1;
	__kernel_size_t msg_controllen;
	unsigned int msg_flags;
	struct kiocb *msg_iocb;
};

enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};

struct prot_inuse {
	int all;
	int val[64];
};

struct icmpv6_mib_device {
	atomic_long_t mibs[6];
};

struct icmpv6msg_mib_device {
	atomic_long_t mibs[512];
};

struct netlink_ext_ack;

struct fib_notifier_ops {
	int family;
	struct list_head list;
	unsigned int (*fib_seq_read)(struct net *);
	int (*fib_dump)(struct net *, struct notifier_block *, struct netlink_ext_ack *);
	struct module *owner;
	struct callback_head rcu;
};

struct net_device_stats {
	long unsigned int rx_packets;
	long unsigned int tx_packets;
	long unsigned int rx_bytes;
	long unsigned int tx_bytes;
	long unsigned int rx_errors;
	long unsigned int tx_errors;
	long unsigned int rx_dropped;
	long unsigned int tx_dropped;
	long unsigned int multicast;
	long unsigned int collisions;
	long unsigned int rx_length_errors;
	long unsigned int rx_over_errors;
	long unsigned int rx_crc_errors;
	long unsigned int rx_frame_errors;
	long unsigned int rx_fifo_errors;
	long unsigned int rx_missed_errors;
	long unsigned int tx_aborted_errors;
	long unsigned int tx_carrier_errors;
	long unsigned int tx_fifo_errors;
	long unsigned int tx_heartbeat_errors;
	long unsigned int tx_window_errors;
	long unsigned int rx_compressed;
	long unsigned int tx_compressed;
};

struct netdev_hw_addr_list {
	struct list_head list;
	int count;
	struct rb_root tree;
};

struct wireless_dev;

struct wpan_dev;

enum rx_handler_result {
	RX_HANDLER_CONSUMED = 0,
	RX_HANDLER_ANOTHER = 1,
	RX_HANDLER_EXACT = 2,
	RX_HANDLER_PASS = 3,
};

typedef enum rx_handler_result rx_handler_result_t;

typedef rx_handler_result_t rx_handler_func_t(struct sk_buff **);

enum netdev_ml_priv_type {
	ML_PRIV_NONE = 0,
	ML_PRIV_CAN = 1,
};

struct pcpu_dstats;

struct netdev_tc_txq {
	u16 count;
	u16 offset;
};

struct sfp_bus;

struct udp_tunnel_nic;

struct bpf_xdp_link;

struct bpf_xdp_entity {
	struct bpf_prog *prog;
	struct bpf_xdp_link *link;
};

struct netdev_name_node;

struct dev_ifalias;

struct net_device_ops;

struct net_device_core_stats;

struct ethtool_ops;

struct header_ops;

struct in_device;

struct inet6_dev;

struct netdev_rx_queue;

struct netdev_queue;

struct Qdisc;

struct xdp_dev_bulk_queue;

struct pcpu_lstats;

struct pcpu_sw_netstats;

struct rtnl_link_ops;

struct phy_device;

struct udp_tunnel_nic_info;

struct rtnl_hw_stats64;

struct net_device {
	char name[16];
	struct netdev_name_node *name_node;
	struct dev_ifalias *ifalias;
	long unsigned int mem_end;
	long unsigned int mem_start;
	long unsigned int base_addr;
	long unsigned int state;
	struct list_head dev_list;
	struct list_head napi_list;
	struct list_head unreg_list;
	struct list_head close_list;
	struct list_head ptype_all;
	struct list_head ptype_specific;
	struct {
		struct list_head upper;
		struct list_head lower;
	} adj_list;
	unsigned int flags;
	long long unsigned int priv_flags;
	const struct net_device_ops *netdev_ops;
	int ifindex;
	short unsigned int gflags;
	short unsigned int hard_header_len;
	unsigned int mtu;
	short unsigned int needed_headroom;
	short unsigned int needed_tailroom;
	netdev_features_t features;
	netdev_features_t hw_features;
	netdev_features_t wanted_features;
	netdev_features_t vlan_features;
	netdev_features_t hw_enc_features;
	netdev_features_t mpls_features;
	netdev_features_t gso_partial_features;
	unsigned int min_mtu;
	unsigned int max_mtu;
	short unsigned int type;
	unsigned char min_header_len;
	unsigned char name_assign_type;
	int group;
	struct net_device_stats stats;
	struct net_device_core_stats *core_stats;
	atomic_t carrier_up_count;
	atomic_t carrier_down_count;
	const struct ethtool_ops *ethtool_ops;
	const struct header_ops *header_ops;
	unsigned char operstate;
	unsigned char link_mode;
	unsigned char if_port;
	unsigned char dma;
	unsigned char perm_addr[32];
	unsigned char addr_assign_type;
	unsigned char addr_len;
	unsigned char upper_level;
	unsigned char lower_level;
	short unsigned int neigh_priv_len;
	short unsigned int dev_id;
	short unsigned int dev_port;
	short unsigned int padded;
	spinlock_t addr_list_lock;
	int irq;
	struct netdev_hw_addr_list uc;
	struct netdev_hw_addr_list mc;
	struct netdev_hw_addr_list dev_addrs;
	struct kset *queues_kset;
	unsigned int promiscuity;
	unsigned int allmulti;
	bool uc_promisc;
	struct in_device *ip_ptr;
	struct inet6_dev *ip6_ptr;
	struct wireless_dev *ieee80211_ptr;
	struct wpan_dev *ieee802154_ptr;
	const unsigned char *dev_addr;
	struct netdev_rx_queue *_rx;
	unsigned int num_rx_queues;
	unsigned int real_num_rx_queues;
	struct bpf_prog *xdp_prog;
	long unsigned int gro_flush_timeout;
	int napi_defer_hard_irqs;
	unsigned int gro_max_size;
	rx_handler_func_t *rx_handler;
	void *rx_handler_data;
	struct netdev_queue *ingress_queue;
	unsigned char broadcast[32];
	struct hlist_node index_hlist;
	struct netdev_queue *_tx;
	unsigned int num_tx_queues;
	unsigned int real_num_tx_queues;
	struct Qdisc *qdisc;
	unsigned int tx_queue_len;
	spinlock_t tx_global_lock;
	struct xdp_dev_bulk_queue *xdp_bulkq;
	struct timer_list watchdog_timer;
	int watchdog_timeo;
	u32 proto_down_reason;
	struct list_head todo_list;
	refcount_t dev_refcnt;
	struct ref_tracker_dir refcnt_tracker;
	struct list_head link_watch_list;
	enum {
		NETREG_UNINITIALIZED = 0,
		NETREG_REGISTERED = 1,
		NETREG_UNREGISTERING = 2,
		NETREG_UNREGISTERED = 3,
		NETREG_RELEASED = 4,
		NETREG_DUMMY = 5,
	} reg_state: 8;
	bool dismantle;
	enum {
		RTNL_LINK_INITIALIZED = 0,
		RTNL_LINK_INITIALIZING = 1,
	} rtnl_link_state: 16;
	bool needs_free_netdev;
	void (*priv_destructor)(struct net_device *);
	possible_net_t nd_net;
	void *ml_priv;
	enum netdev_ml_priv_type ml_priv_type;
	union {
		struct pcpu_lstats *lstats;
		struct pcpu_sw_netstats *tstats;
		struct pcpu_dstats *dstats;
	};
	struct device dev;
	const struct attribute_group *sysfs_groups[4];
	const struct attribute_group *sysfs_rx_queue_group;
	const struct rtnl_link_ops *rtnl_link_ops;
	unsigned int gso_max_size;
	u16 gso_max_segs;
	s16 num_tc;
	struct netdev_tc_txq tc_to_txq[16];
	u8 prio_tc_map[16];
	struct phy_device *phydev;
	struct sfp_bus *sfp_bus;
	struct lock_class_key *qdisc_tx_busylock;
	bool proto_down;
	unsigned int wol_enabled: 1;
	unsigned int threaded: 1;
	struct list_head net_notifier_list;
	const struct udp_tunnel_nic_info *udp_tunnel_nic_info;
	struct udp_tunnel_nic *udp_tunnel_nic;
	struct bpf_xdp_entity xdp_state[3];
	u8 dev_addr_shadow[32];
	netdevice_tracker linkwatch_dev_tracker;
	netdevice_tracker watchdog_dev_tracker;
	netdevice_tracker dev_registered_tracker;
	struct rtnl_hw_stats64 *offload_xstats_l3;
};

struct hh_cache {
	unsigned int hh_len;
	seqlock_t hh_lock;
	long unsigned int hh_data[8];
};

struct neigh_table;

struct neigh_parms;

struct neigh_ops;

struct neighbour {
	struct neighbour *next;
	struct neigh_table *tbl;
	struct neigh_parms *parms;
	long unsigned int confirmed;
	long unsigned int updated;
	rwlock_t lock;
	refcount_t refcnt;
	unsigned int arp_queue_len_bytes;
	struct sk_buff_head arp_queue;
	struct timer_list timer;
	long unsigned int used;
	atomic_t probes;
	u8 nud_state;
	u8 type;
	u8 dead;
	u8 protocol;
	u32 flags;
	seqlock_t ha_lock;
	unsigned char ha[32];
	struct hh_cache hh;
	int (*output)(struct neighbour *, struct sk_buff *);
	const struct neigh_ops *ops;
	struct list_head gc_list;
	struct list_head managed_list;
	struct callback_head rcu;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u8 primary_key[0];
	int: 32;
};

struct ipv6_stable_secret {
	bool initialized;
	struct in6_addr secret;
};

struct ipv6_devconf {
	__s32 forwarding;
	__s32 hop_limit;
	__s32 mtu6;
	__s32 accept_ra;
	__s32 accept_redirects;
	__s32 autoconf;
	__s32 dad_transmits;
	__s32 rtr_solicits;
	__s32 rtr_solicit_interval;
	__s32 rtr_solicit_max_interval;
	__s32 rtr_solicit_delay;
	__s32 force_mld_version;
	__s32 mldv1_unsolicited_report_interval;
	__s32 mldv2_unsolicited_report_interval;
	__s32 use_tempaddr;
	__s32 temp_valid_lft;
	__s32 temp_prefered_lft;
	__s32 regen_max_retry;
	__s32 max_desync_factor;
	__s32 max_addresses;
	__s32 accept_ra_defrtr;
	__u32 ra_defrtr_metric;
	__s32 accept_ra_min_hop_limit;
	__s32 accept_ra_pinfo;
	__s32 ignore_routes_with_linkdown;
	__s32 proxy_ndp;
	__s32 accept_source_route;
	__s32 accept_ra_from_local;
	__s32 disable_ipv6;
	__s32 drop_unicast_in_l2_multicast;
	__s32 accept_dad;
	__s32 force_tllao;
	__s32 ndisc_notify;
	__s32 suppress_frag_ndisc;
	__s32 accept_ra_mtu;
	__s32 drop_unsolicited_na;
	struct ipv6_stable_secret stable_secret;
	__s32 use_oif_addrs_only;
	__s32 keep_addr_on_down;
	__s32 seg6_enabled;
	__u32 enhanced_dad;
	__u32 addr_gen_mode;
	__s32 disable_policy;
	__s32 ndisc_tclass;
	__s32 rpl_seg_enabled;
	__u32 ioam6_id;
	__u32 ioam6_id_wide;
	__u8 ioam6_enabled;
	__u8 ndisc_evict_nocarrier;
	struct ctl_table_header *sysctl_header;
};

typedef struct {
	union {
		void *kernel;
		void *user;
	};
	bool is_kernel: 1;
} sockptr_t;

typedef enum {
	SS_FREE = 0,
	SS_UNCONNECTED = 1,
	SS_CONNECTING = 2,
	SS_CONNECTED = 3,
	SS_DISCONNECTING = 4,
} socket_state;

struct socket_wq {
	wait_queue_head_t wait;
	struct fasync_struct *fasync_list;
	long unsigned int flags;
	struct callback_head rcu;
};

struct proto_ops;

struct socket {
	socket_state state;
	short int type;
	long unsigned int flags;
	struct file *file;
	struct sock *sk;
	const struct proto_ops *ops;
	struct socket_wq wq;
};

typedef struct {
	size_t written;
	size_t count;
	union {
		char *buf;
		void *data;
	} arg;
	int error;
} read_descriptor_t;

typedef int (*sk_read_actor_t)(read_descriptor_t *, struct sk_buff *, unsigned int, size_t);

struct proto_ops {
	int family;
	struct module *owner;
	int (*release)(struct socket *);
	int (*bind)(struct socket *, struct sockaddr *, int);
	int (*connect)(struct socket *, struct sockaddr *, int, int);
	int (*socketpair)(struct socket *, struct socket *);
	int (*accept)(struct socket *, struct socket *, int, bool);
	int (*getname)(struct socket *, struct sockaddr *, int);
	__poll_t (*poll)(struct file *, struct socket *, struct poll_table_struct *);
	int (*ioctl)(struct socket *, unsigned int, long unsigned int);
	int (*gettstamp)(struct socket *, void *, bool, bool);
	int (*listen)(struct socket *, int);
	int (*shutdown)(struct socket *, int);
	int (*setsockopt)(struct socket *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct socket *, int, int, char *, int *);
	void (*show_fdinfo)(struct seq_file *, struct socket *);
	int (*sendmsg)(struct socket *, struct msghdr *, size_t);
	int (*recvmsg)(struct socket *, struct msghdr *, size_t, int);
	int (*mmap)(struct file *, struct socket *, struct vm_area_struct *);
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	ssize_t (*splice_read)(struct socket *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	int (*set_peek_off)(struct sock *, int);
	int (*peek_len)(struct socket *);
	int (*read_sock)(struct sock *, read_descriptor_t *, sk_read_actor_t);
	int (*sendpage_locked)(struct sock *, struct page *, int, size_t, int);
	int (*sendmsg_locked)(struct sock *, struct msghdr *, size_t);
	int (*set_rcvlowat)(struct sock *, int);
};

enum rpc_display_format_t {
	RPC_DISPLAY_ADDR = 0,
	RPC_DISPLAY_PORT = 1,
	RPC_DISPLAY_PROTO = 2,
	RPC_DISPLAY_HEX_ADDR = 3,
	RPC_DISPLAY_HEX_PORT = 4,
	RPC_DISPLAY_NETID = 5,
	RPC_DISPLAY_MAX = 6,
};

typedef struct {
	atomic_long_t a;
} local_t;

struct dql {
	unsigned int num_queued;
	unsigned int adj_limit;
	unsigned int last_obj_cnt;
	unsigned int limit;
	unsigned int num_completed;
	unsigned int prev_ovlimit;
	unsigned int prev_num_queued;
	unsigned int prev_last_obj_cnt;
	unsigned int lowest_slack;
	long unsigned int slack_start_time;
	unsigned int max_limit;
	unsigned int min_limit;
	unsigned int slack_hold_time;
};

struct xdp_mem_info {
	u32 type;
	u32 id;
};

struct xdp_rxq_info {
	struct net_device *dev;
	u32 queue_index;
	u32 reg_state;
	struct xdp_mem_info mem;
	unsigned int napi_id;
	u32 frag_size;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct xdp_txq_info {
	struct net_device *dev;
};

struct xdp_buff {
	void *data;
	void *data_end;
	void *data_meta;
	void *data_hard_start;
	struct xdp_rxq_info *rxq;
	struct xdp_txq_info *txq;
	u32 frame_sz;
	u32 flags;
};

struct xdp_frame {
	void *data;
	u16 len;
	u16 headroom;
	u32 metasize: 8;
	u32 frame_sz: 24;
	struct xdp_mem_info mem;
	struct net_device *dev_rx;
	u32 flags;
};

struct nlmsghdr {
	__u32 nlmsg_len;
	__u16 nlmsg_type;
	__u16 nlmsg_flags;
	__u32 nlmsg_seq;
	__u32 nlmsg_pid;
};

struct nlattr {
	__u16 nla_len;
	__u16 nla_type;
};

struct nla_policy;

struct netlink_ext_ack {
	const char *_msg;
	const struct nlattr *bad_attr;
	const struct nla_policy *policy;
	u8 cookie[20];
	u8 cookie_len;
};

struct netlink_range_validation;

struct netlink_range_validation_signed;

struct nla_policy {
	u8 type;
	u8 validation_type;
	u16 len;
	union {
		const u32 bitfield32_valid;
		const u32 mask;
		const char *reject_message;
		const struct nla_policy *nested_policy;
		struct netlink_range_validation *range;
		struct netlink_range_validation_signed *range_signed;
		struct {
			s16 min;
			s16 max;
		};
		int (*validate)(const struct nlattr *, struct netlink_ext_ack *);
		u16 strict_start_type;
	};
};

struct netlink_callback {
	struct sk_buff *skb;
	const struct nlmsghdr *nlh;
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	struct netlink_ext_ack *extack;
	u16 family;
	u16 answer_flags;
	u32 min_dump_alloc;
	unsigned int prev_seq;
	unsigned int seq;
	bool strict_check;
	union {
		u8 ctx[48];
		long int args[6];
	};
};

struct ndmsg {
	__u8 ndm_family;
	__u8 ndm_pad1;
	__u16 ndm_pad2;
	__s32 ndm_ifindex;
	__u16 ndm_state;
	__u8 ndm_flags;
	__u8 ndm_type;
};

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
} sync_serial_settings;

typedef struct {
	unsigned int clock_rate;
	unsigned int clock_type;
	short unsigned int loopback;
	unsigned int slot_map;
} te1_settings;

typedef struct {
	short unsigned int encoding;
	short unsigned int parity;
} raw_hdlc_proto;

typedef struct {
	unsigned int t391;
	unsigned int t392;
	unsigned int n391;
	unsigned int n392;
	unsigned int n393;
	short unsigned int lmi;
	short unsigned int dce;
} fr_proto;

typedef struct {
	unsigned int dlci;
} fr_proto_pvc;

typedef struct {
	unsigned int dlci;
	char master[16];
} fr_proto_pvc_info;

typedef struct {
	unsigned int interval;
	unsigned int timeout;
} cisco_proto;

typedef struct {
	short unsigned int dce;
	unsigned int modulo;
	unsigned int window;
	unsigned int t1;
	unsigned int t2;
	unsigned int n2;
} x25_hdlc_proto;

struct ifmap {
	long unsigned int mem_start;
	long unsigned int mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct if_settings {
	unsigned int type;
	unsigned int size;
	union {
		raw_hdlc_proto *raw_hdlc;
		cisco_proto *cisco;
		fr_proto *fr;
		fr_proto_pvc *fr_pvc;
		fr_proto_pvc_info *fr_pvc_info;
		x25_hdlc_proto *x25;
		sync_serial_settings *sync;
		te1_settings *te1;
	} ifs_ifsu;
};

struct ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		int ifru_ivalue;
		int ifru_mtu;
		struct ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		void *ifru_data;
		struct if_settings ifru_settings;
	} ifr_ifru;
};

struct rtnl_link_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
	__u64 collisions;
	__u64 rx_length_errors;
	__u64 rx_over_errors;
	__u64 rx_crc_errors;
	__u64 rx_frame_errors;
	__u64 rx_fifo_errors;
	__u64 rx_missed_errors;
	__u64 tx_aborted_errors;
	__u64 tx_carrier_errors;
	__u64 tx_fifo_errors;
	__u64 tx_heartbeat_errors;
	__u64 tx_window_errors;
	__u64 rx_compressed;
	__u64 tx_compressed;
	__u64 rx_nohandler;
};

struct rtnl_hw_stats64 {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 rx_errors;
	__u64 tx_errors;
	__u64 rx_dropped;
	__u64 tx_dropped;
	__u64 multicast;
};

struct ifla_vf_guid {
	__u32 vf;
	__u64 guid;
};

struct ifla_vf_stats {
	__u64 rx_packets;
	__u64 tx_packets;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 broadcast;
	__u64 multicast;
	__u64 rx_dropped;
	__u64 tx_dropped;
};

struct ifla_vf_info {
	__u32 vf;
	__u8 mac[32];
	__u32 vlan;
	__u32 qos;
	__u32 spoofchk;
	__u32 linkstate;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
	__u32 rss_query_en;
	__u32 trusted;
	__be16 vlan_proto;
};

enum netdev_tx {
	__NETDEV_TX_MIN = 2147483648,
	NETDEV_TX_OK = 0,
	NETDEV_TX_BUSY = 16,
};

typedef enum netdev_tx netdev_tx_t;

struct net_device_core_stats {
	local_t rx_dropped;
	local_t tx_dropped;
	local_t rx_nohandler;
	int: 32;
};

struct header_ops {
	int (*create)(struct sk_buff *, struct net_device *, short unsigned int, const void *, const void *, unsigned int);
	int (*parse)(const struct sk_buff *, unsigned char *);
	int (*cache)(const struct neighbour *, struct hh_cache *, __be16);
	void (*cache_update)(struct hh_cache *, const struct net_device *, const unsigned char *);
	bool (*validate)(const char *, unsigned int);
	__be16 (*parse_protocol)(const struct sk_buff *);
};

enum {
	NAPI_STATE_SCHED = 0,
	NAPI_STATE_MISSED = 1,
	NAPI_STATE_DISABLE = 2,
	NAPI_STATE_NPSVC = 3,
	NAPI_STATE_LISTED = 4,
	NAPI_STATE_NO_BUSY_POLL = 5,
	NAPI_STATE_IN_BUSY_POLL = 6,
	NAPI_STATE_PREFER_BUSY_POLL = 7,
	NAPI_STATE_THREADED = 8,
	NAPI_STATE_SCHED_THREADED = 9,
};

struct netdev_queue {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct Qdisc *qdisc;
	struct Qdisc *qdisc_sleeping;
	struct kobject kobj;
	long unsigned int tx_maxrate;
	atomic_long_t trans_timeout;
	struct net_device *sb_dev;
	spinlock_t _xmit_lock;
	int xmit_lock_owner;
	long unsigned int trans_start;
	long unsigned int state;
	struct dql dql;
};

struct netdev_rx_queue {
	struct xdp_rxq_info xdp_rxq;
	struct kobject kobj;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct netdev_phys_item_id {
	unsigned char id[32];
	unsigned char id_len;
};

enum net_device_path_type {
	DEV_PATH_ETHERNET = 0,
	DEV_PATH_VLAN = 1,
	DEV_PATH_BRIDGE = 2,
	DEV_PATH_PPPOE = 3,
	DEV_PATH_DSA = 4,
};

struct net_device_path {
	enum net_device_path_type type;
	const struct net_device *dev;
	union {
		struct {
			u16 id;
			__be16 proto;
			u8 h_dest[6];
		} encap;
		struct {
			enum {
				DEV_PATH_BR_VLAN_KEEP = 0,
				DEV_PATH_BR_VLAN_TAG = 1,
				DEV_PATH_BR_VLAN_UNTAG = 2,
				DEV_PATH_BR_VLAN_UNTAG_HW = 3,
			} vlan_mode;
			u16 vlan_id;
			__be16 vlan_proto;
		} bridge;
		struct {
			int port;
			u16 proto;
		} dsa;
	};
};

struct net_device_path_ctx {
	const struct net_device *dev;
	const u8 *daddr;
	int num_vlans;
	struct {
		u16 id;
		__be16 proto;
	} vlan[2];
};

enum tc_setup_type {
	TC_SETUP_QDISC_MQPRIO = 0,
	TC_SETUP_CLSU32 = 1,
	TC_SETUP_CLSFLOWER = 2,
	TC_SETUP_CLSMATCHALL = 3,
	TC_SETUP_CLSBPF = 4,
	TC_SETUP_BLOCK = 5,
	TC_SETUP_QDISC_CBS = 6,
	TC_SETUP_QDISC_RED = 7,
	TC_SETUP_QDISC_PRIO = 8,
	TC_SETUP_QDISC_MQ = 9,
	TC_SETUP_QDISC_ETF = 10,
	TC_SETUP_ROOT_QDISC = 11,
	TC_SETUP_QDISC_GRED = 12,
	TC_SETUP_QDISC_TAPRIO = 13,
	TC_SETUP_FT = 14,
	TC_SETUP_QDISC_ETS = 15,
	TC_SETUP_QDISC_TBF = 16,
	TC_SETUP_QDISC_FIFO = 17,
	TC_SETUP_QDISC_HTB = 18,
	TC_SETUP_ACT = 19,
};

enum bpf_netdev_command {
	XDP_SETUP_PROG = 0,
	XDP_SETUP_PROG_HW = 1,
	BPF_OFFLOAD_MAP_ALLOC = 2,
	BPF_OFFLOAD_MAP_FREE = 3,
	XDP_SETUP_XSK_POOL = 4,
};

enum bpf_xdp_mode {
	XDP_MODE_SKB = 0,
	XDP_MODE_DRV = 1,
	XDP_MODE_HW = 2,
	__MAX_XDP_MODE = 3,
};

struct bpf_offloaded_map;

struct xsk_buff_pool;

struct netdev_bpf {
	enum bpf_netdev_command command;
	union {
		struct {
			u32 flags;
			struct bpf_prog *prog;
			struct netlink_ext_ack *extack;
		};
		struct {
			struct bpf_offloaded_map *offmap;
		};
		struct {
			struct xsk_buff_pool *pool;
			u16 queue_id;
		} xsk;
	};
};

struct dev_ifalias {
	struct callback_head rcuhead;
	char ifalias[0];
};

struct netdev_name_node {
	struct hlist_node hlist;
	struct list_head list;
	struct net_device *dev;
	const char *name;
};

struct devlink_port;

struct ip_tunnel_parm;

struct net_device_ops {
	int (*ndo_init)(struct net_device *);
	void (*ndo_uninit)(struct net_device *);
	int (*ndo_open)(struct net_device *);
	int (*ndo_stop)(struct net_device *);
	netdev_tx_t (*ndo_start_xmit)(struct sk_buff *, struct net_device *);
	netdev_features_t (*ndo_features_check)(struct sk_buff *, struct net_device *, netdev_features_t);
	u16 (*ndo_select_queue)(struct net_device *, struct sk_buff *, struct net_device *);
	void (*ndo_change_rx_flags)(struct net_device *, int);
	void (*ndo_set_rx_mode)(struct net_device *);
	int (*ndo_set_mac_address)(struct net_device *, void *);
	int (*ndo_validate_addr)(struct net_device *);
	int (*ndo_do_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_eth_ioctl)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocbond)(struct net_device *, struct ifreq *, int);
	int (*ndo_siocwandev)(struct net_device *, struct if_settings *);
	int (*ndo_siocdevprivate)(struct net_device *, struct ifreq *, void *, int);
	int (*ndo_set_config)(struct net_device *, struct ifmap *);
	int (*ndo_change_mtu)(struct net_device *, int);
	int (*ndo_neigh_setup)(struct net_device *, struct neigh_parms *);
	void (*ndo_tx_timeout)(struct net_device *, unsigned int);
	void (*ndo_get_stats64)(struct net_device *, struct rtnl_link_stats64 *);
	bool (*ndo_has_offload_stats)(const struct net_device *, int);
	int (*ndo_get_offload_stats)(int, const struct net_device *, void *);
	struct net_device_stats * (*ndo_get_stats)(struct net_device *);
	int (*ndo_vlan_rx_add_vid)(struct net_device *, __be16, u16);
	int (*ndo_vlan_rx_kill_vid)(struct net_device *, __be16, u16);
	int (*ndo_set_vf_mac)(struct net_device *, int, u8 *);
	int (*ndo_set_vf_vlan)(struct net_device *, int, u16, u8, __be16);
	int (*ndo_set_vf_rate)(struct net_device *, int, int, int);
	int (*ndo_set_vf_spoofchk)(struct net_device *, int, bool);
	int (*ndo_set_vf_trust)(struct net_device *, int, bool);
	int (*ndo_get_vf_config)(struct net_device *, int, struct ifla_vf_info *);
	int (*ndo_set_vf_link_state)(struct net_device *, int, int);
	int (*ndo_get_vf_stats)(struct net_device *, int, struct ifla_vf_stats *);
	int (*ndo_set_vf_port)(struct net_device *, int, struct nlattr **);
	int (*ndo_get_vf_port)(struct net_device *, int, struct sk_buff *);
	int (*ndo_get_vf_guid)(struct net_device *, int, struct ifla_vf_guid *, struct ifla_vf_guid *);
	int (*ndo_set_vf_guid)(struct net_device *, int, u64, int);
	int (*ndo_set_vf_rss_query_en)(struct net_device *, int, bool);
	int (*ndo_setup_tc)(struct net_device *, enum tc_setup_type, void *);
	int (*ndo_add_slave)(struct net_device *, struct net_device *, struct netlink_ext_ack *);
	int (*ndo_del_slave)(struct net_device *, struct net_device *);
	struct net_device * (*ndo_get_xmit_slave)(struct net_device *, struct sk_buff *, bool);
	struct net_device * (*ndo_sk_get_lower_dev)(struct net_device *, struct sock *);
	netdev_features_t (*ndo_fix_features)(struct net_device *, netdev_features_t);
	int (*ndo_set_features)(struct net_device *, netdev_features_t);
	int (*ndo_neigh_construct)(struct net_device *, struct neighbour *);
	void (*ndo_neigh_destroy)(struct net_device *, struct neighbour *);
	int (*ndo_fdb_add)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16, u16, struct netlink_ext_ack *);
	int (*ndo_fdb_del)(struct ndmsg *, struct nlattr **, struct net_device *, const unsigned char *, u16);
	int (*ndo_fdb_dump)(struct sk_buff *, struct netlink_callback *, struct net_device *, struct net_device *, int *);
	int (*ndo_fdb_get)(struct sk_buff *, struct nlattr **, struct net_device *, const unsigned char *, u16, u32, u32, struct netlink_ext_ack *);
	int (*ndo_bridge_setlink)(struct net_device *, struct nlmsghdr *, u16, struct netlink_ext_ack *);
	int (*ndo_bridge_getlink)(struct sk_buff *, u32, u32, struct net_device *, u32, int);
	int (*ndo_bridge_dellink)(struct net_device *, struct nlmsghdr *, u16);
	int (*ndo_change_carrier)(struct net_device *, bool);
	int (*ndo_get_phys_port_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_port_parent_id)(struct net_device *, struct netdev_phys_item_id *);
	int (*ndo_get_phys_port_name)(struct net_device *, char *, size_t);
	void * (*ndo_dfwd_add_station)(struct net_device *, struct net_device *);
	void (*ndo_dfwd_del_station)(struct net_device *, void *);
	int (*ndo_set_tx_maxrate)(struct net_device *, int, u32);
	int (*ndo_get_iflink)(const struct net_device *);
	int (*ndo_fill_metadata_dst)(struct net_device *, struct sk_buff *);
	void (*ndo_set_rx_headroom)(struct net_device *, int);
	int (*ndo_bpf)(struct net_device *, struct netdev_bpf *);
	int (*ndo_xdp_xmit)(struct net_device *, int, struct xdp_frame **, u32);
	struct net_device * (*ndo_xdp_get_xmit_slave)(struct net_device *, struct xdp_buff *);
	int (*ndo_xsk_wakeup)(struct net_device *, u32, u32);
	struct devlink_port * (*ndo_get_devlink_port)(struct net_device *);
	int (*ndo_tunnel_ctl)(struct net_device *, struct ip_tunnel_parm *, int);
	struct net_device * (*ndo_get_peer_dev)(struct net_device *);
	int (*ndo_fill_forward_path)(struct net_device_path_ctx *, struct net_device_path *);
};

struct neigh_parms {
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head list;
	int (*neigh_setup)(struct neighbour *);
	struct neigh_table *tbl;
	void *sysctl_table;
	int dead;
	refcount_t refcnt;
	struct callback_head callback_head;
	int reachable_time;
	int data[13];
	long unsigned int data_state[1];
};

struct pcpu_lstats {
	u64_stats_t packets;
	u64_stats_t bytes;
	struct u64_stats_sync syncp;
};

struct pcpu_sw_netstats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	struct u64_stats_sync syncp;
};

enum ethtool_phys_id_state {
	ETHTOOL_ID_INACTIVE = 0,
	ETHTOOL_ID_ACTIVE = 1,
	ETHTOOL_ID_ON = 2,
	ETHTOOL_ID_OFF = 3,
};

struct ethtool_drvinfo;

struct ethtool_regs;

struct ethtool_wolinfo;

struct ethtool_link_ext_state_info;

struct ethtool_eeprom;

struct ethtool_coalesce;

struct kernel_ethtool_coalesce;

struct ethtool_ringparam;

struct kernel_ethtool_ringparam;

struct ethtool_pause_stats;

struct ethtool_pauseparam;

struct ethtool_test;

struct ethtool_stats;

struct ethtool_rxnfc;

struct ethtool_flash;

struct ethtool_channels;

struct ethtool_dump;

struct ethtool_ts_info;

struct ethtool_modinfo;

struct ethtool_eee;

struct ethtool_tunable;

struct ethtool_link_ksettings;

struct ethtool_fec_stats;

struct ethtool_fecparam;

struct ethtool_module_eeprom;

struct ethtool_eth_phy_stats;

struct ethtool_eth_mac_stats;

struct ethtool_eth_ctrl_stats;

struct ethtool_rmon_stats;

struct ethtool_rmon_hist_range;

struct ethtool_module_power_mode_params;

struct ethtool_ops {
	u32 cap_link_lanes_supported: 1;
	u32 supported_coalesce_params;
	u32 supported_ring_params;
	void (*get_drvinfo)(struct net_device *, struct ethtool_drvinfo *);
	int (*get_regs_len)(struct net_device *);
	void (*get_regs)(struct net_device *, struct ethtool_regs *, void *);
	void (*get_wol)(struct net_device *, struct ethtool_wolinfo *);
	int (*set_wol)(struct net_device *, struct ethtool_wolinfo *);
	u32 (*get_msglevel)(struct net_device *);
	void (*set_msglevel)(struct net_device *, u32);
	int (*nway_reset)(struct net_device *);
	u32 (*get_link)(struct net_device *);
	int (*get_link_ext_state)(struct net_device *, struct ethtool_link_ext_state_info *);
	int (*get_eeprom_len)(struct net_device *);
	int (*get_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*set_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	int (*set_coalesce)(struct net_device *, struct ethtool_coalesce *, struct kernel_ethtool_coalesce *, struct netlink_ext_ack *);
	void (*get_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	int (*set_ringparam)(struct net_device *, struct ethtool_ringparam *, struct kernel_ethtool_ringparam *, struct netlink_ext_ack *);
	void (*get_pause_stats)(struct net_device *, struct ethtool_pause_stats *);
	void (*get_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	int (*set_pauseparam)(struct net_device *, struct ethtool_pauseparam *);
	void (*self_test)(struct net_device *, struct ethtool_test *, u64 *);
	void (*get_strings)(struct net_device *, u32, u8 *);
	int (*set_phys_id)(struct net_device *, enum ethtool_phys_id_state);
	void (*get_ethtool_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*begin)(struct net_device *);
	void (*complete)(struct net_device *);
	u32 (*get_priv_flags)(struct net_device *);
	int (*set_priv_flags)(struct net_device *, u32);
	int (*get_sset_count)(struct net_device *, int);
	int (*get_rxnfc)(struct net_device *, struct ethtool_rxnfc *, u32 *);
	int (*set_rxnfc)(struct net_device *, struct ethtool_rxnfc *);
	int (*flash_device)(struct net_device *, struct ethtool_flash *);
	int (*reset)(struct net_device *, u32 *);
	u32 (*get_rxfh_key_size)(struct net_device *);
	u32 (*get_rxfh_indir_size)(struct net_device *);
	int (*get_rxfh)(struct net_device *, u32 *, u8 *, u8 *);
	int (*set_rxfh)(struct net_device *, const u32 *, const u8 *, const u8);
	int (*get_rxfh_context)(struct net_device *, u32 *, u8 *, u8 *, u32);
	int (*set_rxfh_context)(struct net_device *, const u32 *, const u8 *, const u8, u32 *, bool);
	void (*get_channels)(struct net_device *, struct ethtool_channels *);
	int (*set_channels)(struct net_device *, struct ethtool_channels *);
	int (*get_dump_flag)(struct net_device *, struct ethtool_dump *);
	int (*get_dump_data)(struct net_device *, struct ethtool_dump *, void *);
	int (*set_dump)(struct net_device *, struct ethtool_dump *);
	int (*get_ts_info)(struct net_device *, struct ethtool_ts_info *);
	int (*get_module_info)(struct net_device *, struct ethtool_modinfo *);
	int (*get_module_eeprom)(struct net_device *, struct ethtool_eeprom *, u8 *);
	int (*get_eee)(struct net_device *, struct ethtool_eee *);
	int (*set_eee)(struct net_device *, struct ethtool_eee *);
	int (*get_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*set_per_queue_coalesce)(struct net_device *, u32, struct ethtool_coalesce *);
	int (*get_link_ksettings)(struct net_device *, struct ethtool_link_ksettings *);
	int (*set_link_ksettings)(struct net_device *, const struct ethtool_link_ksettings *);
	void (*get_fec_stats)(struct net_device *, struct ethtool_fec_stats *);
	int (*get_fecparam)(struct net_device *, struct ethtool_fecparam *);
	int (*set_fecparam)(struct net_device *, struct ethtool_fecparam *);
	void (*get_ethtool_phy_stats)(struct net_device *, struct ethtool_stats *, u64 *);
	int (*get_phy_tunable)(struct net_device *, const struct ethtool_tunable *, void *);
	int (*set_phy_tunable)(struct net_device *, const struct ethtool_tunable *, const void *);
	int (*get_module_eeprom_by_page)(struct net_device *, const struct ethtool_module_eeprom *, struct netlink_ext_ack *);
	void (*get_eth_phy_stats)(struct net_device *, struct ethtool_eth_phy_stats *);
	void (*get_eth_mac_stats)(struct net_device *, struct ethtool_eth_mac_stats *);
	void (*get_eth_ctrl_stats)(struct net_device *, struct ethtool_eth_ctrl_stats *);
	void (*get_rmon_stats)(struct net_device *, struct ethtool_rmon_stats *, const struct ethtool_rmon_hist_range **);
	int (*get_module_power_mode)(struct net_device *, struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
	int (*set_module_power_mode)(struct net_device *, const struct ethtool_module_power_mode_params *, struct netlink_ext_ack *);
};

struct ipv6_devstat {
	struct proc_dir_entry *proc_dir_entry;
	struct ipstats_mib *ipv6;
	struct icmpv6_mib_device *icmpv6dev;
	struct icmpv6msg_mib_device *icmpv6msgdev;
};

struct ifmcaddr6;

struct ifacaddr6;

struct inet6_dev {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct list_head addr_list;
	struct ifmcaddr6 *mc_list;
	struct ifmcaddr6 *mc_tomb;
	unsigned char mc_qrv;
	unsigned char mc_gq_running;
	unsigned char mc_ifc_count;
	unsigned char mc_dad_count;
	long unsigned int mc_v1_seen;
	long unsigned int mc_qi;
	long unsigned int mc_qri;
	long unsigned int mc_maxdelay;
	struct delayed_work mc_gq_work;
	struct delayed_work mc_ifc_work;
	struct delayed_work mc_dad_work;
	struct delayed_work mc_query_work;
	struct delayed_work mc_report_work;
	struct sk_buff_head mc_query_queue;
	struct sk_buff_head mc_report_queue;
	spinlock_t mc_query_lock;
	spinlock_t mc_report_lock;
	struct mutex mc_lock;
	struct ifacaddr6 *ac_list;
	rwlock_t lock;
	refcount_t refcnt;
	__u32 if_flags;
	int dead;
	u32 desync_factor;
	struct list_head tempaddr_list;
	struct in6_addr token;
	struct neigh_parms *nd_parms;
	struct ipv6_devconf cnf;
	struct ipv6_devstat stats;
	struct timer_list rs_timer;
	__s32 rs_interval;
	__u8 rs_probes;
	long unsigned int tstamp;
	struct callback_head rcu;
	unsigned int ra_mtu;
};

struct rtnl_link_ops {
	struct list_head list;
	const char *kind;
	size_t priv_size;
	struct net_device * (*alloc)(struct nlattr **, const char *, unsigned char, unsigned int, unsigned int);
	void (*setup)(struct net_device *);
	bool netns_refund;
	unsigned int maxtype;
	const struct nla_policy *policy;
	int (*validate)(struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*newlink)(struct net *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	int (*changelink)(struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	void (*dellink)(struct net_device *, struct list_head *);
	size_t (*get_size)(const struct net_device *);
	int (*fill_info)(struct sk_buff *, const struct net_device *);
	size_t (*get_xstats_size)(const struct net_device *);
	int (*fill_xstats)(struct sk_buff *, const struct net_device *);
	unsigned int (*get_num_tx_queues)();
	unsigned int (*get_num_rx_queues)();
	unsigned int slave_maxtype;
	const struct nla_policy *slave_policy;
	int (*slave_changelink)(struct net_device *, struct net_device *, struct nlattr **, struct nlattr **, struct netlink_ext_ack *);
	size_t (*get_slave_size)(const struct net_device *, const struct net_device *);
	int (*fill_slave_info)(struct sk_buff *, const struct net_device *, const struct net_device *);
	struct net * (*get_link_net)(const struct net_device *);
	size_t (*get_linkxstats_size)(const struct net_device *, int);
	int (*fill_linkxstats)(struct sk_buff *, const struct net_device *, int *, int);
};

struct udp_tunnel_nic_table_info {
	unsigned int n_entries;
	unsigned int tunnel_types;
};

struct udp_tunnel_info;

struct udp_tunnel_nic_shared;

struct udp_tunnel_nic_info {
	int (*set_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*unset_port)(struct net_device *, unsigned int, unsigned int, struct udp_tunnel_info *);
	int (*sync_table)(struct net_device *, unsigned int);
	struct udp_tunnel_nic_shared *shared;
	unsigned int flags;
	struct udp_tunnel_nic_table_info tables[4];
};

enum {
	NETIF_MSG_DRV_BIT = 0,
	NETIF_MSG_PROBE_BIT = 1,
	NETIF_MSG_LINK_BIT = 2,
	NETIF_MSG_TIMER_BIT = 3,
	NETIF_MSG_IFDOWN_BIT = 4,
	NETIF_MSG_IFUP_BIT = 5,
	NETIF_MSG_RX_ERR_BIT = 6,
	NETIF_MSG_TX_ERR_BIT = 7,
	NETIF_MSG_TX_QUEUED_BIT = 8,
	NETIF_MSG_INTR_BIT = 9,
	NETIF_MSG_TX_DONE_BIT = 10,
	NETIF_MSG_RX_STATUS_BIT = 11,
	NETIF_MSG_PKTDATA_BIT = 12,
	NETIF_MSG_HW_BIT = 13,
	NETIF_MSG_WOL_BIT = 14,
	NETIF_MSG_CLASS_COUNT = 15,
};

enum {
	RTAX_UNSPEC = 0,
	RTAX_LOCK = 1,
	RTAX_MTU = 2,
	RTAX_WINDOW = 3,
	RTAX_RTT = 4,
	RTAX_RTTVAR = 5,
	RTAX_SSTHRESH = 6,
	RTAX_CWND = 7,
	RTAX_ADVMSS = 8,
	RTAX_REORDERING = 9,
	RTAX_HOPLIMIT = 10,
	RTAX_INITCWND = 11,
	RTAX_FEATURES = 12,
	RTAX_RTO_MIN = 13,
	RTAX_INITRWND = 14,
	RTAX_QUICKACK = 15,
	RTAX_CC_ALGO = 16,
	RTAX_FASTOPEN_NO_COOKIE = 17,
	__RTAX_MAX = 18,
};

struct netlink_range_validation {
	u64 min;
	u64 max;
};

struct netlink_range_validation_signed {
	s64 min;
	s64 max;
};

enum {
	NEIGH_VAR_MCAST_PROBES = 0,
	NEIGH_VAR_UCAST_PROBES = 1,
	NEIGH_VAR_APP_PROBES = 2,
	NEIGH_VAR_MCAST_REPROBES = 3,
	NEIGH_VAR_RETRANS_TIME = 4,
	NEIGH_VAR_BASE_REACHABLE_TIME = 5,
	NEIGH_VAR_DELAY_PROBE_TIME = 6,
	NEIGH_VAR_GC_STALETIME = 7,
	NEIGH_VAR_QUEUE_LEN_BYTES = 8,
	NEIGH_VAR_PROXY_QLEN = 9,
	NEIGH_VAR_ANYCAST_DELAY = 10,
	NEIGH_VAR_PROXY_DELAY = 11,
	NEIGH_VAR_LOCKTIME = 12,
	NEIGH_VAR_QUEUE_LEN = 13,
	NEIGH_VAR_RETRANS_TIME_MS = 14,
	NEIGH_VAR_BASE_REACHABLE_TIME_MS = 15,
	NEIGH_VAR_GC_INTERVAL = 16,
	NEIGH_VAR_GC_THRESH1 = 17,
	NEIGH_VAR_GC_THRESH2 = 18,
	NEIGH_VAR_GC_THRESH3 = 19,
	NEIGH_VAR_MAX = 20,
};

struct pneigh_entry;

struct neigh_statistics;

struct neigh_hash_table;

struct neigh_table {
	int family;
	unsigned int entry_size;
	unsigned int key_len;
	__be16 protocol;
	__u32 (*hash)(const void *, const struct net_device *, __u32 *);
	bool (*key_eq)(const struct neighbour *, const void *);
	int (*constructor)(struct neighbour *);
	int (*pconstructor)(struct pneigh_entry *);
	void (*pdestructor)(struct pneigh_entry *);
	void (*proxy_redo)(struct sk_buff *);
	int (*is_multicast)(const void *);
	bool (*allow_add)(const struct net_device *, struct netlink_ext_ack *);
	char *id;
	struct neigh_parms parms;
	struct list_head parms_list;
	int gc_interval;
	int gc_thresh1;
	int gc_thresh2;
	int gc_thresh3;
	long unsigned int last_flush;
	struct delayed_work gc_work;
	struct delayed_work managed_work;
	struct timer_list proxy_timer;
	struct sk_buff_head proxy_queue;
	atomic_t entries;
	atomic_t gc_entries;
	struct list_head gc_list;
	struct list_head managed_list;
	rwlock_t lock;
	long unsigned int last_rand;
	struct neigh_statistics *stats;
	struct neigh_hash_table *nht;
	struct pneigh_entry **phash_buckets;
};

struct neigh_statistics {
	long unsigned int allocs;
	long unsigned int destroys;
	long unsigned int hash_grows;
	long unsigned int res_failed;
	long unsigned int lookups;
	long unsigned int hits;
	long unsigned int rcv_probes_mcast;
	long unsigned int rcv_probes_ucast;
	long unsigned int periodic_gc_runs;
	long unsigned int forced_gc_runs;
	long unsigned int unres_discards;
	long unsigned int table_fulls;
};

struct neigh_ops {
	int family;
	void (*solicit)(struct neighbour *, struct sk_buff *);
	void (*error_report)(struct neighbour *, struct sk_buff *);
	int (*output)(struct neighbour *, struct sk_buff *);
	int (*connected_output)(struct neighbour *, struct sk_buff *);
};

struct pneigh_entry {
	struct pneigh_entry *next;
	possible_net_t net;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	u32 flags;
	u8 protocol;
	u8 key[0];
};

struct neigh_hash_table {
	struct neighbour **hash_buckets;
	unsigned int hash_shift;
	__u32 hash_rnd[4];
	struct callback_head rcu;
};

enum {
	TCP_ESTABLISHED = 1,
	TCP_SYN_SENT = 2,
	TCP_SYN_RECV = 3,
	TCP_FIN_WAIT1 = 4,
	TCP_FIN_WAIT2 = 5,
	TCP_TIME_WAIT = 6,
	TCP_CLOSE = 7,
	TCP_CLOSE_WAIT = 8,
	TCP_LAST_ACK = 9,
	TCP_LISTEN = 10,
	TCP_CLOSING = 11,
	TCP_NEW_SYN_RECV = 12,
	TCP_MAX_STATES = 13,
};

struct smc_hashinfo;

struct sk_psock;

struct request_sock_ops;

struct timewait_sock_ops;

struct udp_table;

struct raw_hashinfo;

struct proto {
	void (*close)(struct sock *, long int);
	int (*pre_connect)(struct sock *, struct sockaddr *, int);
	int (*connect)(struct sock *, struct sockaddr *, int);
	int (*disconnect)(struct sock *, int);
	struct sock * (*accept)(struct sock *, int, int *, bool);
	int (*ioctl)(struct sock *, int, long unsigned int);
	int (*init)(struct sock *);
	void (*destroy)(struct sock *);
	void (*shutdown)(struct sock *, int);
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*keepalive)(struct sock *, int);
	int (*sendmsg)(struct sock *, struct msghdr *, size_t);
	int (*recvmsg)(struct sock *, struct msghdr *, size_t, int, int, int *);
	int (*sendpage)(struct sock *, struct page *, int, size_t, int);
	int (*bind)(struct sock *, struct sockaddr *, int);
	int (*bind_add)(struct sock *, struct sockaddr *, int);
	int (*backlog_rcv)(struct sock *, struct sk_buff *);
	bool (*bpf_bypass_getsockopt)(int, int);
	void (*release_cb)(struct sock *);
	int (*hash)(struct sock *);
	void (*unhash)(struct sock *);
	void (*rehash)(struct sock *);
	int (*get_port)(struct sock *, short unsigned int);
	void (*put_port)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	unsigned int inuse_idx;
	bool (*stream_memory_free)(const struct sock *, int);
	bool (*sock_is_readable)(struct sock *);
	void (*enter_memory_pressure)(struct sock *);
	void (*leave_memory_pressure)(struct sock *);
	atomic_long_t *memory_allocated;
	struct percpu_counter *sockets_allocated;
	long unsigned int *memory_pressure;
	long int *sysctl_mem;
	int *sysctl_wmem;
	int *sysctl_rmem;
	u32 sysctl_wmem_offset;
	u32 sysctl_rmem_offset;
	int max_header;
	bool no_autobind;
	struct kmem_cache *slab;
	unsigned int obj_size;
	slab_flags_t slab_flags;
	unsigned int useroffset;
	unsigned int usersize;
	unsigned int *orphan_count;
	struct request_sock_ops *rsk_prot;
	struct timewait_sock_ops *twsk_prot;
	union {
		struct inet_hashinfo *hashinfo;
		struct udp_table *udp_table;
		struct raw_hashinfo *raw_hash;
		struct smc_hashinfo *smc_hash;
	} h;
	struct module *owner;
	char name[32];
	struct list_head node;
	int (*diag_destroy)(struct sock *, int);
};

struct request_sock;

struct request_sock_ops {
	int family;
	unsigned int obj_size;
	struct kmem_cache *slab;
	char *slab_name;
	int (*rtx_syn_ack)(const struct sock *, struct request_sock *);
	void (*send_ack)(const struct sock *, struct sk_buff *, struct request_sock *);
	void (*send_reset)(const struct sock *, struct sk_buff *);
	void (*destructor)(struct request_sock *);
	void (*syn_ack_timeout)(const struct request_sock *);
};

struct timewait_sock_ops {
	struct kmem_cache *twsk_slab;
	char *twsk_slab_name;
	unsigned int twsk_obj_size;
	int (*twsk_unique)(struct sock *, struct sock *, void *);
	void (*twsk_destructor)(struct sock *);
};

struct saved_syn;

struct request_sock {
	struct sock_common __req_common;
	struct request_sock *dl_next;
	u16 mss;
	u8 num_retrans;
	u8 syncookie: 1;
	u8 num_timeout: 7;
	u32 ts_recent;
	struct timer_list rsk_timer;
	const struct request_sock_ops *rsk_ops;
	struct sock *sk;
	struct saved_syn *saved_syn;
	u32 secid;
	u32 peer_secid;
	u32 timeout;
};

struct saved_syn {
	u32 mac_hdrlen;
	u32 network_hdrlen;
	u32 tcp_hdrlen;
	u8 data[0];
};

enum tsq_enum {
	TSQ_THROTTLED = 0,
	TSQ_QUEUED = 1,
	TCP_TSQ_DEFERRED = 2,
	TCP_WRITE_TIMER_DEFERRED = 3,
	TCP_DELACK_TIMER_DEFERRED = 4,
	TCP_MTU_REDUCED_DEFERRED = 5,
};

struct ip6_sf_list {
	struct ip6_sf_list *sf_next;
	struct in6_addr sf_addr;
	long unsigned int sf_count[2];
	unsigned char sf_gsresp;
	unsigned char sf_oldin;
	unsigned char sf_crcount;
	struct callback_head rcu;
};

struct ifmcaddr6 {
	struct in6_addr mca_addr;
	struct inet6_dev *idev;
	struct ifmcaddr6 *next;
	struct ip6_sf_list *mca_sources;
	struct ip6_sf_list *mca_tomb;
	unsigned int mca_sfmode;
	unsigned char mca_crcount;
	long unsigned int mca_sfcount[2];
	struct delayed_work mca_work;
	unsigned int mca_flags;
	int mca_users;
	refcount_t mca_refcnt;
	long unsigned int mca_cstamp;
	long unsigned int mca_tstamp;
	struct callback_head rcu;
};

struct fib6_info;

struct ifacaddr6 {
	struct in6_addr aca_addr;
	struct fib6_info *aca_rt;
	struct ifacaddr6 *aca_next;
	struct hlist_node aca_addr_lst;
	int aca_users;
	refcount_t aca_refcnt;
	long unsigned int aca_cstamp;
	long unsigned int aca_tstamp;
	struct callback_head rcu;
};

enum nfs_opnum4 {
	OP_ACCESS = 3,
	OP_CLOSE = 4,
	OP_COMMIT = 5,
	OP_CREATE = 6,
	OP_DELEGPURGE = 7,
	OP_DELEGRETURN = 8,
	OP_GETATTR = 9,
	OP_GETFH = 10,
	OP_LINK = 11,
	OP_LOCK = 12,
	OP_LOCKT = 13,
	OP_LOCKU = 14,
	OP_LOOKUP = 15,
	OP_LOOKUPP = 16,
	OP_NVERIFY = 17,
	OP_OPEN = 18,
	OP_OPENATTR = 19,
	OP_OPEN_CONFIRM = 20,
	OP_OPEN_DOWNGRADE = 21,
	OP_PUTFH = 22,
	OP_PUTPUBFH = 23,
	OP_PUTROOTFH = 24,
	OP_READ = 25,
	OP_READDIR = 26,
	OP_READLINK = 27,
	OP_REMOVE = 28,
	OP_RENAME = 29,
	OP_RENEW = 30,
	OP_RESTOREFH = 31,
	OP_SAVEFH = 32,
	OP_SECINFO = 33,
	OP_SETATTR = 34,
	OP_SETCLIENTID = 35,
	OP_SETCLIENTID_CONFIRM = 36,
	OP_VERIFY = 37,
	OP_WRITE = 38,
	OP_RELEASE_LOCKOWNER = 39,
	OP_BACKCHANNEL_CTL = 40,
	OP_BIND_CONN_TO_SESSION = 41,
	OP_EXCHANGE_ID = 42,
	OP_CREATE_SESSION = 43,
	OP_DESTROY_SESSION = 44,
	OP_FREE_STATEID = 45,
	OP_GET_DIR_DELEGATION = 46,
	OP_GETDEVICEINFO = 47,
	OP_GETDEVICELIST = 48,
	OP_LAYOUTCOMMIT = 49,
	OP_LAYOUTGET = 50,
	OP_LAYOUTRETURN = 51,
	OP_SECINFO_NO_NAME = 52,
	OP_SEQUENCE = 53,
	OP_SET_SSV = 54,
	OP_TEST_STATEID = 55,
	OP_WANT_DELEGATION = 56,
	OP_DESTROY_CLIENTID = 57,
	OP_RECLAIM_COMPLETE = 58,
	OP_ALLOCATE = 59,
	OP_COPY = 60,
	OP_COPY_NOTIFY = 61,
	OP_DEALLOCATE = 62,
	OP_IO_ADVISE = 63,
	OP_LAYOUTERROR = 64,
	OP_LAYOUTSTATS = 65,
	OP_OFFLOAD_CANCEL = 66,
	OP_OFFLOAD_STATUS = 67,
	OP_READ_PLUS = 68,
	OP_SEEK = 69,
	OP_WRITE_SAME = 70,
	OP_CLONE = 71,
	OP_GETXATTR = 72,
	OP_SETXATTR = 73,
	OP_LISTXATTRS = 74,
	OP_REMOVEXATTR = 75,
	OP_ILLEGAL = 10044,
};

enum {
	UNAME26 = 131072,
	ADDR_NO_RANDOMIZE = 262144,
	FDPIC_FUNCPTRS = 524288,
	MMAP_PAGE_ZERO = 1048576,
	ADDR_COMPAT_LAYOUT = 2097152,
	READ_IMPLIES_EXEC = 4194304,
	ADDR_LIMIT_32BIT = 8388608,
	SHORT_INODE = 16777216,
	WHOLE_SECONDS = 33554432,
	STICKY_TIMEOUTS = 67108864,
	ADDR_LIMIT_3GB = 134217728,
};

enum perf_branch_sample_type_shift {
	PERF_SAMPLE_BRANCH_USER_SHIFT = 0,
	PERF_SAMPLE_BRANCH_KERNEL_SHIFT = 1,
	PERF_SAMPLE_BRANCH_HV_SHIFT = 2,
	PERF_SAMPLE_BRANCH_ANY_SHIFT = 3,
	PERF_SAMPLE_BRANCH_ANY_CALL_SHIFT = 4,
	PERF_SAMPLE_BRANCH_ANY_RETURN_SHIFT = 5,
	PERF_SAMPLE_BRANCH_IND_CALL_SHIFT = 6,
	PERF_SAMPLE_BRANCH_ABORT_TX_SHIFT = 7,
	PERF_SAMPLE_BRANCH_IN_TX_SHIFT = 8,
	PERF_SAMPLE_BRANCH_NO_TX_SHIFT = 9,
	PERF_SAMPLE_BRANCH_COND_SHIFT = 10,
	PERF_SAMPLE_BRANCH_CALL_STACK_SHIFT = 11,
	PERF_SAMPLE_BRANCH_IND_JUMP_SHIFT = 12,
	PERF_SAMPLE_BRANCH_CALL_SHIFT = 13,
	PERF_SAMPLE_BRANCH_NO_FLAGS_SHIFT = 14,
	PERF_SAMPLE_BRANCH_NO_CYCLES_SHIFT = 15,
	PERF_SAMPLE_BRANCH_TYPE_SAVE_SHIFT = 16,
	PERF_SAMPLE_BRANCH_HW_INDEX_SHIFT = 17,
	PERF_SAMPLE_BRANCH_MAX_SHIFT = 18,
};

enum {
	TSK_TRACE_FL_TRACE_BIT = 0,
	TSK_TRACE_FL_GRAPH_BIT = 1,
};

struct uuidcmp {
	const char *uuid;
	int len;
};

typedef void *va_list;

enum umh_disable_depth {
	UMH_ENABLED = 0,
	UMH_FREEZING = 1,
	UMH_DISABLED = 2,
};

typedef u64 async_cookie_t;

typedef void (*async_func_t)(void *, async_cookie_t);

struct async_domain {
	struct list_head pending;
	unsigned int registered: 1;
};

struct hash {
	int ino;
	int minor;
	int major;
	umode_t mode;
	struct hash *next;
	char name[4098];
};

struct dir_entry {
	struct list_head list;
	char *name;
	time64_t mtime;
};

enum state {
	Start = 0,
	Collect = 1,
	GotHeader = 2,
	SkipIt = 3,
	GotName = 4,
	CopyFile = 5,
	GotSymlink = 6,
	Reset = 7,
};

typedef int (*decompress_fn)(unsigned char *, long int, long int (*)(void *, long unsigned int), long int (*)(void *, long unsigned int), unsigned char *, long int *, void (*)(char *));

enum migratetype {
	MIGRATE_UNMOVABLE = 0,
	MIGRATE_MOVABLE = 1,
	MIGRATE_RECLAIMABLE = 2,
	MIGRATE_PCPTYPES = 3,
	MIGRATE_HIGHATOMIC = 3,
	MIGRATE_TYPES = 4,
};

enum zone_stat_item {
	NR_FREE_PAGES = 0,
	NR_ZONE_LRU_BASE = 1,
	NR_ZONE_INACTIVE_ANON = 1,
	NR_ZONE_ACTIVE_ANON = 2,
	NR_ZONE_INACTIVE_FILE = 3,
	NR_ZONE_ACTIVE_FILE = 4,
	NR_ZONE_UNEVICTABLE = 5,
	NR_ZONE_WRITE_PENDING = 6,
	NR_MLOCK = 7,
	NR_BOUNCE = 8,
	NR_FREE_CMA_PAGES = 9,
	NR_VM_ZONE_STAT_ITEMS = 10,
};

enum lru_list {
	LRU_INACTIVE_ANON = 0,
	LRU_ACTIVE_ANON = 1,
	LRU_INACTIVE_FILE = 2,
	LRU_ACTIVE_FILE = 3,
	LRU_UNEVICTABLE = 4,
	NR_LRU_LISTS = 5,
};

enum vmscan_throttle_state {
	VMSCAN_THROTTLE_WRITEBACK = 0,
	VMSCAN_THROTTLE_ISOLATED = 1,
	VMSCAN_THROTTLE_NOPROGRESS = 2,
	VMSCAN_THROTTLE_CONGESTED = 3,
	NR_VMSCAN_THROTTLE = 4,
};

enum zone_watermarks {
	WMARK_MIN = 0,
	WMARK_LOW = 1,
	WMARK_HIGH = 2,
	WMARK_PROMO = 3,
	NR_WMARK = 4,
};

enum {
	ZONELIST_FALLBACK = 0,
	MAX_ZONELISTS = 1,
};

enum {
	HI_SOFTIRQ = 0,
	TIMER_SOFTIRQ = 1,
	NET_TX_SOFTIRQ = 2,
	NET_RX_SOFTIRQ = 3,
	BLOCK_SOFTIRQ = 4,
	IRQ_POLL_SOFTIRQ = 5,
	TASKLET_SOFTIRQ = 6,
	SCHED_SOFTIRQ = 7,
	HRTIMER_SOFTIRQ = 8,
	RCU_SOFTIRQ = 9,
	NR_SOFTIRQS = 10,
};

enum {
	DQF_ROOT_SQUASH_B = 0,
	DQF_SYS_FILE_B = 16,
	DQF_PRIVATE = 17,
};

enum {
	DQST_LOOKUPS = 0,
	DQST_DROPS = 1,
	DQST_READS = 2,
	DQST_WRITES = 3,
	DQST_CACHE_HITS = 4,
	DQST_ALLOC_DQUOTS = 5,
	DQST_FREE_DQUOTS = 6,
	DQST_SYNCS = 7,
	_DQST_DQSTAT_LAST = 8,
};

enum {
	SB_UNFROZEN = 0,
	SB_FREEZE_WRITE = 1,
	SB_FREEZE_PAGEFAULT = 2,
	SB_FREEZE_FS = 3,
	SB_FREEZE_COMPLETE = 4,
};

enum compound_dtor_id {
	NULL_COMPOUND_DTOR = 0,
	COMPOUND_PAGE_DTOR = 1,
	NR_COMPOUND_DTORS = 2,
};

enum vm_event_item {
	PGPGIN = 0,
	PGPGOUT = 1,
	PSWPIN = 2,
	PSWPOUT = 3,
	PGALLOC_NORMAL = 4,
	PGALLOC_MOVABLE = 5,
	ALLOCSTALL_NORMAL = 6,
	ALLOCSTALL_MOVABLE = 7,
	PGSCAN_SKIP_NORMAL = 8,
	PGSCAN_SKIP_MOVABLE = 9,
	PGFREE = 10,
	PGACTIVATE = 11,
	PGDEACTIVATE = 12,
	PGLAZYFREE = 13,
	PGFAULT = 14,
	PGMAJFAULT = 15,
	PGLAZYFREED = 16,
	PGREFILL = 17,
	PGREUSE = 18,
	PGSTEAL_KSWAPD = 19,
	PGSTEAL_DIRECT = 20,
	PGDEMOTE_KSWAPD = 21,
	PGDEMOTE_DIRECT = 22,
	PGSCAN_KSWAPD = 23,
	PGSCAN_DIRECT = 24,
	PGSCAN_DIRECT_THROTTLE = 25,
	PGSCAN_ANON = 26,
	PGSCAN_FILE = 27,
	PGSTEAL_ANON = 28,
	PGSTEAL_FILE = 29,
	PGINODESTEAL = 30,
	SLABS_SCANNED = 31,
	KSWAPD_INODESTEAL = 32,
	KSWAPD_LOW_WMARK_HIT_QUICKLY = 33,
	KSWAPD_HIGH_WMARK_HIT_QUICKLY = 34,
	PAGEOUTRUN = 35,
	PGROTATED = 36,
	DROP_PAGECACHE = 37,
	DROP_SLAB = 38,
	OOM_KILL = 39,
	UNEVICTABLE_PGCULLED = 40,
	UNEVICTABLE_PGSCANNED = 41,
	UNEVICTABLE_PGRESCUED = 42,
	UNEVICTABLE_PGMLOCKED = 43,
	UNEVICTABLE_PGMUNLOCKED = 44,
	UNEVICTABLE_PGCLEARED = 45,
	UNEVICTABLE_PGSTRANDED = 46,
	NR_VM_EVENT_ITEMS = 47,
};

enum ucount_type {
	UCOUNT_USER_NAMESPACES = 0,
	UCOUNT_PID_NAMESPACES = 1,
	UCOUNT_UTS_NAMESPACES = 2,
	UCOUNT_IPC_NAMESPACES = 3,
	UCOUNT_NET_NAMESPACES = 4,
	UCOUNT_MNT_NAMESPACES = 5,
	UCOUNT_CGROUP_NAMESPACES = 6,
	UCOUNT_TIME_NAMESPACES = 7,
	UCOUNT_INOTIFY_INSTANCES = 8,
	UCOUNT_INOTIFY_WATCHES = 9,
	UCOUNT_RLIMIT_NPROC = 10,
	UCOUNT_RLIMIT_MSGQUEUE = 11,
	UCOUNT_RLIMIT_SIGPENDING = 12,
	UCOUNT_RLIMIT_MEMLOCK = 13,
	UCOUNT_COUNTS = 14,
};

struct bcr_identity {
	unsigned int family: 8;
	unsigned int cpu_id: 8;
	unsigned int chip_id: 16;
};

struct bcr_isa_arcv2 {
	unsigned int ver: 8;
	unsigned int pad1: 12;
	unsigned int be: 1;
	unsigned int atomic: 1;
	unsigned int unalign: 1;
	unsigned int ldd: 1;
	unsigned int pad2: 4;
	unsigned int div_rem: 4;
};

struct bcr_uarch_build_arcv2 {
	unsigned int min: 8;
	unsigned int maj: 8;
	unsigned int prod: 8;
	unsigned int pad: 8;
};

struct bcr_mpy {
	unsigned int ver: 8;
	unsigned int type: 2;
	unsigned int cycles: 2;
	unsigned int dsp: 4;
	unsigned int x1616: 8;
	unsigned int pad: 8;
};

struct bcr_iccm_arcompact {
	unsigned int ver: 8;
	unsigned int sz: 3;
	unsigned int pad: 5;
	unsigned int base: 16;
};

struct bcr_iccm_arcv2 {
	unsigned int ver: 8;
	unsigned int sz00: 4;
	unsigned int sz10: 4;
	unsigned int sz01: 4;
	unsigned int sz11: 4;
	unsigned int pad: 8;
};

struct bcr_dccm_arcompact {
	unsigned int ver: 8;
	unsigned int sz: 3;
	unsigned int res: 21;
};

struct bcr_dccm_arcv2 {
	unsigned int ver: 8;
	unsigned int sz0: 4;
	unsigned int sz1: 4;
	unsigned int pad1: 1;
	unsigned int cyc: 3;
	unsigned int pad2: 12;
};

struct bcr_fp_arcompact {
	unsigned int ver: 8;
	unsigned int fast: 1;
};

struct bcr_fp_arcv2 {
	unsigned int ver: 8;
	unsigned int sp: 1;
	unsigned int pad1: 7;
	unsigned int dp: 1;
	unsigned int pad2: 15;
};

struct bcr_actionpoint {
	unsigned int ver: 8;
	unsigned int num: 2;
	unsigned int min: 1;
	unsigned int pad: 21;
};

struct bcr_timer {
	unsigned int ver: 8;
	unsigned int t0: 1;
	unsigned int t1: 1;
	unsigned int rtc: 1;
	unsigned int pad1: 5;
	unsigned int rtsc: 1;
	unsigned int pad2: 15;
};

struct bcr_bpu_arcompact {
	unsigned int ver: 8;
	unsigned int ent: 2;
	unsigned int pad: 2;
	unsigned int fam: 1;
	unsigned int pad2: 19;
};

struct bcr_bpu_arcv2 {
	unsigned int ver: 8;
	unsigned int bce: 3;
	unsigned int pte: 3;
	unsigned int rse: 2;
	unsigned int ft: 1;
	unsigned int ts: 4;
	unsigned int tqe: 2;
	unsigned int fbe: 2;
	unsigned int pad: 6;
};

struct bcr_erp {
	unsigned int ver: 8;
	unsigned int pad1: 6;
	unsigned int dc: 3;
	unsigned int ic: 3;
	unsigned int pad2: 4;
	unsigned int mmu: 3;
	unsigned int pad3: 5;
};

struct ctl_erp {
	unsigned int dpi: 1;
	unsigned int dpd: 1;
	unsigned int pad1: 2;
	unsigned int mpd: 1;
	unsigned int pad2: 27;
};

struct bcr_lpb {
	unsigned int ver: 8;
	unsigned int entries: 8;
	unsigned int pad: 16;
};

struct bcr_generic {
	unsigned int ver: 8;
	unsigned int info: 24;
};

struct cpuinfo_arc_mmu {
	unsigned int ver: 4;
	unsigned int pg_sz_k: 8;
	unsigned int s_pg_sz_m: 8;
	unsigned int pad: 10;
	unsigned int sasid: 1;
	unsigned int pae: 1;
	unsigned int sets: 12;
	unsigned int ways: 4;
	unsigned int u_dtlb: 8;
	unsigned int u_itlb: 8;
};

struct cpuinfo_arc_cache {
	unsigned int sz_k: 14;
	unsigned int line_len: 8;
	unsigned int assoc: 4;
	unsigned int alias: 1;
	unsigned int vipt: 1;
	unsigned int pad: 4;
};

struct cpuinfo_arc_bpu {
	unsigned int ver;
	unsigned int full;
	unsigned int num_cache;
	unsigned int num_pred;
	unsigned int ret_stk;
};

struct cpuinfo_arc_ccm {
	unsigned int base_addr;
	unsigned int sz;
};

struct cpuinfo_arc {
	struct cpuinfo_arc_cache icache;
	struct cpuinfo_arc_cache dcache;
	struct cpuinfo_arc_cache slc;
	struct cpuinfo_arc_mmu mmu;
	struct cpuinfo_arc_bpu bpu;
	struct bcr_identity core;
	struct bcr_isa_arcv2 isa;
	const char *release;
	const char *name;
	unsigned int vec_base;
	struct cpuinfo_arc_ccm iccm;
	struct cpuinfo_arc_ccm dccm;
	struct {
		unsigned int swap: 1;
		unsigned int norm: 1;
		unsigned int minmax: 1;
		unsigned int barrel: 1;
		unsigned int crc: 1;
		unsigned int swape: 1;
		unsigned int pad1: 2;
		unsigned int fpu_sp: 1;
		unsigned int fpu_dp: 1;
		unsigned int dual: 1;
		unsigned int dual_enb: 1;
		unsigned int pad2: 4;
		unsigned int ap_num: 4;
		unsigned int ap_full: 1;
		unsigned int smart: 1;
		unsigned int rtt: 1;
		unsigned int pad3: 1;
		unsigned int timer0: 1;
		unsigned int timer1: 1;
		unsigned int rtc: 1;
		unsigned int gfrc: 1;
		unsigned int pad4: 4;
	} extn;
	struct bcr_mpy extn_mpy;
};

struct cpu {
	int node_id;
	int hotpluggable;
	struct device dev;
};

enum {
	TASKSTATS_CMD_UNSPEC = 0,
	TASKSTATS_CMD_GET = 1,
	TASKSTATS_CMD_NEW = 2,
	__TASKSTATS_CMD_MAX = 3,
};

enum cpu_usage_stat {
	CPUTIME_USER = 0,
	CPUTIME_NICE = 1,
	CPUTIME_SYSTEM = 2,
	CPUTIME_SOFTIRQ = 3,
	CPUTIME_IRQ = 4,
	CPUTIME_IDLE = 5,
	CPUTIME_IOWAIT = 6,
	CPUTIME_STEAL = 7,
	CPUTIME_GUEST = 8,
	CPUTIME_GUEST_NICE = 9,
	NR_STATS = 10,
};

struct id_to_str {
	int id;
	const char *str;
};

struct machine_desc {
	const char *name;
	const char **dt_compat;
	void (*init_early)();
	void (*init_per_cpu)(unsigned int);
	void (*init_machine)();
	void (*init_late)();
};

typedef long unsigned int irq_hw_number_t;

enum irqreturn {
	IRQ_NONE = 0,
	IRQ_HANDLED = 1,
	IRQ_WAKE_THREAD = 2,
};

typedef enum irqreturn irqreturn_t;

struct irq_desc;

typedef void (*irq_flow_handler_t)(struct irq_desc *);

struct msi_desc;

struct irq_common_data {
	unsigned int state_use_accessors;
	void *handler_data;
	struct msi_desc *msi_desc;
	cpumask_var_t affinity;
};

struct irq_chip;

struct irq_domain;

struct irq_data {
	u32 mask;
	unsigned int irq;
	long unsigned int hwirq;
	struct irq_common_data *common;
	struct irq_chip *chip;
	struct irq_domain *domain;
	void *chip_data;
};

struct irqaction;

struct irq_desc {
	struct irq_common_data irq_common_data;
	struct irq_data irq_data;
	unsigned int *kstat_irqs;
	irq_flow_handler_t handle_irq;
	struct irqaction *action;
	unsigned int status_use_accessors;
	unsigned int core_internal_state__do_not_mess_with_it;
	unsigned int depth;
	unsigned int wake_depth;
	unsigned int tot_count;
	unsigned int irq_count;
	long unsigned int last_unhandled;
	unsigned int irqs_unhandled;
	atomic_t threads_handled;
	int threads_handled_last;
	raw_spinlock_t lock;
	struct cpumask *percpu_enabled;
	const struct cpumask *percpu_affinity;
	long unsigned int threads_oneshot;
	atomic_t threads_active;
	wait_queue_head_t wait_for_threads;
	struct proc_dir_entry *dir;
	struct mutex request_mutex;
	int parent_irq;
	struct module *owner;
	const char *name;
};

enum irqchip_irq_state {
	IRQCHIP_STATE_PENDING = 0,
	IRQCHIP_STATE_ACTIVE = 1,
	IRQCHIP_STATE_MASKED = 2,
	IRQCHIP_STATE_LINE_LEVEL = 3,
};

struct msi_msg;

struct irq_chip {
	const char *name;
	unsigned int (*irq_startup)(struct irq_data *);
	void (*irq_shutdown)(struct irq_data *);
	void (*irq_enable)(struct irq_data *);
	void (*irq_disable)(struct irq_data *);
	void (*irq_ack)(struct irq_data *);
	void (*irq_mask)(struct irq_data *);
	void (*irq_mask_ack)(struct irq_data *);
	void (*irq_unmask)(struct irq_data *);
	void (*irq_eoi)(struct irq_data *);
	int (*irq_set_affinity)(struct irq_data *, const struct cpumask *, bool);
	int (*irq_retrigger)(struct irq_data *);
	int (*irq_set_type)(struct irq_data *, unsigned int);
	int (*irq_set_wake)(struct irq_data *, unsigned int);
	void (*irq_bus_lock)(struct irq_data *);
	void (*irq_bus_sync_unlock)(struct irq_data *);
	void (*irq_suspend)(struct irq_data *);
	void (*irq_resume)(struct irq_data *);
	void (*irq_pm_shutdown)(struct irq_data *);
	void (*irq_calc_mask)(struct irq_data *);
	void (*irq_print_chip)(struct irq_data *, struct seq_file *);
	int (*irq_request_resources)(struct irq_data *);
	void (*irq_release_resources)(struct irq_data *);
	void (*irq_compose_msi_msg)(struct irq_data *, struct msi_msg *);
	void (*irq_write_msi_msg)(struct irq_data *, struct msi_msg *);
	int (*irq_get_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool *);
	int (*irq_set_irqchip_state)(struct irq_data *, enum irqchip_irq_state, bool);
	int (*irq_set_vcpu_affinity)(struct irq_data *, void *);
	void (*ipi_send_single)(struct irq_data *, unsigned int);
	void (*ipi_send_mask)(struct irq_data *, const struct cpumask *);
	int (*irq_nmi_setup)(struct irq_data *);
	void (*irq_nmi_teardown)(struct irq_data *);
	long unsigned int flags;
};

enum irq_domain_bus_token {
	DOMAIN_BUS_ANY = 0,
	DOMAIN_BUS_WIRED = 1,
	DOMAIN_BUS_GENERIC_MSI = 2,
	DOMAIN_BUS_PCI_MSI = 3,
	DOMAIN_BUS_PLATFORM_MSI = 4,
	DOMAIN_BUS_NEXUS = 5,
	DOMAIN_BUS_IPI = 6,
	DOMAIN_BUS_FSL_MC_MSI = 7,
	DOMAIN_BUS_TI_SCI_INTA_MSI = 8,
	DOMAIN_BUS_WAKEUP = 9,
	DOMAIN_BUS_VMD_MSI = 10,
};

struct irq_domain_ops;

struct irq_domain_chip_generic;

struct irq_domain {
	struct list_head link;
	const char *name;
	const struct irq_domain_ops *ops;
	void *host_data;
	unsigned int flags;
	unsigned int mapcount;
	struct fwnode_handle *fwnode;
	enum irq_domain_bus_token bus_token;
	struct irq_domain_chip_generic *gc;
	struct device *dev;
	irq_hw_number_t hwirq_max;
	unsigned int revmap_size;
	struct xarray revmap_tree;
	struct mutex revmap_mutex;
	struct irq_data *revmap[0];
};

typedef irqreturn_t (*irq_handler_t)(int, void *);

struct irqaction {
	irq_handler_t handler;
	void *dev_id;
	void *percpu_dev_id;
	struct irqaction *next;
	irq_handler_t thread_fn;
	struct task_struct *thread;
	struct irqaction *secondary;
	unsigned int irq;
	unsigned int flags;
	long unsigned int thread_flags;
	long unsigned int thread_mask;
	const char *name;
	struct proc_dir_entry *dir;
};

struct irq_chip_regs {
	long unsigned int enable;
	long unsigned int disable;
	long unsigned int mask;
	long unsigned int ack;
	long unsigned int eoi;
	long unsigned int type;
	long unsigned int polarity;
};

struct irq_chip_type {
	struct irq_chip chip;
	struct irq_chip_regs regs;
	irq_flow_handler_t handler;
	u32 type;
	u32 mask_cache_priv;
	u32 *mask_cache;
};

struct irq_chip_generic {
	raw_spinlock_t lock;
	void *reg_base;
	u32 (*reg_readl)(void *);
	void (*reg_writel)(u32, void *);
	void (*suspend)(struct irq_chip_generic *);
	void (*resume)(struct irq_chip_generic *);
	unsigned int irq_base;
	unsigned int irq_cnt;
	u32 mask_cache;
	u32 type_cache;
	u32 polarity_cache;
	u32 wake_enabled;
	u32 wake_active;
	unsigned int num_ct;
	void *private;
	long unsigned int installed;
	long unsigned int unused;
	struct irq_domain *domain;
	struct list_head list;
	struct irq_chip_type chip_types[0];
};

enum irq_gc_flags {
	IRQ_GC_INIT_MASK_CACHE = 1,
	IRQ_GC_INIT_NESTED_LOCK = 2,
	IRQ_GC_MASK_CACHE_PER_TYPE = 4,
	IRQ_GC_NO_MASK = 8,
	IRQ_GC_BE_IO = 16,
};

struct irq_domain_chip_generic {
	unsigned int irqs_per_chip;
	unsigned int num_chips;
	unsigned int irq_flags_to_clear;
	unsigned int irq_flags_to_set;
	enum irq_gc_flags gc_flags;
	struct irq_chip_generic *gc[0];
};

struct irq_fwspec {
	struct fwnode_handle *fwnode;
	int param_count;
	u32 param[16];
};

struct irq_domain_ops {
	int (*match)(struct irq_domain *, struct device_node *, enum irq_domain_bus_token);
	int (*select)(struct irq_domain *, struct irq_fwspec *, enum irq_domain_bus_token);
	int (*map)(struct irq_domain *, unsigned int, irq_hw_number_t);
	void (*unmap)(struct irq_domain *, unsigned int);
	int (*xlate)(struct irq_domain *, struct device_node *, const u32 *, unsigned int, long unsigned int *, unsigned int *);
};

struct callee_regs {
	long unsigned int r25;
	long unsigned int r24;
	long unsigned int r23;
	long unsigned int r22;
	long unsigned int r21;
	long unsigned int r20;
	long unsigned int r19;
	long unsigned int r18;
	long unsigned int r17;
	long unsigned int r16;
	long unsigned int r15;
	long unsigned int r14;
	long unsigned int r13;
};

typedef __u32 Elf32_Off;

struct elf32_hdr {
	unsigned char e_ident[16];
	Elf32_Half e_type;
	Elf32_Half e_machine;
	Elf32_Word e_version;
	Elf32_Addr e_entry;
	Elf32_Off e_phoff;
	Elf32_Off e_shoff;
	Elf32_Word e_flags;
	Elf32_Half e_ehsize;
	Elf32_Half e_phentsize;
	Elf32_Half e_phnum;
	Elf32_Half e_shentsize;
	Elf32_Half e_shnum;
	Elf32_Half e_shstrndx;
};

struct syscall_metadata {
	const char *name;
	int syscall_nr;
	int nb_args;
	const char **types;
	const char **args;
	struct list_head enter_fields;
	struct trace_event_call *enter_event;
	struct trace_event_call *exit_event;
};

struct membuf {
	void *p;
	size_t left;
};

struct user_regset;

typedef int user_regset_active_fn(struct task_struct *, const struct user_regset *);

typedef int user_regset_get2_fn(struct task_struct *, const struct user_regset *, struct membuf);

typedef int user_regset_set_fn(struct task_struct *, const struct user_regset *, unsigned int, unsigned int, const void *, const void *);

typedef int user_regset_writeback_fn(struct task_struct *, const struct user_regset *, int);

struct user_regset {
	user_regset_get2_fn *regset_get;
	user_regset_set_fn *set;
	user_regset_active_fn *active;
	user_regset_writeback_fn *writeback;
	unsigned int n;
	unsigned int size;
	unsigned int align;
	unsigned int bias;
	unsigned int core_note_type;
};

struct user_regset_view {
	const char *name;
	const struct user_regset *regsets;
	unsigned int n;
	u32 e_flags;
	u16 e_machine;
	u8 ei_osabi;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

struct trace_event_raw_sys_exit {
	struct trace_entry ent;
	long int id;
	long int ret;
	char __data[0];
};

struct trace_event_data_offsets_sys_enter {};

struct trace_event_data_offsets_sys_exit {};

typedef void (*btf_trace_sys_enter)(void *, struct pt_regs *, long int);

typedef void (*btf_trace_sys_exit)(void *, struct pt_regs *, long int);

struct pt_regs_offset {
	const char *name;
	int offset;
};

enum arc_getset {
	REGSET_CMN = 0,
	REGSET_ARCV2 = 1,
};

struct user_regs_struct {
	long unsigned int pad;
	struct {
		long unsigned int bta;
		long unsigned int lp_start;
		long unsigned int lp_end;
		long unsigned int lp_count;
		long unsigned int status32;
		long unsigned int ret;
		long unsigned int blink;
		long unsigned int fp;
		long unsigned int gp;
		long unsigned int r12;
		long unsigned int r11;
		long unsigned int r10;
		long unsigned int r9;
		long unsigned int r8;
		long unsigned int r7;
		long unsigned int r6;
		long unsigned int r5;
		long unsigned int r4;
		long unsigned int r3;
		long unsigned int r2;
		long unsigned int r1;
		long unsigned int r0;
		long unsigned int sp;
	} scratch;
	long unsigned int pad2;
	struct {
		long unsigned int r25;
		long unsigned int r24;
		long unsigned int r23;
		long unsigned int r22;
		long unsigned int r21;
		long unsigned int r20;
		long unsigned int r19;
		long unsigned int r18;
		long unsigned int r17;
		long unsigned int r16;
		long unsigned int r15;
		long unsigned int r14;
		long unsigned int r13;
	} callee;
	long unsigned int efa;
	long unsigned int stop_pc;
};

struct user_regs_arcv2 {
	long unsigned int r30;
	long unsigned int r58;
	long unsigned int r59;
};

struct sigaltstack {
	void *ss_sp;
	int ss_flags;
	__kernel_size_t ss_size;
};

typedef struct sigaltstack stack_t;

struct sigcontext {
	struct user_regs_struct regs;
	struct user_regs_arcv2 v2abi;
};

struct siginfo {
	union {
		struct {
			int si_signo;
			int si_errno;
			int si_code;
			union __sifields _sifields;
		};
		int _si_pad[32];
	};
};

typedef struct siginfo siginfo_t;

struct ksignal {
	struct k_sigaction ka;
	kernel_siginfo_t info;
	int sig;
};

struct ucontext {
	long unsigned int uc_flags;
	struct ucontext *uc_link;
	stack_t uc_stack;
	struct sigcontext uc_mcontext;
	sigset_t uc_sigmask;
};

struct rt_sigframe {
	struct siginfo info;
	struct ucontext uc;
	unsigned int sigret_magic;
};

enum die_val {
	DIE_UNUSED = 0,
	DIE_TRAP = 1,
	DIE_IERR = 2,
	DIE_OOPS = 3,
};

struct stack_trace {
	unsigned int nr_entries;
	unsigned int max_entries;
	long unsigned int *entries;
	unsigned int skip;
};

struct arc700_regs {
	long unsigned int r0;
	long unsigned int r1;
	long unsigned int r2;
	long unsigned int r3;
	long unsigned int r4;
	long unsigned int r5;
	long unsigned int r6;
	long unsigned int r7;
	long unsigned int r8;
	long unsigned int r9;
	long unsigned int r10;
	long unsigned int r11;
	long unsigned int r12;
	long unsigned int r13;
	long unsigned int r14;
	long unsigned int r15;
	long unsigned int r16;
	long unsigned int r17;
	long unsigned int r18;
	long unsigned int r19;
	long unsigned int r20;
	long unsigned int r21;
	long unsigned int r22;
	long unsigned int r23;
	long unsigned int r24;
	long unsigned int r25;
	long unsigned int r26;
	long unsigned int r27;
	long unsigned int r28;
	long unsigned int r29;
	long unsigned int r30;
	long unsigned int r31;
	long unsigned int r63;
};

struct unwind_frame_info {
	struct arc700_regs regs;
	struct task_struct *task;
	unsigned int call_frame: 1;
};

enum {
	op_Bcc = 0,
	op_BLcc = 1,
	op_LD = 2,
	op_ST = 3,
	op_MAJOR_4 = 4,
	op_MAJOR_5 = 5,
	op_LD_ADD = 12,
	op_ADD_SUB_SHIFT = 13,
	op_ADD_MOV_CMP = 14,
	op_S = 15,
	op_LD_S = 16,
	op_LDB_S = 17,
	op_LDW_S = 18,
	op_LDWX_S = 19,
	op_ST_S = 20,
	op_STB_S = 21,
	op_STW_S = 22,
	op_Su5 = 23,
	op_SP = 24,
	op_GP = 25,
	op_Pcl = 26,
	op_MOV_S = 27,
	op_ADD_CMP = 28,
	op_BR_S = 29,
	op_B_S = 30,
	op_BL_S = 31,
};

enum flow {
	noflow = 0,
	direct_jump = 1,
	direct_call = 2,
	indirect_jump = 3,
	indirect_call = 4,
	invalid_instr = 5,
};

struct disasm_state {
	long unsigned int words[2];
	int instr_len;
	int major_opcode;
	int is_branch;
	int target;
	int delay_slot;
	enum flow flow;
	int src1;
	int src2;
	int src3;
	int dest;
	int wb_reg;
	int zz;
	int aa;
	int x;
	int pref;
	int di;
	int fault;
	int write;
};

struct irq_affinity_desc {
	struct cpumask mask;
	unsigned int is_managed: 1;
};

typedef int (*of_init_fn_2)(struct device_node *, struct device_node *);

typedef int (*of_irq_init_cb_t)(struct device_node *, struct device_node *);

struct bcr_irq_arcv2 {
	unsigned int ver: 8;
	unsigned int irqs: 8;
	unsigned int exts: 8;
	unsigned int prio: 4;
	unsigned int firq: 1;
	unsigned int pad: 3;
};

struct aux_irq_ctrl {
	unsigned int save_nr_gpr_pairs: 5;
	unsigned int res: 4;
	unsigned int save_blink: 1;
	unsigned int save_lp_regs: 1;
	unsigned int save_u_to_u: 1;
	unsigned int res2: 1;
	unsigned int save_idx_regs: 1;
	unsigned int res3: 18;
};

typedef __s32 Elf32_Sword;

struct elf32_rela {
	Elf32_Addr r_offset;
	Elf32_Word r_info;
	Elf32_Sword r_addend;
};

typedef struct elf32_rela Elf32_Rela;

typedef struct elf32_hdr Elf32_Ehdr;

struct elf32_shdr {
	Elf32_Word sh_name;
	Elf32_Word sh_type;
	Elf32_Word sh_flags;
	Elf32_Addr sh_addr;
	Elf32_Off sh_offset;
	Elf32_Word sh_size;
	Elf32_Word sh_link;
	Elf32_Word sh_info;
	Elf32_Word sh_addralign;
	Elf32_Word sh_entsize;
};

typedef struct elf32_shdr Elf32_Shdr;

typedef void (*swap_func_t)(void *, void *, int);

typedef int (*cmp_func_t)(const void *, const void *);

typedef long unsigned int uleb128_t;

typedef long int sleb128_t;

struct unwind_table {
	struct {
		long unsigned int pc;
		long unsigned int range;
	} core;
	struct {
		long unsigned int pc;
		long unsigned int range;
	} init;
	const void *address;
	long unsigned int size;
	const unsigned char *header;
	long unsigned int hdrsz;
	struct unwind_table *link;
	const char *name;
};

enum item_location {
	Nowhere = 0,
	Memory = 1,
	Register = 2,
	Value = 3,
};

struct unwind_item {
	enum item_location where;
	uleb128_t value;
};

struct cfa {
	uleb128_t reg;
	uleb128_t offs;
};

struct unwind_state {
	uleb128_t loc;
	uleb128_t org;
	const u8 *cieStart;
	const u8 *cieEnd;
	uleb128_t codeAlign;
	sleb128_t dataAlign;
	struct cfa cfa;
	struct unwind_item regs[33];
	unsigned int stackDepth: 8;
	unsigned int version: 8;
	const u8 *label;
	const u8 *stack[8];
};

struct eh_frame_hdr_table_entry {
	long unsigned int start;
	long unsigned int fde;
};

struct unlink_table_info {
	struct unwind_table *table;
	int init_only;
};

struct freelist_node {
	atomic_t refs;
	struct freelist_node *next;
};

struct freelist_head {
	struct freelist_node *head;
};

typedef u16 kprobe_opcode_t;

struct arch_specific_insn {
	int is_short;
	kprobe_opcode_t *t1_addr;
	kprobe_opcode_t *t2_addr;
	kprobe_opcode_t t1_opcode;
	kprobe_opcode_t t2_opcode;
};

struct kprobe;

struct prev_kprobe {
	struct kprobe *kp;
	long unsigned int status;
};

typedef int (*kprobe_pre_handler_t)(struct kprobe *, struct pt_regs *);

typedef void (*kprobe_post_handler_t)(struct kprobe *, struct pt_regs *, long unsigned int);

struct kprobe {
	struct hlist_node hlist;
	struct list_head list;
	long unsigned int nmissed;
	kprobe_opcode_t *addr;
	const char *symbol_name;
	unsigned int offset;
	kprobe_pre_handler_t pre_handler;
	kprobe_post_handler_t post_handler;
	kprobe_opcode_t opcode;
	struct arch_specific_insn ainsn;
	u32 flags;
};

struct kprobe_ctlblk {
	unsigned int kprobe_status;
	struct prev_kprobe prev_kprobe;
};

struct kretprobe_instance;

typedef int (*kretprobe_handler_t)(struct kretprobe_instance *, struct pt_regs *);

struct kretprobe_holder;

struct kretprobe_instance {
	union {
		struct freelist_node freelist;
		struct callback_head rcu;
	};
	struct llist_node llist;
	struct kretprobe_holder *rph;
	kprobe_opcode_t *ret_addr;
	void *fp;
	char data[0];
};

struct kretprobe;

struct kretprobe_holder {
	struct kretprobe *rp;
	refcount_t ref;
};

struct kretprobe {
	struct kprobe kp;
	kretprobe_handler_t handler;
	kretprobe_handler_t entry_handler;
	int maxactive;
	int nmissed;
	size_t data_size;
	struct freelist_head freelist;
	struct kretprobe_holder *rph;
};

struct die_args {
	struct pt_regs *regs;
	const char *str;
	long int err;
	int trapnr;
	int signr;
};

typedef struct {
	long unsigned int fds_bits[32];
} __kernel_fd_set;

typedef int __kernel_key_t;

typedef int __kernel_mqd_t;

typedef unsigned int __kernel_mode_t;

typedef int __kernel_ipc_pid_t;

typedef unsigned int __kernel_uid_t;

typedef unsigned int __kernel_gid_t;

typedef __kernel_long_t __kernel_old_time_t;

typedef __kernel_fd_set fd_set;

typedef __kernel_key_t key_t;

typedef __kernel_timer_t timer_t;

typedef __kernel_mqd_t mqd_t;

typedef s32 int32_t;

struct sysinfo {
	__kernel_long_t uptime;
	__kernel_ulong_t loads[3];
	__kernel_ulong_t totalram;
	__kernel_ulong_t freeram;
	__kernel_ulong_t sharedram;
	__kernel_ulong_t bufferram;
	__kernel_ulong_t totalswap;
	__kernel_ulong_t freeswap;
	__u16 procs;
	__u16 pad;
	__kernel_ulong_t totalhigh;
	__kernel_ulong_t freehigh;
	__u32 mem_unit;
	char _f[8];
};

struct __kernel_itimerspec {
	struct __kernel_timespec it_interval;
	struct __kernel_timespec it_value;
};

struct __kernel_old_timeval {
	__kernel_long_t tv_sec;
	__kernel_long_t tv_usec;
};

struct __kernel_old_itimerval {
	struct __kernel_old_timeval it_interval;
	struct __kernel_old_timeval it_value;
};

struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};

struct stat64 {
	long long unsigned int st_dev;
	long long unsigned int st_ino;
	unsigned int st_mode;
	unsigned int st_nlink;
	unsigned int st_uid;
	unsigned int st_gid;
	long long unsigned int st_rdev;
	long long unsigned int __pad1;
	long long int st_size;
	int st_blksize;
	int __pad2;
	long long int st_blocks;
	int st_atime;
	unsigned int st_atime_nsec;
	int st_mtime;
	unsigned int st_mtime_nsec;
	int st_ctime;
	unsigned int st_ctime_nsec;
	unsigned int __unused4;
	unsigned int __unused5;
};

struct statx_timestamp {
	__s64 tv_sec;
	__u32 tv_nsec;
	__s32 __reserved;
};

struct statx {
	__u32 stx_mask;
	__u32 stx_blksize;
	__u64 stx_attributes;
	__u32 stx_nlink;
	__u32 stx_uid;
	__u32 stx_gid;
	__u16 stx_mode;
	__u16 __spare0[1];
	__u64 stx_ino;
	__u64 stx_size;
	__u64 stx_blocks;
	__u64 stx_attributes_mask;
	struct statx_timestamp stx_atime;
	struct statx_timestamp stx_btime;
	struct statx_timestamp stx_ctime;
	struct statx_timestamp stx_mtime;
	__u32 stx_rdev_major;
	__u32 stx_rdev_minor;
	__u32 stx_dev_major;
	__u32 stx_dev_minor;
	__u64 stx_mnt_id;
	__u64 __spare2;
	__u64 __spare3[12];
};

struct __kernel_timex_timeval {
	__kernel_time64_t tv_sec;
	long long int tv_usec;
};

struct __kernel_timex {
	unsigned int modes;
	int: 32;
	long long int offset;
	long long int freq;
	long long int maxerror;
	long long int esterror;
	int status;
	int: 32;
	long long int constant;
	long long int precision;
	long long int tolerance;
	struct __kernel_timex_timeval time;
	long long int tick;
	long long int ppsfreq;
	long long int jitter;
	int shift;
	int: 32;
	long long int stabil;
	long long int jitcnt;
	long long int calcnt;
	long long int errcnt;
	long long int stbcnt;
	int tai;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct old_timeval32 {
	old_time32_t tv_sec;
	s32 tv_usec;
};

struct old_itimerspec32 {
	struct old_timespec32 it_interval;
	struct old_timespec32 it_value;
};

struct old_timex32 {
	u32 modes;
	s32 offset;
	s32 freq;
	s32 maxerror;
	s32 esterror;
	s32 status;
	s32 constant;
	s32 precision;
	s32 tolerance;
	struct old_timeval32 time;
	s32 tick;
	s32 ppsfreq;
	s32 jitter;
	s32 shift;
	s32 stabil;
	s32 jitcnt;
	s32 calcnt;
	s32 errcnt;
	s32 stbcnt;
	s32 tai;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct __user_cap_header_struct {
	__u32 version;
	int pid;
};

typedef struct __user_cap_header_struct *cap_user_header_t;

struct __user_cap_data_struct {
	__u32 effective;
	__u32 permitted;
	__u32 inheritable;
};

typedef struct __user_cap_data_struct *cap_user_data_t;

struct open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

struct sigevent {
	sigval_t sigev_value;
	int sigev_signo;
	int sigev_notify;
	union {
		int _pad[13];
		int _tid;
		struct {
			void (*_function)(sigval_t);
			void *_attribute;
		} _sigev_thread;
	} _sigev_un;
};

struct ipc_perm {
	__kernel_key_t key;
	__kernel_uid_t uid;
	__kernel_gid_t gid;
	__kernel_uid_t cuid;
	__kernel_gid_t cgid;
	__kernel_mode_t mode;
	short unsigned int seq;
};

struct msgbuf;

struct sembuf {
	short unsigned int sem_num;
	short int sem_op;
	short int sem_flg;
};

struct shmid_ds {
	struct ipc_perm shm_perm;
	int shm_segsz;
	__kernel_old_time_t shm_atime;
	__kernel_old_time_t shm_dtime;
	__kernel_old_time_t shm_ctime;
	__kernel_ipc_pid_t shm_cpid;
	__kernel_ipc_pid_t shm_lpid;
	short unsigned int shm_nattch;
	short unsigned int shm_unused;
	void *shm_unused2;
	void *shm_unused3;
};

struct rusage {
	struct __kernel_old_timeval ru_utime;
	struct __kernel_old_timeval ru_stime;
	__kernel_long_t ru_maxrss;
	__kernel_long_t ru_ixrss;
	__kernel_long_t ru_idrss;
	__kernel_long_t ru_isrss;
	__kernel_long_t ru_minflt;
	__kernel_long_t ru_majflt;
	__kernel_long_t ru_nswap;
	__kernel_long_t ru_inblock;
	__kernel_long_t ru_oublock;
	__kernel_long_t ru_msgsnd;
	__kernel_long_t ru_msgrcv;
	__kernel_long_t ru_nsignals;
	__kernel_long_t ru_nvcsw;
	__kernel_long_t ru_nivcsw;
};

struct rlimit64 {
	__u64 rlim_cur;
	__u64 rlim_max;
};

struct rseq {
	__u32 cpu_id_start;
	__u32 cpu_id;
	__u64 rseq_cs;
	__u32 flags;
	int: 32;
	int: 32;
	int: 32;
};

typedef int32_t key_serial_t;

typedef int __kernel_rwf_t;

typedef __kernel_rwf_t rwf_t;

typedef __kernel_uid32_t qid_t;

struct file_handle {
	__u32 handle_bytes;
	int handle_type;
	unsigned char f_handle[0];
};

typedef __kernel_ulong_t aio_context_t;

struct io_event {
	__u64 data;
	__u64 obj;
	__s64 res;
	__s64 res2;
};

struct iocb {
	__u64 aio_data;
	__u32 aio_key;
	__kernel_rwf_t aio_rw_flags;
	__u16 aio_lio_opcode;
	__s16 aio_reqprio;
	__u32 aio_fildes;
	__u64 aio_buf;
	__u64 aio_nbytes;
	__s64 aio_offset;
	__u64 aio_reserved2;
	__u32 aio_flags;
	__u32 aio_resfd;
};

struct epoll_event {
	__poll_t events;
	__u64 data;
};

struct futex_waitv;

enum landlock_rule_type;

struct landlock_ruleset_attr;

struct mount_attr;

struct iovec;

struct io_uring_params;

struct mmsghdr;

struct __aio_sigset;

union bpf_attr;

struct sched_attr;

struct sockaddr;

struct user_msghdr;

struct msqid_ds;

struct mq_attr;

struct getcpu_cache;

struct new_utsname;

struct tms;

struct sched_param;

struct kexec_segment;

struct linux_dirent64;

struct statfs64;

typedef phys_addr_t resource_size_t;

typedef void (*exitcall_t)();

typedef void (*smp_call_func_t)(void *);

typedef bool (*smp_cond_func_t)(int, void *);

enum {
	IRQ_TYPE_NONE = 0,
	IRQ_TYPE_EDGE_RISING = 1,
	IRQ_TYPE_EDGE_FALLING = 2,
	IRQ_TYPE_EDGE_BOTH = 3,
	IRQ_TYPE_LEVEL_HIGH = 4,
	IRQ_TYPE_LEVEL_LOW = 8,
	IRQ_TYPE_LEVEL_MASK = 12,
	IRQ_TYPE_SENSE_MASK = 15,
	IRQ_TYPE_DEFAULT = 15,
	IRQ_TYPE_PROBE = 16,
	IRQ_LEVEL = 256,
	IRQ_PER_CPU = 512,
	IRQ_NOPROBE = 1024,
	IRQ_NOREQUEST = 2048,
	IRQ_NOAUTOEN = 4096,
	IRQ_NO_BALANCING = 8192,
	IRQ_MOVE_PCNTXT = 16384,
	IRQ_NESTED_THREAD = 32768,
	IRQ_NOTHREAD = 65536,
	IRQ_PER_CPU_DEVID = 131072,
	IRQ_IS_POLLED = 262144,
	IRQ_DISABLE_UNLAZY = 524288,
	IRQ_HIDDEN = 1048576,
	IRQ_NO_DEBUG = 2097152,
};

struct platform_device_id {
	char name[20];
	kernel_ulong_t driver_data;
};

enum perf_type_id {
	PERF_TYPE_HARDWARE = 0,
	PERF_TYPE_SOFTWARE = 1,
	PERF_TYPE_TRACEPOINT = 2,
	PERF_TYPE_HW_CACHE = 3,
	PERF_TYPE_RAW = 4,
	PERF_TYPE_BREAKPOINT = 5,
	PERF_TYPE_MAX = 6,
};

enum perf_hw_id {
	PERF_COUNT_HW_CPU_CYCLES = 0,
	PERF_COUNT_HW_INSTRUCTIONS = 1,
	PERF_COUNT_HW_CACHE_REFERENCES = 2,
	PERF_COUNT_HW_CACHE_MISSES = 3,
	PERF_COUNT_HW_BRANCH_INSTRUCTIONS = 4,
	PERF_COUNT_HW_BRANCH_MISSES = 5,
	PERF_COUNT_HW_BUS_CYCLES = 6,
	PERF_COUNT_HW_STALLED_CYCLES_FRONTEND = 7,
	PERF_COUNT_HW_STALLED_CYCLES_BACKEND = 8,
	PERF_COUNT_HW_REF_CPU_CYCLES = 9,
	PERF_COUNT_HW_MAX = 10,
};

enum perf_hw_cache_id {
	PERF_COUNT_HW_CACHE_L1D = 0,
	PERF_COUNT_HW_CACHE_L1I = 1,
	PERF_COUNT_HW_CACHE_LL = 2,
	PERF_COUNT_HW_CACHE_DTLB = 3,
	PERF_COUNT_HW_CACHE_ITLB = 4,
	PERF_COUNT_HW_CACHE_BPU = 5,
	PERF_COUNT_HW_CACHE_NODE = 6,
	PERF_COUNT_HW_CACHE_MAX = 7,
};

enum perf_hw_cache_op_id {
	PERF_COUNT_HW_CACHE_OP_READ = 0,
	PERF_COUNT_HW_CACHE_OP_WRITE = 1,
	PERF_COUNT_HW_CACHE_OP_PREFETCH = 2,
	PERF_COUNT_HW_CACHE_OP_MAX = 3,
};

enum perf_hw_cache_op_result_id {
	PERF_COUNT_HW_CACHE_RESULT_ACCESS = 0,
	PERF_COUNT_HW_CACHE_RESULT_MISS = 1,
	PERF_COUNT_HW_CACHE_RESULT_MAX = 2,
};

struct arc_reg_pct_build {
	unsigned int v: 8;
	unsigned int s: 2;
	unsigned int i: 1;
	unsigned int r: 5;
	unsigned int c: 8;
	unsigned int m: 8;
};

struct arc_reg_cc_build {
	unsigned int v: 8;
	unsigned int r: 8;
	unsigned int c: 16;
};

struct resource {
	resource_size_t start;
	resource_size_t end;
	const char *name;
	long unsigned int flags;
	long unsigned int desc;
	struct resource *parent;
	struct resource *sibling;
	struct resource *child;
};

struct pdev_archdata {};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device *, struct device_attribute *, char *);
	ssize_t (*store)(struct device *, struct device_attribute *, const char *, size_t);
};

struct perf_callchain_entry_ctx {
	struct perf_callchain_entry *entry;
	u32 max_stack;
	u32 nr;
	short int contexts;
	bool contexts_maxed;
};

struct perf_pmu_events_attr {
	struct device_attribute attr;
	u64 id;
	const char *event_str;
};

struct mfd_cell;

struct platform_device {
	const char *name;
	int id;
	bool id_auto;
	struct device dev;
	u64 platform_dma_mask;
	struct device_dma_parameters dma_parms;
	u32 num_resources;
	struct resource *resource;
	const struct platform_device_id *id_entry;
	char *driver_override;
	struct mfd_cell *mfd_cell;
	struct pdev_archdata archdata;
};

struct platform_driver {
	int (*probe)(struct platform_device *);
	int (*remove)(struct platform_device *);
	void (*shutdown)(struct platform_device *);
	int (*suspend)(struct platform_device *, pm_message_t);
	int (*resume)(struct platform_device *);
	struct device_driver driver;
	const struct platform_device_id *id_table;
	bool prevent_deferred_probe;
};

enum arc_pmu_attr_groups {
	ARCPMU_ATTR_GR_EVENTS = 0,
	ARCPMU_ATTR_GR_FORMATS = 1,
	ARCPMU_NR_ATTR_GR = 2,
};

struct arc_pmu_raw_event_entry {
	char name[9];
};

struct arc_pmu {
	struct pmu pmu;
	unsigned int irq;
	int n_counters;
	int n_events;
	u64 max_period;
	int ev_hw_idx[18];
	struct arc_pmu_raw_event_entry *raw_entry;
	struct attribute **attrs;
	struct perf_pmu_events_attr *attr;
	const struct attribute_group *attr_groups[3];
};

struct arc_pmu_cpu {
	long unsigned int used_mask[1];
	struct perf_event *act_counter[32];
};

struct arc_callchain_trace {
	int depth;
	void *perf_stuff;
};

union cc_name {
	struct {
		u32 word0;
		u32 word1;
		char sentinel;
	} indiv;
	char str[9];
};

enum vm_fault_reason {
	VM_FAULT_OOM = 1,
	VM_FAULT_SIGBUS = 2,
	VM_FAULT_MAJOR = 4,
	VM_FAULT_WRITE = 8,
	VM_FAULT_HWPOISON = 16,
	VM_FAULT_HWPOISON_LARGE = 32,
	VM_FAULT_SIGSEGV = 64,
	VM_FAULT_NOPAGE = 256,
	VM_FAULT_LOCKED = 512,
	VM_FAULT_RETRY = 1024,
	VM_FAULT_FALLBACK = 2048,
	VM_FAULT_DONE_COW = 4096,
	VM_FAULT_NEEDDSYNC = 8192,
	VM_FAULT_HINDEX_MASK = 983040,
};

enum memblock_flags {
	MEMBLOCK_NONE = 0,
	MEMBLOCK_HOTPLUG = 1,
	MEMBLOCK_MIRROR = 2,
	MEMBLOCK_NOMAP = 4,
	MEMBLOCK_DRIVER_MANAGED = 8,
};

enum pageflags {
	PG_locked = 0,
	PG_referenced = 1,
	PG_uptodate = 2,
	PG_dirty = 3,
	PG_lru = 4,
	PG_active = 5,
	PG_workingset = 6,
	PG_waiters = 7,
	PG_error = 8,
	PG_slab = 9,
	PG_owner_priv_1 = 10,
	PG_arch_1 = 11,
	PG_reserved = 12,
	PG_private = 13,
	PG_private_2 = 14,
	PG_writeback = 15,
	PG_head = 16,
	PG_mappedtodisk = 17,
	PG_reclaim = 18,
	PG_swapbacked = 19,
	PG_unevictable = 20,
	PG_mlocked = 21,
	__NR_PAGEFLAGS = 22,
	PG_readahead = 18,
	PG_checked = 10,
	PG_swapcache = 10,
	PG_fscache = 14,
	PG_pinned = 10,
	PG_savepinned = 3,
	PG_foreign = 10,
	PG_xen_remapped = 10,
	PG_slob_free = 13,
	PG_double_map = 6,
	PG_isolated = 18,
	PG_reported = 2,
};

struct bcr_mmu_3 {
	unsigned int u_dtlb: 4;
	unsigned int u_itlb: 4;
	unsigned int pg_sz: 4;
	unsigned int sasid: 1;
	unsigned int res: 3;
	unsigned int sets: 4;
	unsigned int ways: 4;
	unsigned int ver: 8;
};

struct bcr_mmu_4 {
	unsigned int u_dtlb: 3;
	unsigned int u_itlb: 3;
	unsigned int n_super: 2;
	unsigned int n_entry: 2;
	unsigned int n_ways: 2;
	unsigned int pae: 1;
	unsigned int res: 2;
	unsigned int sz0: 4;
	unsigned int sz1: 4;
	unsigned int sasid: 1;
	unsigned int ver: 8;
};

struct bcr_cache {
	unsigned int ver: 8;
	unsigned int config: 4;
	unsigned int sz: 4;
	unsigned int line_len: 4;
	unsigned int pad: 12;
};

struct bcr_slc_cfg {
	unsigned int sz: 4;
	unsigned int lsz: 2;
	unsigned int way: 2;
	unsigned int pad: 24;
};

struct bcr_clust_cfg {
	unsigned int ver: 8;
	unsigned int num_cores: 8;
	unsigned int num_entries: 8;
	unsigned int c: 1;
	unsigned int pad: 7;
};

struct bcr_volatile {
	unsigned int disable: 1;
	unsigned int order: 1;
	unsigned int pad: 22;
	unsigned int limit: 4;
	unsigned int start: 4;
};

struct vm_unmapped_area_info {
	long unsigned int flags;
	long unsigned int length;
	long unsigned int low_limit;
	long unsigned int high_limit;
	long unsigned int align_mask;
	long unsigned int align_offset;
};

struct vm_struct {
	struct vm_struct *next;
	void *addr;
	long unsigned int size;
	long unsigned int flags;
	struct page **pages;
	unsigned int nr_pages;
	phys_addr_t phys_addr;
	const void *caller;
};

enum {
	BPF_REG_0 = 0,
	BPF_REG_1 = 1,
	BPF_REG_2 = 2,
	BPF_REG_3 = 3,
	BPF_REG_4 = 4,
	BPF_REG_5 = 5,
	BPF_REG_6 = 6,
	BPF_REG_7 = 7,
	BPF_REG_8 = 8,
	BPF_REG_9 = 9,
	BPF_REG_10 = 10,
	__MAX_BPF_REG = 11,
};

struct bpf_insn {
	__u8 code;
	__u8 dst_reg: 4;
	__u8 src_reg: 4;
	__s16 off;
	__s32 imm;
};

enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC = 0,
	BPF_MAP_TYPE_HASH = 1,
	BPF_MAP_TYPE_ARRAY = 2,
	BPF_MAP_TYPE_PROG_ARRAY = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY = 4,
	BPF_MAP_TYPE_PERCPU_HASH = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY = 6,
	BPF_MAP_TYPE_STACK_TRACE = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY = 8,
	BPF_MAP_TYPE_LRU_HASH = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH = 10,
	BPF_MAP_TYPE_LPM_TRIE = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS = 13,
	BPF_MAP_TYPE_DEVMAP = 14,
	BPF_MAP_TYPE_SOCKMAP = 15,
	BPF_MAP_TYPE_CPUMAP = 16,
	BPF_MAP_TYPE_XSKMAP = 17,
	BPF_MAP_TYPE_SOCKHASH = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE = 22,
	BPF_MAP_TYPE_STACK = 23,
	BPF_MAP_TYPE_SK_STORAGE = 24,
	BPF_MAP_TYPE_DEVMAP_HASH = 25,
	BPF_MAP_TYPE_STRUCT_OPS = 26,
	BPF_MAP_TYPE_RINGBUF = 27,
	BPF_MAP_TYPE_INODE_STORAGE = 28,
	BPF_MAP_TYPE_TASK_STORAGE = 29,
	BPF_MAP_TYPE_BLOOM_FILTER = 30,
};

enum bpf_prog_type {
	BPF_PROG_TYPE_UNSPEC = 0,
	BPF_PROG_TYPE_SOCKET_FILTER = 1,
	BPF_PROG_TYPE_KPROBE = 2,
	BPF_PROG_TYPE_SCHED_CLS = 3,
	BPF_PROG_TYPE_SCHED_ACT = 4,
	BPF_PROG_TYPE_TRACEPOINT = 5,
	BPF_PROG_TYPE_XDP = 6,
	BPF_PROG_TYPE_PERF_EVENT = 7,
	BPF_PROG_TYPE_CGROUP_SKB = 8,
	BPF_PROG_TYPE_CGROUP_SOCK = 9,
	BPF_PROG_TYPE_LWT_IN = 10,
	BPF_PROG_TYPE_LWT_OUT = 11,
	BPF_PROG_TYPE_LWT_XMIT = 12,
	BPF_PROG_TYPE_SOCK_OPS = 13,
	BPF_PROG_TYPE_SK_SKB = 14,
	BPF_PROG_TYPE_CGROUP_DEVICE = 15,
	BPF_PROG_TYPE_SK_MSG = 16,
	BPF_PROG_TYPE_RAW_TRACEPOINT = 17,
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,
	BPF_PROG_TYPE_LWT_SEG6LOCAL = 19,
	BPF_PROG_TYPE_LIRC_MODE2 = 20,
	BPF_PROG_TYPE_SK_REUSEPORT = 21,
	BPF_PROG_TYPE_FLOW_DISSECTOR = 22,
	BPF_PROG_TYPE_CGROUP_SYSCTL = 23,
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 24,
	BPF_PROG_TYPE_CGROUP_SOCKOPT = 25,
	BPF_PROG_TYPE_TRACING = 26,
	BPF_PROG_TYPE_STRUCT_OPS = 27,
	BPF_PROG_TYPE_EXT = 28,
	BPF_PROG_TYPE_LSM = 29,
	BPF_PROG_TYPE_SK_LOOKUP = 30,
	BPF_PROG_TYPE_SYSCALL = 31,
};

enum bpf_attach_type {
	BPF_CGROUP_INET_INGRESS = 0,
	BPF_CGROUP_INET_EGRESS = 1,
	BPF_CGROUP_INET_SOCK_CREATE = 2,
	BPF_CGROUP_SOCK_OPS = 3,
	BPF_SK_SKB_STREAM_PARSER = 4,
	BPF_SK_SKB_STREAM_VERDICT = 5,
	BPF_CGROUP_DEVICE = 6,
	BPF_SK_MSG_VERDICT = 7,
	BPF_CGROUP_INET4_BIND = 8,
	BPF_CGROUP_INET6_BIND = 9,
	BPF_CGROUP_INET4_CONNECT = 10,
	BPF_CGROUP_INET6_CONNECT = 11,
	BPF_CGROUP_INET4_POST_BIND = 12,
	BPF_CGROUP_INET6_POST_BIND = 13,
	BPF_CGROUP_UDP4_SENDMSG = 14,
	BPF_CGROUP_UDP6_SENDMSG = 15,
	BPF_LIRC_MODE2 = 16,
	BPF_FLOW_DISSECTOR = 17,
	BPF_CGROUP_SYSCTL = 18,
	BPF_CGROUP_UDP4_RECVMSG = 19,
	BPF_CGROUP_UDP6_RECVMSG = 20,
	BPF_CGROUP_GETSOCKOPT = 21,
	BPF_CGROUP_SETSOCKOPT = 22,
	BPF_TRACE_RAW_TP = 23,
	BPF_TRACE_FENTRY = 24,
	BPF_TRACE_FEXIT = 25,
	BPF_MODIFY_RETURN = 26,
	BPF_LSM_MAC = 27,
	BPF_TRACE_ITER = 28,
	BPF_CGROUP_INET4_GETPEERNAME = 29,
	BPF_CGROUP_INET6_GETPEERNAME = 30,
	BPF_CGROUP_INET4_GETSOCKNAME = 31,
	BPF_CGROUP_INET6_GETSOCKNAME = 32,
	BPF_XDP_DEVMAP = 33,
	BPF_CGROUP_INET_SOCK_RELEASE = 34,
	BPF_XDP_CPUMAP = 35,
	BPF_SK_LOOKUP = 36,
	BPF_XDP = 37,
	BPF_SK_SKB_VERDICT = 38,
	BPF_SK_REUSEPORT_SELECT = 39,
	BPF_SK_REUSEPORT_SELECT_OR_MIGRATE = 40,
	BPF_PERF_EVENT = 41,
	BPF_TRACE_KPROBE_MULTI = 42,
	__MAX_BPF_ATTACH_TYPE = 43,
};

union bpf_attr {
	struct {
		__u32 map_type;
		__u32 key_size;
		__u32 value_size;
		__u32 max_entries;
		__u32 map_flags;
		__u32 inner_map_fd;
		__u32 numa_node;
		char map_name[16];
		__u32 map_ifindex;
		__u32 btf_fd;
		__u32 btf_key_type_id;
		__u32 btf_value_type_id;
		__u32 btf_vmlinux_value_type_id;
		__u64 map_extra;
	};
	struct {
		__u32 map_fd;
		int: 32;
		__u64 key;
		union {
			__u64 value;
			__u64 next_key;
		};
		__u64 flags;
	};
	struct {
		__u64 in_batch;
		__u64 out_batch;
		__u64 keys;
		__u64 values;
		__u32 count;
		__u32 map_fd;
		__u64 elem_flags;
		__u64 flags;
	} batch;
	struct {
		__u32 prog_type;
		__u32 insn_cnt;
		__u64 insns;
		__u64 license;
		__u32 log_level;
		__u32 log_size;
		__u64 log_buf;
		__u32 kern_version;
		__u32 prog_flags;
		char prog_name[16];
		__u32 prog_ifindex;
		__u32 expected_attach_type;
		__u32 prog_btf_fd;
		__u32 func_info_rec_size;
		__u64 func_info;
		__u32 func_info_cnt;
		__u32 line_info_rec_size;
		__u64 line_info;
		__u32 line_info_cnt;
		__u32 attach_btf_id;
		union {
			__u32 attach_prog_fd;
			__u32 attach_btf_obj_fd;
		};
		__u32 core_relo_cnt;
		__u64 fd_array;
		__u64 core_relos;
		__u32 core_relo_rec_size;
		int: 32;
	};
	struct {
		__u64 pathname;
		__u32 bpf_fd;
		__u32 file_flags;
	};
	struct {
		__u32 target_fd;
		__u32 attach_bpf_fd;
		__u32 attach_type;
		__u32 attach_flags;
		__u32 replace_bpf_fd;
	};
	struct {
		__u32 prog_fd;
		__u32 retval;
		__u32 data_size_in;
		__u32 data_size_out;
		__u64 data_in;
		__u64 data_out;
		__u32 repeat;
		__u32 duration;
		__u32 ctx_size_in;
		__u32 ctx_size_out;
		__u64 ctx_in;
		__u64 ctx_out;
		__u32 flags;
		__u32 cpu;
		__u32 batch_size;
		int: 32;
	} test;
	struct {
		union {
			__u32 start_id;
			__u32 prog_id;
			__u32 map_id;
			__u32 btf_id;
			__u32 link_id;
		};
		__u32 next_id;
		__u32 open_flags;
	};
	struct {
		__u32 bpf_fd;
		__u32 info_len;
		__u64 info;
	} info;
	struct {
		__u32 target_fd;
		__u32 attach_type;
		__u32 query_flags;
		__u32 attach_flags;
		__u64 prog_ids;
		__u32 prog_cnt;
		int: 32;
	} query;
	struct {
		__u64 name;
		__u32 prog_fd;
	} raw_tracepoint;
	struct {
		__u64 btf;
		__u64 btf_log_buf;
		__u32 btf_size;
		__u32 btf_log_size;
		__u32 btf_log_level;
		int: 32;
	};
	struct {
		__u32 pid;
		__u32 fd;
		__u32 flags;
		__u32 buf_len;
		__u64 buf;
		__u32 prog_id;
		__u32 fd_type;
		__u64 probe_offset;
		__u64 probe_addr;
	} task_fd_query;
	struct {
		__u32 prog_fd;
		union {
			__u32 target_fd;
			__u32 target_ifindex;
		};
		__u32 attach_type;
		__u32 flags;
		union {
			__u32 target_btf_id;
			struct {
				__u64 iter_info;
				__u32 iter_info_len;
				int: 32;
			};
			struct {
				__u64 bpf_cookie;
			} perf_event;
			struct {
				__u32 flags;
				__u32 cnt;
				__u64 syms;
				__u64 addrs;
				__u64 cookies;
			} kprobe_multi;
		};
	} link_create;
	struct {
		__u32 link_fd;
		__u32 new_prog_fd;
		__u32 flags;
		__u32 old_prog_fd;
	} link_update;
	struct {
		__u32 link_fd;
	} link_detach;
	struct {
		__u32 type;
	} enable_stats;
	struct {
		__u32 link_fd;
		__u32 flags;
	} iter_create;
	struct {
		__u32 prog_fd;
		__u32 map_fd;
		__u32 flags;
	} prog_bind_map;
};

struct bpf_func_info {
	__u32 insn_off;
	__u32 type_id;
};

struct bpf_line_info {
	__u32 insn_off;
	__u32 file_name_off;
	__u32 line_off;
	__u32 line_col;
};

enum {
	DUMP_PREFIX_NONE = 0,
	DUMP_PREFIX_ADDRESS = 1,
	DUMP_PREFIX_OFFSET = 2,
};

struct bpf_run_ctx {};

typedef u64 (*bpf_callback_t)(u64, u64, u64, u64, u64);

struct bpf_iter_aux_info;

typedef int (*bpf_iter_init_seq_priv_t)(void *, struct bpf_iter_aux_info *);

struct bpf_map;

struct bpf_iter_aux_info {
	struct bpf_map *map;
};

typedef void (*bpf_iter_fini_seq_priv_t)(void *);

struct bpf_iter_seq_info {
	const struct seq_operations *seq_ops;
	bpf_iter_init_seq_priv_t init_seq_private;
	bpf_iter_fini_seq_priv_t fini_seq_private;
	u32 seq_priv_size;
};

struct btf;

struct btf_type;

struct bpf_prog_aux;

struct bpf_local_storage_map;

struct bpf_verifier_env;

struct bpf_func_state;

struct bpf_map_ops {
	int (*map_alloc_check)(union bpf_attr *);
	struct bpf_map * (*map_alloc)(union bpf_attr *);
	void (*map_release)(struct bpf_map *, struct file *);
	void (*map_free)(struct bpf_map *);
	int (*map_get_next_key)(struct bpf_map *, void *, void *);
	void (*map_release_uref)(struct bpf_map *);
	void * (*map_lookup_elem_sys_only)(struct bpf_map *, void *);
	int (*map_lookup_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_lookup_and_delete_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_lookup_and_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_update_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	int (*map_delete_batch)(struct bpf_map *, const union bpf_attr *, union bpf_attr *);
	void * (*map_lookup_elem)(struct bpf_map *, void *);
	int (*map_update_elem)(struct bpf_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_map *, void *);
	int (*map_push_elem)(struct bpf_map *, void *, u64);
	int (*map_pop_elem)(struct bpf_map *, void *);
	int (*map_peek_elem)(struct bpf_map *, void *);
	void * (*map_fd_get_ptr)(struct bpf_map *, struct file *, int);
	void (*map_fd_put_ptr)(void *);
	int (*map_gen_lookup)(struct bpf_map *, struct bpf_insn *);
	u32 (*map_fd_sys_lookup_elem)(void *);
	void (*map_seq_show_elem)(struct bpf_map *, void *, struct seq_file *);
	int (*map_check_btf)(const struct bpf_map *, const struct btf *, const struct btf_type *, const struct btf_type *);
	int (*map_poke_track)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_untrack)(struct bpf_map *, struct bpf_prog_aux *);
	void (*map_poke_run)(struct bpf_map *, u32, struct bpf_prog *, struct bpf_prog *);
	int (*map_direct_value_addr)(const struct bpf_map *, u64 *, u32);
	int (*map_direct_value_meta)(const struct bpf_map *, u64, u32 *);
	int (*map_mmap)(struct bpf_map *, struct vm_area_struct *);
	__poll_t (*map_poll)(struct bpf_map *, struct file *, struct poll_table_struct *);
	int (*map_local_storage_charge)(struct bpf_local_storage_map *, void *, u32);
	void (*map_local_storage_uncharge)(struct bpf_local_storage_map *, void *, u32);
	struct bpf_local_storage ** (*map_owner_storage_ptr)(void *);
	int (*map_redirect)(struct bpf_map *, u32, u64);
	bool (*map_meta_equal)(const struct bpf_map *, const struct bpf_map *);
	int (*map_set_for_each_callback_args)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *);
	int (*map_for_each_callback)(struct bpf_map *, bpf_callback_t, void *, u64);
	const char * const map_btf_name;
	int *map_btf_id;
	const struct bpf_iter_seq_info *iter_seq_info;
};

struct bpf_map {
	const struct bpf_map_ops *ops;
	struct bpf_map *inner_map_meta;
	enum bpf_map_type map_type;
	u32 key_size;
	u32 value_size;
	u32 max_entries;
	u64 map_extra;
	u32 map_flags;
	int spin_lock_off;
	int timer_off;
	u32 id;
	int numa_node;
	u32 btf_key_type_id;
	u32 btf_value_type_id;
	u32 btf_vmlinux_value_type_id;
	struct btf *btf;
	char name[16];
	bool bypass_spec_v1;
	bool frozen;
	int: 16;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	atomic64_t refcnt;
	atomic64_t usercnt;
	struct work_struct work;
	struct mutex freeze_mutex;
	int: 32;
	atomic64_t writecnt;
	struct {
		spinlock_t lock;
		enum bpf_prog_type type;
		bool jited;
		bool xdp_has_frags;
	} owner;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct btf_header {
	__u16 magic;
	__u8 version;
	__u8 flags;
	__u32 hdr_len;
	__u32 type_off;
	__u32 type_len;
	__u32 str_off;
	__u32 str_len;
};

struct btf_kfunc_set_tab;

struct btf {
	void *data;
	struct btf_type **types;
	u32 *resolved_ids;
	u32 *resolved_sizes;
	const char *strings;
	void *nohdr_data;
	struct btf_header hdr;
	u32 nr_types;
	u32 types_size;
	u32 data_size;
	refcount_t refcnt;
	u32 id;
	struct callback_head rcu;
	struct btf_kfunc_set_tab *kfunc_set_tab;
	struct btf *base_btf;
	u32 start_id;
	u32 start_str_off;
	char name[60];
	bool kernel_btf;
};

struct btf_type {
	__u32 name_off;
	__u32 info;
	union {
		__u32 size;
		__u32 type;
	};
};

struct bpf_ksym {
	long unsigned int start;
	long unsigned int end;
	char name[128];
	struct list_head lnode;
	struct latch_tree_node tnode;
	bool prog;
};

struct bpf_ctx_arg_aux;

struct bpf_trampoline;

struct bpf_jit_poke_descriptor;

struct bpf_kfunc_desc_tab;

struct bpf_kfunc_btf_tab;

struct bpf_prog_ops;

struct btf_mod_pair;

struct bpf_prog_offload;

struct bpf_func_info_aux;

struct bpf_prog_aux {
	atomic64_t refcnt;
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 max_ctx_offset;
	u32 max_pkt_offset;
	u32 max_tp_access;
	u32 stack_depth;
	u32 id;
	u32 func_cnt;
	u32 func_idx;
	u32 attach_btf_id;
	u32 ctx_arg_info_size;
	u32 max_rdonly_access;
	u32 max_rdwr_access;
	struct btf *attach_btf;
	const struct bpf_ctx_arg_aux *ctx_arg_info;
	struct mutex dst_mutex;
	struct bpf_prog *dst_prog;
	struct bpf_trampoline *dst_trampoline;
	enum bpf_prog_type saved_dst_prog_type;
	enum bpf_attach_type saved_dst_attach_type;
	bool verifier_zext;
	bool offload_requested;
	bool attach_btf_trace;
	bool func_proto_unreliable;
	bool sleepable;
	bool tail_call_reachable;
	bool xdp_has_frags;
	bool use_bpf_prog_pack;
	struct hlist_node tramp_hlist;
	const struct btf_type *attach_func_proto;
	const char *attach_func_name;
	struct bpf_prog **func;
	void *jit_data;
	struct bpf_jit_poke_descriptor *poke_tab;
	struct bpf_kfunc_desc_tab *kfunc_tab;
	struct bpf_kfunc_btf_tab *kfunc_btf_tab;
	u32 size_poke_tab;
	struct bpf_ksym ksym;
	const struct bpf_prog_ops *ops;
	struct bpf_map **used_maps;
	struct mutex used_maps_mutex;
	struct btf_mod_pair *used_btfs;
	struct bpf_prog *prog;
	struct user_struct *user;
	u64 load_time;
	u32 verified_insns;
	struct bpf_map *cgroup_storage[2];
	char name[16];
	struct bpf_prog_offload *offload;
	struct btf *btf;
	struct bpf_func_info *func_info;
	struct bpf_func_info_aux *func_info_aux;
	struct bpf_line_info *linfo;
	void **jited_linfo;
	u32 func_info_cnt;
	u32 nr_linfo;
	u32 linfo_idx;
	u32 num_exentries;
	struct exception_table_entry *extable;
	union {
		struct work_struct work;
		struct callback_head rcu;
	};
	int: 32;
};

struct sock_filter {
	__u16 code;
	__u8 jt;
	__u8 jf;
	__u32 k;
};

struct bpf_prog_stats;

struct sock_fprog_kern;

struct bpf_prog {
	u16 pages;
	u16 jited: 1;
	u16 jit_requested: 1;
	u16 gpl_compatible: 1;
	u16 cb_access: 1;
	u16 dst_needed: 1;
	u16 blinding_requested: 1;
	u16 blinded: 1;
	u16 is_func: 1;
	u16 kprobe_override: 1;
	u16 has_callchain_buf: 1;
	u16 enforce_expected_attach_type: 1;
	u16 call_get_stack: 1;
	u16 call_get_func_ip: 1;
	u16 tstamp_type_access: 1;
	enum bpf_prog_type type;
	enum bpf_attach_type expected_attach_type;
	u32 len;
	u32 jited_len;
	u8 tag[8];
	struct bpf_prog_stats *stats;
	int *active;
	unsigned int (*bpf_func)(const void *, const struct bpf_insn *);
	struct bpf_prog_aux *aux;
	struct sock_fprog_kern *orig_prog;
	union {
		struct {
			struct {} __empty_insns;
			struct sock_filter insns[0];
		};
		struct {
			struct {} __empty_insnsi;
			struct bpf_insn insnsi[0];
		};
	};
};

struct bpf_map_dev_ops {
	int (*map_get_next_key)(struct bpf_offloaded_map *, void *, void *);
	int (*map_lookup_elem)(struct bpf_offloaded_map *, void *, void *);
	int (*map_update_elem)(struct bpf_offloaded_map *, void *, void *, u64);
	int (*map_delete_elem)(struct bpf_offloaded_map *, void *);
};

struct bpf_offloaded_map {
	struct bpf_map map;
	struct net_device *netdev;
	const struct bpf_map_dev_ops *dev_ops;
	void *dev_priv;
	struct list_head offloads;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

enum bpf_reg_type {
	NOT_INIT = 0,
	SCALAR_VALUE = 1,
	PTR_TO_CTX = 2,
	CONST_PTR_TO_MAP = 3,
	PTR_TO_MAP_VALUE = 4,
	PTR_TO_MAP_KEY = 5,
	PTR_TO_STACK = 6,
	PTR_TO_PACKET_META = 7,
	PTR_TO_PACKET = 8,
	PTR_TO_PACKET_END = 9,
	PTR_TO_FLOW_KEYS = 10,
	PTR_TO_SOCKET = 11,
	PTR_TO_SOCK_COMMON = 12,
	PTR_TO_TCP_SOCK = 13,
	PTR_TO_TP_BUFFER = 14,
	PTR_TO_XDP_SOCK = 15,
	PTR_TO_BTF_ID = 16,
	PTR_TO_MEM = 17,
	PTR_TO_BUF = 18,
	PTR_TO_FUNC = 19,
	__BPF_REG_TYPE_MAX = 20,
	PTR_TO_MAP_VALUE_OR_NULL = 260,
	PTR_TO_SOCKET_OR_NULL = 267,
	PTR_TO_SOCK_COMMON_OR_NULL = 268,
	PTR_TO_TCP_SOCK_OR_NULL = 269,
	PTR_TO_BTF_ID_OR_NULL = 272,
	__BPF_REG_TYPE_LIMIT = 8191,
};

struct bpf_prog_ops {
	int (*test_run)(struct bpf_prog *, const union bpf_attr *, union bpf_attr *);
};

struct bpf_offload_dev;

struct bpf_prog_offload {
	struct bpf_prog *prog;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	void *dev_priv;
	struct list_head offloads;
	bool dev_state;
	bool opt_failed;
	void *jited_image;
	u32 jited_len;
};

struct btf_func_model {
	u8 ret_size;
	u8 nr_args;
	u8 arg_size[12];
};

struct bpf_tramp_image {
	void *image;
	struct bpf_ksym ksym;
	struct percpu_ref pcref;
	void *ip_after_call;
	void *ip_epilogue;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct bpf_trampoline {
	struct hlist_node hlist;
	struct mutex mutex;
	refcount_t refcnt;
	u64 key;
	struct {
		struct btf_func_model model;
		void *addr;
		bool ftrace_managed;
	} func;
	struct bpf_prog *extension_prog;
	struct hlist_head progs_hlist[3];
	int progs_cnt[3];
	struct bpf_tramp_image *cur_image;
	u64 selector;
	struct module *mod;
};

struct bpf_func_info_aux {
	u16 linkage;
	bool unreliable;
};

struct bpf_jit_poke_descriptor {
	void *tailcall_target;
	void *tailcall_bypass;
	void *bypass_addr;
	void *aux;
	union {
		struct {
			struct bpf_map *map;
			u32 key;
		} tail_call;
	};
	bool tailcall_target_stable;
	u8 adj_off;
	u16 reason;
	u32 insn_idx;
};

struct bpf_ctx_arg_aux {
	u32 offset;
	enum bpf_reg_type reg_type;
	u32 btf_id;
};

struct btf_mod_pair {
	struct btf *btf;
	struct module *module;
};

struct bpf_cgroup_storage;

struct bpf_prog_array_item {
	struct bpf_prog *prog;
	union {
		struct bpf_cgroup_storage *cgroup_storage[2];
		u64 bpf_cookie;
	};
};

struct bpf_prog_array {
	struct callback_head rcu;
	struct bpf_prog_array_item items[0];
};

struct tc_stats {
	__u64 bytes;
	__u32 packets;
	__u32 drops;
	__u32 overlimits;
	__u32 bps;
	__u32 pps;
	__u32 qlen;
	__u32 backlog;
};

struct tc_sizespec {
	unsigned char cell_log;
	unsigned char size_log;
	short int cell_align;
	int overhead;
	unsigned int linklayer;
	unsigned int mpu;
	unsigned int mtu;
	unsigned int tsize;
};

struct net_rate_estimator;

struct qdisc_skb_head {
	struct sk_buff *head;
	struct sk_buff *tail;
	__u32 qlen;
	spinlock_t lock;
};

struct gnet_stats_basic_sync {
	u64_stats_t bytes;
	u64_stats_t packets;
	struct u64_stats_sync syncp;
};

struct gnet_stats_queue {
	__u32 qlen;
	__u32 backlog;
	__u32 drops;
	__u32 requeues;
	__u32 overlimits;
};

struct Qdisc_ops;

struct qdisc_size_table;

struct Qdisc {
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	unsigned int flags;
	u32 limit;
	const struct Qdisc_ops *ops;
	struct qdisc_size_table *stab;
	struct hlist_node hash;
	u32 handle;
	u32 parent;
	struct netdev_queue *dev_queue;
	struct net_rate_estimator *rate_est;
	struct gnet_stats_basic_sync *cpu_bstats;
	struct gnet_stats_queue *cpu_qstats;
	int pad;
	refcount_t refcnt;
	struct sk_buff_head gso_skb;
	struct qdisc_skb_head q;
	int: 32;
	int: 32;
	struct gnet_stats_basic_sync bstats;
	struct gnet_stats_queue qstats;
	long unsigned int state;
	long unsigned int state2;
	struct Qdisc *next_sched;
	struct sk_buff_head skb_bad_txq;
	spinlock_t busylock;
	spinlock_t seqlock;
	struct callback_head rcu;
	netdevice_tracker dev_tracker;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	long int privdata[0];
};

struct tcmsg {
	unsigned char tcm_family;
	unsigned char tcm__pad1;
	short unsigned int tcm__pad2;
	int tcm_ifindex;
	__u32 tcm_handle;
	__u32 tcm_parent;
	__u32 tcm_info;
};

struct gnet_dump {
	spinlock_t *lock;
	struct sk_buff *skb;
	struct nlattr *tail;
	int compat_tc_stats;
	int compat_xstats;
	int padattr;
	void *xstats;
	int xstats_len;
	struct tc_stats tc_stats;
};

enum flow_action_hw_stats_bit {
	FLOW_ACTION_HW_STATS_IMMEDIATE_BIT = 0,
	FLOW_ACTION_HW_STATS_DELAYED_BIT = 1,
	FLOW_ACTION_HW_STATS_DISABLED_BIT = 2,
	FLOW_ACTION_HW_STATS_NUM_BITS = 3,
};

struct flow_block {
	struct list_head cb_list;
};

typedef int flow_setup_cb_t(enum tc_setup_type, void *, void *);

struct qdisc_size_table {
	struct callback_head rcu;
	struct list_head list;
	struct tc_sizespec szopts;
	int refcnt;
	u16 data[0];
};

struct Qdisc_class_ops;

struct Qdisc_ops {
	struct Qdisc_ops *next;
	const struct Qdisc_class_ops *cl_ops;
	char id[16];
	int priv_size;
	unsigned int static_flags;
	int (*enqueue)(struct sk_buff *, struct Qdisc *, struct sk_buff **);
	struct sk_buff * (*dequeue)(struct Qdisc *);
	struct sk_buff * (*peek)(struct Qdisc *);
	int (*init)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*reset)(struct Qdisc *);
	void (*destroy)(struct Qdisc *);
	int (*change)(struct Qdisc *, struct nlattr *, struct netlink_ext_ack *);
	void (*attach)(struct Qdisc *);
	int (*change_tx_queue_len)(struct Qdisc *, unsigned int);
	void (*change_real_num_tx)(struct Qdisc *, unsigned int);
	int (*dump)(struct Qdisc *, struct sk_buff *);
	int (*dump_stats)(struct Qdisc *, struct gnet_dump *);
	void (*ingress_block_set)(struct Qdisc *, u32);
	void (*egress_block_set)(struct Qdisc *, u32);
	u32 (*ingress_block_get)(struct Qdisc *);
	u32 (*egress_block_get)(struct Qdisc *);
	struct module *owner;
};

struct qdisc_walker;

struct tcf_block;

struct Qdisc_class_ops {
	unsigned int flags;
	struct netdev_queue * (*select_queue)(struct Qdisc *, struct tcmsg *);
	int (*graft)(struct Qdisc *, long unsigned int, struct Qdisc *, struct Qdisc **, struct netlink_ext_ack *);
	struct Qdisc * (*leaf)(struct Qdisc *, long unsigned int);
	void (*qlen_notify)(struct Qdisc *, long unsigned int);
	long unsigned int (*find)(struct Qdisc *, u32);
	int (*change)(struct Qdisc *, u32, u32, struct nlattr **, long unsigned int *, struct netlink_ext_ack *);
	int (*delete)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	void (*walk)(struct Qdisc *, struct qdisc_walker *);
	struct tcf_block * (*tcf_block)(struct Qdisc *, long unsigned int, struct netlink_ext_ack *);
	long unsigned int (*bind_tcf)(struct Qdisc *, long unsigned int, u32);
	void (*unbind_tcf)(struct Qdisc *, long unsigned int);
	int (*dump)(struct Qdisc *, long unsigned int, struct sk_buff *, struct tcmsg *);
	int (*dump_stats)(struct Qdisc *, long unsigned int, struct gnet_dump *);
};

struct tcf_chain;

struct tcf_block {
	struct mutex lock;
	struct list_head chain_list;
	u32 index;
	u32 classid;
	refcount_t refcnt;
	struct net *net;
	struct Qdisc *q;
	struct rw_semaphore cb_lock;
	struct flow_block flow_block;
	struct list_head owner_list;
	bool keep_dst;
	atomic_t offloadcnt;
	unsigned int nooffloaddevcnt;
	unsigned int lockeddevcnt;
	struct {
		struct tcf_chain *chain;
		struct list_head filter_chain_list;
	} chain0;
	struct callback_head rcu;
	struct hlist_head proto_destroy_ht[128];
	struct mutex proto_destroy_lock;
};

struct tcf_result;

struct tcf_proto_ops;

struct tcf_proto {
	struct tcf_proto *next;
	void *root;
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	__be16 protocol;
	u32 prio;
	void *data;
	const struct tcf_proto_ops *ops;
	struct tcf_chain *chain;
	spinlock_t lock;
	bool deleting;
	refcount_t refcnt;
	struct callback_head rcu;
	struct hlist_node destroy_ht_node;
};

struct tcf_result {
	union {
		struct {
			long unsigned int class;
			u32 classid;
		};
		const struct tcf_proto *goto_tp;
		struct {
			bool ingress;
			struct gnet_stats_queue *qstats;
		};
	};
};

struct tcf_walker;

struct tcf_proto_ops {
	struct list_head head;
	char kind[16];
	int (*classify)(struct sk_buff *, const struct tcf_proto *, struct tcf_result *);
	int (*init)(struct tcf_proto *);
	void (*destroy)(struct tcf_proto *, bool, struct netlink_ext_ack *);
	void * (*get)(struct tcf_proto *, u32);
	void (*put)(struct tcf_proto *, void *);
	int (*change)(struct net *, struct sk_buff *, struct tcf_proto *, long unsigned int, u32, struct nlattr **, void **, u32, struct netlink_ext_ack *);
	int (*delete)(struct tcf_proto *, void *, bool *, bool, struct netlink_ext_ack *);
	bool (*delete_empty)(struct tcf_proto *);
	void (*walk)(struct tcf_proto *, struct tcf_walker *, bool);
	int (*reoffload)(struct tcf_proto *, bool, flow_setup_cb_t *, void *, struct netlink_ext_ack *);
	void (*hw_add)(struct tcf_proto *, void *);
	void (*hw_del)(struct tcf_proto *, void *);
	void (*bind_class)(void *, u32, long unsigned int, void *, long unsigned int);
	void * (*tmplt_create)(struct net *, struct tcf_chain *, struct nlattr **, struct netlink_ext_ack *);
	void (*tmplt_destroy)(void *);
	int (*dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*terse_dump)(struct net *, struct tcf_proto *, void *, struct sk_buff *, struct tcmsg *, bool);
	int (*tmplt_dump)(struct sk_buff *, struct net *, void *);
	struct module *owner;
	int flags;
};

struct tcf_chain {
	struct mutex filter_chain_lock;
	struct tcf_proto *filter_chain;
	struct list_head list;
	struct tcf_block *block;
	u32 index;
	unsigned int refcnt;
	unsigned int action_refcnt;
	bool explicitly_created;
	bool flushing;
	const struct tcf_proto_ops *tmplt_ops;
	void *tmplt_priv;
	struct callback_head rcu;
};

struct sock_fprog_kern {
	u16 len;
	struct sock_filter *filter;
};

struct bpf_binary_header {
	u32 size;
	int: 32;
	u8 image[0];
};

struct bpf_prog_stats {
	u64_stats_t cnt;
	u64_stats_t nsecs;
	u64_stats_t misses;
	struct u64_stats_sync syncp;
	int: 32;
	int: 32;
};

typedef void (*bpf_jit_fill_hole_t)(void *, unsigned int);

enum {
	ARC_R_0 = 0,
	ARC_R_1 = 1,
	ARC_R_2 = 2,
	ARC_R_3 = 3,
	ARC_R_4 = 4,
	ARC_R_5 = 5,
	ARC_R_6 = 6,
	ARC_R_7 = 7,
	ARC_R_8 = 8,
	ARC_R_9 = 9,
	ARC_R_10 = 10,
	ARC_R_11 = 11,
	ARC_R_12 = 12,
	ARC_R_13 = 13,
	ARC_R_14 = 14,
	ARC_R_15 = 15,
	ARC_R_16 = 16,
	ARC_R_17 = 17,
	ARC_R_18 = 18,
	ARC_R_19 = 19,
	ARC_R_20 = 20,
	ARC_R_21 = 21,
	ARC_R_22 = 22,
	ARC_R_23 = 23,
	ARC_R_24 = 24,
	ARC_R_25 = 25,
	ARC_R_26 = 26,
	ARC_R_FP = 27,
	ARC_R_SP = 28,
	ARC_R_ILINK = 29,
	ARC_R_30 = 30,
	ARC_R_BLINK = 31,
	ARC_R_IMM = 62,
};

enum {
	INSN_len_short = 2,
	INSN_len_normal = 4,
	INSN_len_imm = 4,
};

enum {
	ZZ_1_byte = 1,
	ZZ_2_byte = 2,
	ZZ_4_byte = 0,
	ZZ_8_byte = 3,
};

enum {
	AA_none = 0,
	AA_pre = 1,
	AA_post = 2,
	AA_scale = 3,
};

enum {
	D_cached = 0,
	D_direct = 1,
};

enum {
	X_zero = 0,
	X_sign = 1,
};

enum {
	CC_always = 0,
	CC_equal = 1,
	CC_unequal = 2,
	CC_positive = 3,
	CC_negative = 4,
	CC_less_u = 5,
	CC_less_eq_u = 14,
	CC_great_eq_u = 6,
	CC_great_u = 13,
	CC_less_s = 11,
	CC_less_eq_s = 12,
	CC_great_eq_s = 10,
	CC_great_s = 9,
};

struct jit_buffer {
	u8 *buf;
	u32 len;
	u32 index;
};

struct arc_jit_data {
	struct bpf_binary_header *bpf_header;
	u32 *bpf2insn;
};

struct jit_context {
	struct bpf_prog *prog;
	struct bpf_prog *orig_prog;
	struct jit_buffer jit;
	struct bpf_binary_header *bpf_header;
	u32 *bpf2insn;
	bool bpf2insn_valid;
	struct arc_jit_data *jit_data;
	u32 arc_regs_clobbered;
	bool save_blink;
	u16 frame_size;
	u32 epilogue_offset;
	bool need_extra_pass;
	bool blinded;
	bool success;
};

enum OP_TYPES {
	OP_R32_R32 = 0,
	OP_R32_I32 = 1,
	OP_R64_R64 = 2,
	OP_R64_I32 = 3,
};

typedef long unsigned int uintptr_t;

typedef void (*rcu_callback_t)(struct callback_head *);

enum tk_offsets {
	TK_OFFS_REAL = 0,
	TK_OFFS_BOOT = 1,
	TK_OFFS_TAI = 2,
	TK_OFFS_MAX = 3,
};

enum {
	WORK_STRUCT_PENDING_BIT = 0,
	WORK_STRUCT_INACTIVE_BIT = 1,
	WORK_STRUCT_PWQ_BIT = 2,
	WORK_STRUCT_LINKED_BIT = 3,
	WORK_STRUCT_COLOR_SHIFT = 4,
	WORK_STRUCT_COLOR_BITS = 4,
	WORK_STRUCT_PENDING = 1,
	WORK_STRUCT_INACTIVE = 2,
	WORK_STRUCT_PWQ = 4,
	WORK_STRUCT_LINKED = 8,
	WORK_STRUCT_STATIC = 0,
	WORK_NR_COLORS = 16,
	WORK_CPU_UNBOUND = 1,
	WORK_STRUCT_FLAG_BITS = 8,
	WORK_OFFQ_FLAG_BASE = 4,
	__WORK_OFFQ_CANCELING = 4,
	WORK_OFFQ_CANCELING = 16,
	WORK_OFFQ_FLAG_BITS = 1,
	WORK_OFFQ_POOL_SHIFT = 5,
	WORK_OFFQ_LEFT = 27,
	WORK_OFFQ_POOL_BITS = 27,
	WORK_OFFQ_POOL_NONE = 134217727,
	WORK_STRUCT_FLAG_MASK = 255,
	WORK_STRUCT_WQ_DATA_MASK = 4294967040,
	WORK_STRUCT_NO_POOL = 4294967264,
	WORK_BUSY_PENDING = 1,
	WORK_BUSY_RUNNING = 2,
	WORKER_DESC_LEN = 24,
};

typedef long unsigned int vm_flags_t;

struct clone_args {
	__u64 flags;
	__u64 pidfd;
	__u64 child_tid;
	__u64 parent_tid;
	__u64 exit_signal;
	__u64 stack;
	__u64 stack_size;
	__u64 tls;
	__u64 set_tid;
	__u64 set_tid_size;
	__u64 cgroup;
};

enum hrtimer_mode {
	HRTIMER_MODE_ABS = 0,
	HRTIMER_MODE_REL = 1,
	HRTIMER_MODE_PINNED = 2,
	HRTIMER_MODE_SOFT = 4,
	HRTIMER_MODE_HARD = 8,
	HRTIMER_MODE_ABS_PINNED = 2,
	HRTIMER_MODE_REL_PINNED = 3,
	HRTIMER_MODE_ABS_SOFT = 4,
	HRTIMER_MODE_REL_SOFT = 5,
	HRTIMER_MODE_ABS_PINNED_SOFT = 6,
	HRTIMER_MODE_REL_PINNED_SOFT = 7,
	HRTIMER_MODE_ABS_HARD = 8,
	HRTIMER_MODE_REL_HARD = 9,
	HRTIMER_MODE_ABS_PINNED_HARD = 10,
	HRTIMER_MODE_REL_PINNED_HARD = 11,
};

struct fdtable {
	unsigned int max_fds;
	struct file **fd;
	long unsigned int *close_on_exec;
	long unsigned int *open_fds;
	long unsigned int *full_fds_bits;
	struct callback_head rcu;
};

struct files_struct {
	atomic_t count;
	bool resize_in_progress;
	wait_queue_head_t resize_wait;
	struct fdtable *fdt;
	struct fdtable fdtab;
	spinlock_t file_lock;
	unsigned int next_fd;
	long unsigned int close_on_exec_init[1];
	long unsigned int open_fds_init[1];
	long unsigned int full_fds_bits_init[1];
	struct file *fd_array[32];
};

struct robust_list {
	struct robust_list *next;
};

struct robust_list_head {
	struct robust_list list;
	long int futex_offset;
	struct robust_list *list_op_pending;
};

struct cgroup;

struct kernel_clone_args {
	u64 flags;
	int *pidfd;
	int *child_tid;
	int *parent_tid;
	int exit_signal;
	long unsigned int stack;
	long unsigned int stack_size;
	long unsigned int tls;
	pid_t *set_tid;
	size_t set_tid_size;
	int cgroup;
	int io_thread;
	struct cgroup *cgrp;
	struct css_set *cset;
};

struct multiprocess_signals {
	sigset_t signal;
	struct hlist_node node;
};

typedef int (*proc_visitor)(struct task_struct *, void *);

struct mempolicy {};

typedef struct poll_table_struct poll_table;

enum {
	FUTEX_STATE_OK = 0,
	FUTEX_STATE_EXITING = 1,
	FUTEX_STATE_DEAD = 2,
};

enum proc_hidepid {
	HIDEPID_OFF = 0,
	HIDEPID_NO_ACCESS = 1,
	HIDEPID_INVISIBLE = 2,
	HIDEPID_NOT_PTRACEABLE = 4,
};

enum proc_pidonly {
	PROC_PIDONLY_OFF = 0,
	PROC_PIDONLY_ON = 1,
};

struct proc_fs_info {
	struct pid_namespace *pid_ns;
	struct dentry *proc_self;
	struct dentry *proc_thread_self;
	kgid_t pid_gid;
	enum proc_hidepid hide_pid;
	enum proc_pidonly pidonly;
};

enum bpf_type_flag {
	PTR_MAYBE_NULL = 256,
	MEM_RDONLY = 512,
	MEM_ALLOC = 1024,
	MEM_USER = 2048,
	MEM_PERCPU = 4096,
	__BPF_TYPE_LAST_FLAG = 4096,
};

enum bpf_arg_type {
	ARG_DONTCARE = 0,
	ARG_CONST_MAP_PTR = 1,
	ARG_PTR_TO_MAP_KEY = 2,
	ARG_PTR_TO_MAP_VALUE = 3,
	ARG_PTR_TO_UNINIT_MAP_VALUE = 4,
	ARG_PTR_TO_MEM = 5,
	ARG_PTR_TO_UNINIT_MEM = 6,
	ARG_CONST_SIZE = 7,
	ARG_CONST_SIZE_OR_ZERO = 8,
	ARG_PTR_TO_CTX = 9,
	ARG_ANYTHING = 10,
	ARG_PTR_TO_SPIN_LOCK = 11,
	ARG_PTR_TO_SOCK_COMMON = 12,
	ARG_PTR_TO_INT = 13,
	ARG_PTR_TO_LONG = 14,
	ARG_PTR_TO_SOCKET = 15,
	ARG_PTR_TO_BTF_ID = 16,
	ARG_PTR_TO_ALLOC_MEM = 17,
	ARG_CONST_ALLOC_SIZE_OR_ZERO = 18,
	ARG_PTR_TO_BTF_ID_SOCK_COMMON = 19,
	ARG_PTR_TO_PERCPU_BTF_ID = 20,
	ARG_PTR_TO_FUNC = 21,
	ARG_PTR_TO_STACK = 22,
	ARG_PTR_TO_CONST_STR = 23,
	ARG_PTR_TO_TIMER = 24,
	__BPF_ARG_TYPE_MAX = 25,
	ARG_PTR_TO_MAP_VALUE_OR_NULL = 259,
	ARG_PTR_TO_MEM_OR_NULL = 261,
	ARG_PTR_TO_CTX_OR_NULL = 265,
	ARG_PTR_TO_SOCKET_OR_NULL = 271,
	ARG_PTR_TO_ALLOC_MEM_OR_NULL = 273,
	ARG_PTR_TO_STACK_OR_NULL = 278,
	__BPF_ARG_TYPE_LIMIT = 8191,
};

enum bpf_return_type {
	RET_INTEGER = 0,
	RET_VOID = 1,
	RET_PTR_TO_MAP_VALUE = 2,
	RET_PTR_TO_SOCKET = 3,
	RET_PTR_TO_TCP_SOCK = 4,
	RET_PTR_TO_SOCK_COMMON = 5,
	RET_PTR_TO_ALLOC_MEM = 6,
	RET_PTR_TO_MEM_OR_BTF_ID = 7,
	RET_PTR_TO_BTF_ID = 8,
	__BPF_RET_TYPE_MAX = 9,
	RET_PTR_TO_MAP_VALUE_OR_NULL = 258,
	RET_PTR_TO_SOCKET_OR_NULL = 259,
	RET_PTR_TO_TCP_SOCK_OR_NULL = 260,
	RET_PTR_TO_SOCK_COMMON_OR_NULL = 261,
	RET_PTR_TO_ALLOC_MEM_OR_NULL = 1286,
	RET_PTR_TO_BTF_ID_OR_NULL = 264,
	__BPF_RET_TYPE_LIMIT = 8191,
};

enum bpf_cgroup_storage_type {
	BPF_CGROUP_STORAGE_SHARED = 0,
	BPF_CGROUP_STORAGE_PERCPU = 1,
	__BPF_CGROUP_STORAGE_MAX = 2,
};

enum bpf_tramp_prog_type {
	BPF_TRAMP_FENTRY = 0,
	BPF_TRAMP_FEXIT = 1,
	BPF_TRAMP_MODIFY_RETURN = 2,
	BPF_TRAMP_MAX = 3,
	BPF_TRAMP_REPLACE = 4,
};

struct trace_event_raw_task_newtask {
	struct trace_entry ent;
	pid_t pid;
	char comm[16];
	long unsigned int clone_flags;
	short int oom_score_adj;
	char __data[0];
};

struct trace_event_raw_task_rename {
	struct trace_entry ent;
	pid_t pid;
	char oldcomm[16];
	char newcomm[16];
	short int oom_score_adj;
	char __data[0];
};

struct trace_event_data_offsets_task_newtask {};

struct trace_event_data_offsets_task_rename {};

typedef void (*btf_trace_task_newtask)(void *, struct task_struct *, long unsigned int);

typedef void (*btf_trace_task_rename)(void *, struct task_struct *, const char *);

struct audit_context;

struct taint_flag {
	char c_true;
	char c_false;
	bool module;
};

enum lockdep_ok {
	LOCKDEP_STILL_OK = 0,
	LOCKDEP_NOW_UNRELIABLE = 1,
};

enum ftrace_dump_mode {
	DUMP_NONE = 0,
	DUMP_ALL = 1,
	DUMP_ORIG = 2,
};

struct atomic_notifier_head {
	spinlock_t lock;
	struct notifier_block *head;
};

enum kmsg_dump_reason {
	KMSG_DUMP_UNDEF = 0,
	KMSG_DUMP_PANIC = 1,
	KMSG_DUMP_OOPS = 2,
	KMSG_DUMP_EMERG = 3,
	KMSG_DUMP_SHUTDOWN = 4,
	KMSG_DUMP_MAX = 5,
};

enum reboot_mode {
	REBOOT_UNDEFINED = 4294967295,
	REBOOT_COLD = 0,
	REBOOT_WARM = 1,
	REBOOT_HARD = 2,
	REBOOT_SOFT = 3,
	REBOOT_GPIO = 4,
};

enum con_flush_mode {
	CONSOLE_FLUSH_PENDING = 0,
	CONSOLE_REPLAY_ALL = 1,
};

enum error_detector {
	ERROR_DETECTOR_KFENCE = 0,
	ERROR_DETECTOR_KASAN = 1,
	ERROR_DETECTOR_WARN = 2,
};

struct warn_args {
	const char *fmt;
	va_list args;
};

struct plist_head {
	struct list_head node_list;
};

enum pm_qos_type {
	PM_QOS_UNITIALIZED = 0,
	PM_QOS_MAX = 1,
	PM_QOS_MIN = 2,
};

struct pm_qos_constraints {
	struct plist_head list;
	s32 target_value;
	s32 default_value;
	s32 no_constraint_value;
	enum pm_qos_type type;
	struct blocking_notifier_head *notifiers;
};

struct freq_constraints {
	struct pm_qos_constraints min_freq;
	struct blocking_notifier_head min_freq_notifiers;
	struct pm_qos_constraints max_freq;
	struct blocking_notifier_head max_freq_notifiers;
};

struct pm_qos_flags {
	struct list_head list;
	s32 effective_flags;
};

struct dev_pm_qos_request;

struct dev_pm_qos {
	struct pm_qos_constraints resume_latency;
	struct pm_qos_constraints latency_tolerance;
	struct freq_constraints freq;
	struct pm_qos_flags flags;
	struct dev_pm_qos_request *resume_latency_req;
	struct dev_pm_qos_request *latency_tolerance_req;
	struct dev_pm_qos_request *flags_req;
};

struct pm_qos_flags_request {
	struct list_head node;
	s32 flags;
};

enum freq_qos_req_type {
	FREQ_QOS_MIN = 1,
	FREQ_QOS_MAX = 2,
};

struct freq_qos_request {
	enum freq_qos_req_type type;
	struct plist_node pnode;
	struct freq_constraints *qos;
};

enum dev_pm_qos_req_type {
	DEV_PM_QOS_RESUME_LATENCY = 1,
	DEV_PM_QOS_LATENCY_TOLERANCE = 2,
	DEV_PM_QOS_MIN_FREQUENCY = 3,
	DEV_PM_QOS_MAX_FREQUENCY = 4,
	DEV_PM_QOS_FLAGS = 5,
};

struct dev_pm_qos_request {
	enum dev_pm_qos_req_type type;
	union {
		struct plist_node pnode;
		struct pm_qos_flags_request flr;
		struct freq_qos_request freq;
	} data;
	struct device *dev;
};

struct trace_event_raw_cpuhp_enter {
	struct trace_entry ent;
	unsigned int cpu;
	int target;
	int idx;
	void *fun;
	char __data[0];
};

struct trace_event_raw_cpuhp_multi_enter {
	struct trace_entry ent;
	unsigned int cpu;
	int target;
	int idx;
	void *fun;
	char __data[0];
};

struct trace_event_raw_cpuhp_exit {
	struct trace_entry ent;
	unsigned int cpu;
	int state;
	int idx;
	int ret;
	char __data[0];
};

struct trace_event_data_offsets_cpuhp_enter {};

struct trace_event_data_offsets_cpuhp_multi_enter {};

struct trace_event_data_offsets_cpuhp_exit {};

typedef void (*btf_trace_cpuhp_enter)(void *, unsigned int, int, int, int (*)(unsigned int));

typedef void (*btf_trace_cpuhp_multi_enter)(void *, unsigned int, int, int, int (*)(unsigned int, struct hlist_node *), struct hlist_node *);

typedef void (*btf_trace_cpuhp_exit)(void *, unsigned int, int, int, int);

struct cpuhp_cpu_state {
	enum cpuhp_state state;
	enum cpuhp_state target;
	enum cpuhp_state fail;
};

struct cpuhp_step {
	const char *name;
	union {
		int (*single)(unsigned int);
		int (*multi)(unsigned int, struct hlist_node *);
	} startup;
	union {
		int (*single)(unsigned int);
		int (*multi)(unsigned int, struct hlist_node *);
	} teardown;
	struct hlist_head list;
	bool cant_stop;
	bool multi_instance;
};

enum cpu_mitigations {
	CPU_MITIGATIONS_OFF = 0,
	CPU_MITIGATIONS_AUTO = 1,
	CPU_MITIGATIONS_AUTO_NOSMT = 2,
};

struct waitid_info {
	pid_t pid;
	uid_t uid;
	int status;
	int cause;
};

struct wait_opts {
	enum pid_type wo_type;
	int wo_flags;
	struct pid *wo_pid;
	struct waitid_info *wo_info;
	int wo_stat;
	struct rusage *wo_rusage;
	wait_queue_entry_t child_wait;
	int notask_error;
};

typedef struct {
	unsigned int __softirq_pending;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
} irq_cpustat_t;

struct softirq_action {
	void (*action)(struct softirq_action *);
};

struct tasklet_struct {
	struct tasklet_struct *next;
	long unsigned int state;
	atomic_t count;
	bool use_callback;
	union {
		void (*func)(long unsigned int);
		void (*callback)(struct tasklet_struct *);
	};
	long unsigned int data;
};

enum {
	TASKLET_STATE_SCHED = 0,
	TASKLET_STATE_RUN = 1,
};

struct kernel_stat {
	long unsigned int irqs_sum;
	unsigned int softirqs[10];
};

struct trace_print_flags {
	long unsigned int mask;
	const char *name;
};

struct wait_bit_key {
	void *flags;
	int bit_nr;
	long unsigned int timeout;
};

struct wait_bit_queue_entry {
	struct wait_bit_key key;
	struct wait_queue_entry wq_entry;
};

struct smp_hotplug_thread {
	struct task_struct **store;
	struct list_head list;
	int (*thread_should_run)(unsigned int);
	void (*thread_fn)(unsigned int);
	void (*create)(unsigned int);
	void (*setup)(unsigned int);
	void (*cleanup)(unsigned int, bool);
	void (*park)(unsigned int);
	void (*unpark)(unsigned int);
	bool selfparking;
	const char *thread_comm;
};

struct trace_event_raw_irq_handler_entry {
	struct trace_entry ent;
	int irq;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_irq_handler_exit {
	struct trace_entry ent;
	int irq;
	int ret;
	char __data[0];
};

struct trace_event_raw_softirq {
	struct trace_entry ent;
	unsigned int vec;
	char __data[0];
};

struct trace_event_data_offsets_irq_handler_entry {
	u32 name;
};

struct trace_event_data_offsets_irq_handler_exit {};

struct trace_event_data_offsets_softirq {};

typedef void (*btf_trace_irq_handler_entry)(void *, int, struct irqaction *);

typedef void (*btf_trace_irq_handler_exit)(void *, int, struct irqaction *, int);

typedef void (*btf_trace_softirq_entry)(void *, unsigned int);

typedef void (*btf_trace_softirq_exit)(void *, unsigned int);

typedef void (*btf_trace_softirq_raise)(void *, unsigned int);

struct tasklet_head {
	struct tasklet_struct *head;
	struct tasklet_struct **tail;
};

enum {
	IORES_DESC_NONE = 0,
	IORES_DESC_CRASH_KERNEL = 1,
	IORES_DESC_ACPI_TABLES = 2,
	IORES_DESC_ACPI_NV_STORAGE = 3,
	IORES_DESC_PERSISTENT_MEMORY = 4,
	IORES_DESC_PERSISTENT_MEMORY_LEGACY = 5,
	IORES_DESC_DEVICE_PRIVATE_MEMORY = 6,
	IORES_DESC_RESERVED = 7,
	IORES_DESC_SOFT_RESERVED = 8,
};

enum {
	REGION_INTERSECTS = 0,
	REGION_DISJOINT = 1,
	REGION_MIXED = 2,
};

struct pseudo_fs_context {
	const struct super_operations *ops;
	const struct xattr_handler **xattr;
	const struct dentry_operations *dops;
	long unsigned int magic;
};

typedef void (*dr_release_t)(struct device *, void *);

typedef int (*dr_match_t)(struct device *, void *, void *);

struct resource_entry {
	struct list_head node;
	struct resource *res;
	resource_size_t offset;
	struct resource __res;
};

struct resource_constraint {
	resource_size_t min;
	resource_size_t max;
	resource_size_t align;
	resource_size_t (*alignf)(void *, const struct resource *, resource_size_t, resource_size_t);
	void *alignf_data;
};

enum {
	MAX_IORES_LEVEL = 5,
};

struct region_devres {
	struct resource *parent;
	resource_size_t start;
	resource_size_t n;
};

typedef __kernel_clock_t clock_t;

struct sk_filter {
	refcount_t refcnt;
	struct callback_head rcu;
	struct bpf_prog *prog;
};

enum sysctl_writes_mode {
	SYSCTL_WRITES_LEGACY = 4294967295,
	SYSCTL_WRITES_WARN = 0,
	SYSCTL_WRITES_STRICT = 1,
};

struct do_proc_dointvec_minmax_conv_param {
	int *min;
	int *max;
};

struct do_proc_douintvec_minmax_conv_param {
	unsigned int *min;
	unsigned int *max;
};

struct sigqueue {
	struct list_head list;
	int flags;
	kernel_siginfo_t info;
	struct ucounts *ucounts;
};

enum siginfo_layout {
	SIL_KILL = 0,
	SIL_TIMER = 1,
	SIL_POLL = 2,
	SIL_FAULT = 3,
	SIL_FAULT_TRAPNO = 4,
	SIL_FAULT_MCEERR = 5,
	SIL_FAULT_BNDERR = 6,
	SIL_FAULT_PKUERR = 7,
	SIL_FAULT_PERF_EVENT = 8,
	SIL_CHLD = 9,
	SIL_RT = 10,
	SIL_SYS = 11,
};

struct fd {
	struct file *file;
	unsigned int flags;
};

struct core_vma_metadata;

struct coredump_params {
	const kernel_siginfo_t *siginfo;
	struct pt_regs *regs;
	struct file *file;
	long unsigned int limit;
	long unsigned int mm_flags;
	loff_t written;
	loff_t pos;
	loff_t to_skip;
	int vma_count;
	size_t vma_data_size;
	struct core_vma_metadata *vma_meta;
};

struct core_vma_metadata {
	long unsigned int start;
	long unsigned int end;
	long unsigned int flags;
	long unsigned int dump_size;
	long unsigned int pgoff;
	struct file *file;
};

enum {
	TRACE_SIGNAL_DELIVERED = 0,
	TRACE_SIGNAL_IGNORED = 1,
	TRACE_SIGNAL_ALREADY_PENDING = 2,
	TRACE_SIGNAL_OVERFLOW_FAIL = 3,
	TRACE_SIGNAL_LOSE_INFO = 4,
};

struct trace_event_raw_signal_generate {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	char comm[16];
	pid_t pid;
	int group;
	int result;
	char __data[0];
};

struct trace_event_raw_signal_deliver {
	struct trace_entry ent;
	int sig;
	int errno;
	int code;
	long unsigned int sa_handler;
	long unsigned int sa_flags;
	char __data[0];
};

struct trace_event_data_offsets_signal_generate {};

struct trace_event_data_offsets_signal_deliver {};

typedef void (*btf_trace_signal_generate)(void *, int, struct kernel_siginfo *, struct task_struct *, int, int);

typedef void (*btf_trace_signal_deliver)(void *, int, struct kernel_siginfo *, struct k_sigaction *);

enum sig_handler {
	HANDLER_CURRENT = 0,
	HANDLER_SIG_DFL = 1,
	HANDLER_EXIT = 2,
};

struct timens_offsets {
	struct timespec64 monotonic;
	struct timespec64 boottime;
};

struct time_namespace {
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct ns_common ns;
	struct timens_offsets offsets;
	struct page *vvar_page;
	bool frozen_offsets;
};

enum uts_proc {
	UTS_PROC_OSTYPE = 0,
	UTS_PROC_OSRELEASE = 1,
	UTS_PROC_VERSION = 2,
	UTS_PROC_HOSTNAME = 3,
	UTS_PROC_DOMAINNAME = 4,
};

struct prctl_mm_map {
	__u64 start_code;
	__u64 end_code;
	__u64 start_data;
	__u64 end_data;
	__u64 start_brk;
	__u64 brk;
	__u64 start_stack;
	__u64 arg_start;
	__u64 arg_end;
	__u64 env_start;
	__u64 env_end;
	__u64 *auxv;
	__u32 auxv_size;
	__u32 exe_fd;
};

struct tms {
	__kernel_clock_t tms_utime;
	__kernel_clock_t tms_stime;
	__kernel_clock_t tms_cutime;
	__kernel_clock_t tms_cstime;
};

struct getcpu_cache {
	long unsigned int blob[32];
};

struct wq_flusher;

struct worker;

struct workqueue_attrs;

struct pool_workqueue;

struct wq_device;

struct workqueue_struct {
	struct list_head pwqs;
	struct list_head list;
	struct mutex mutex;
	int work_color;
	int flush_color;
	atomic_t nr_pwqs_to_flush;
	struct wq_flusher *first_flusher;
	struct list_head flusher_queue;
	struct list_head flusher_overflow;
	struct list_head maydays;
	struct worker *rescuer;
	int nr_drainers;
	int saved_max_active;
	struct workqueue_attrs *unbound_attrs;
	struct pool_workqueue *dfl_pwq;
	struct wq_device *wq_dev;
	char name[24];
	struct callback_head rcu;
	int: 32;
	unsigned int flags;
	struct pool_workqueue *cpu_pwqs;
	struct pool_workqueue *numa_pwq_tbl[0];
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct rcu_work {
	struct work_struct work;
	struct callback_head rcu;
	struct workqueue_struct *wq;
};

struct workqueue_attrs {
	int nice;
	cpumask_var_t cpumask;
	bool no_numa;
};

struct execute_work {
	struct work_struct work;
};

enum {
	WQ_UNBOUND = 2,
	WQ_FREEZABLE = 4,
	WQ_MEM_RECLAIM = 8,
	WQ_HIGHPRI = 16,
	WQ_CPU_INTENSIVE = 32,
	WQ_SYSFS = 64,
	WQ_POWER_EFFICIENT = 128,
	__WQ_DRAINING = 65536,
	__WQ_ORDERED = 131072,
	__WQ_LEGACY = 262144,
	__WQ_ORDERED_EXPLICIT = 524288,
	WQ_MAX_ACTIVE = 512,
	WQ_MAX_UNBOUND_PER_CPU = 4,
	WQ_DFL_ACTIVE = 256,
};

typedef unsigned int xa_mark_t;

enum xa_lock_type {
	XA_LOCK_IRQ = 1,
	XA_LOCK_BH = 2,
};

struct ida {
	struct xarray xa;
};

enum kobject_action {
	KOBJ_ADD = 0,
	KOBJ_REMOVE = 1,
	KOBJ_CHANGE = 2,
	KOBJ_MOVE = 3,
	KOBJ_ONLINE = 4,
	KOBJ_OFFLINE = 5,
	KOBJ_BIND = 6,
	KOBJ_UNBIND = 7,
};

struct __una_u32 {
	u32 x;
};

enum hk_type {
	HK_TYPE_TIMER = 0,
	HK_TYPE_RCU = 1,
	HK_TYPE_MISC = 2,
	HK_TYPE_SCHED = 3,
	HK_TYPE_TICK = 4,
	HK_TYPE_DOMAIN = 5,
	HK_TYPE_WQ = 6,
	HK_TYPE_MANAGED_IRQ = 7,
	HK_TYPE_KTHREAD = 8,
	HK_TYPE_MAX = 9,
};

struct worker_pool;

struct worker {
	union {
		struct list_head entry;
		struct hlist_node hentry;
	};
	struct work_struct *current_work;
	work_func_t current_func;
	struct pool_workqueue *current_pwq;
	unsigned int current_color;
	struct list_head scheduled;
	struct task_struct *task;
	struct worker_pool *pool;
	struct list_head node;
	long unsigned int last_active;
	unsigned int flags;
	int id;
	int sleeping;
	char desc[24];
	struct workqueue_struct *rescue_wq;
	work_func_t last_func;
};

struct pool_workqueue {
	struct worker_pool *pool;
	struct workqueue_struct *wq;
	int work_color;
	int flush_color;
	int refcnt;
	int nr_in_flight[16];
	int nr_active;
	int max_active;
	struct list_head inactive_works;
	struct list_head pwqs_node;
	struct list_head mayday_node;
	struct work_struct unbound_release_work;
	struct callback_head rcu;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct worker_pool {
	raw_spinlock_t lock;
	int cpu;
	int node;
	int id;
	unsigned int flags;
	long unsigned int watchdog_ts;
	int nr_running;
	struct list_head worklist;
	int nr_workers;
	int nr_idle;
	struct list_head idle_list;
	struct timer_list idle_timer;
	struct timer_list mayday_timer;
	struct hlist_head busy_hash[64];
	struct worker *manager;
	struct list_head workers;
	struct completion *detach_completion;
	struct ida worker_ida;
	struct workqueue_attrs *attrs;
	struct hlist_node hash_node;
	int refcnt;
	struct callback_head rcu;
};

enum {
	POOL_MANAGER_ACTIVE = 1,
	POOL_DISASSOCIATED = 4,
	WORKER_DIE = 2,
	WORKER_IDLE = 4,
	WORKER_PREP = 8,
	WORKER_CPU_INTENSIVE = 64,
	WORKER_UNBOUND = 128,
	WORKER_REBOUND = 256,
	WORKER_NOT_RUNNING = 456,
	NR_STD_WORKER_POOLS = 2,
	UNBOUND_POOL_HASH_ORDER = 6,
	BUSY_WORKER_HASH_ORDER = 6,
	MAX_IDLE_WORKERS_RATIO = 4,
	IDLE_WORKER_TIMEOUT = 30000,
	MAYDAY_INITIAL_TIMEOUT = 2,
	MAYDAY_INTERVAL = 10,
	CREATE_COOLDOWN = 100,
	RESCUER_NICE_LEVEL = 4294967276,
	HIGHPRI_NICE_LEVEL = 4294967276,
	WQ_NAME_LEN = 24,
};

struct wq_flusher {
	struct list_head list;
	int flush_color;
	struct completion done;
};

struct wq_device {
	struct workqueue_struct *wq;
	struct device dev;
};

struct trace_event_raw_workqueue_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	u32 __data_loc_workqueue;
	unsigned int req_cpu;
	unsigned int cpu;
	char __data[0];
};

struct trace_event_raw_workqueue_activate_work {
	struct trace_entry ent;
	void *work;
	char __data[0];
};

struct trace_event_raw_workqueue_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_workqueue_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_data_offsets_workqueue_queue_work {
	u32 workqueue;
};

struct trace_event_data_offsets_workqueue_activate_work {};

struct trace_event_data_offsets_workqueue_execute_start {};

struct trace_event_data_offsets_workqueue_execute_end {};

typedef void (*btf_trace_workqueue_queue_work)(void *, unsigned int, struct pool_workqueue *, struct work_struct *);

typedef void (*btf_trace_workqueue_activate_work)(void *, struct work_struct *);

typedef void (*btf_trace_workqueue_execute_start)(void *, struct work_struct *);

typedef void (*btf_trace_workqueue_execute_end)(void *, struct work_struct *, work_func_t);

struct wq_barrier {
	struct work_struct work;
	struct completion done;
	struct task_struct *task;
};

struct cwt_wait {
	wait_queue_entry_t wait;
	struct work_struct *work;
};

struct apply_wqattrs_ctx {
	struct workqueue_struct *wq;
	struct workqueue_attrs *attrs;
	struct list_head list;
	struct pool_workqueue *dfl_pwq;
	struct pool_workqueue *pwq_tbl[0];
};

typedef int wait_bit_action_f(struct wait_bit_key *, int);

struct ptrace_peeksiginfo_args {
	__u64 off;
	__u32 flags;
	__s32 nr;
};

struct ptrace_syscall_info {
	__u8 op;
	__u8 pad[3];
	__u32 arch;
	__u64 instruction_pointer;
	__u64 stack_pointer;
	union {
		struct {
			__u64 nr;
			__u64 args[6];
		} entry;
		struct {
			__s64 rval;
			__u8 is_error;
		} exit;
		struct {
			__u64 nr;
			__u64 args[6];
			__u32 ret_data;
		} seccomp;
	};
};

typedef void (*task_work_func_t)(struct callback_head *);

enum task_work_notify_mode {
	TWA_NONE = 0,
	TWA_RESUME = 1,
	TWA_SIGNAL = 2,
};

typedef struct {} local_lock_t;

struct xa_node {
	unsigned char shift;
	unsigned char offset;
	unsigned char count;
	unsigned char nr_values;
	struct xa_node *parent;
	struct xarray *array;
	union {
		struct list_head private_list;
		struct callback_head callback_head;
	};
	void *slots[64];
	union {
		long unsigned int tags[6];
		long unsigned int marks[6];
	};
};

struct radix_tree_preload {
	local_lock_t lock;
	unsigned int nr;
	struct xa_node *nodes;
};

struct sched_param {
	int sched_priority;
};

struct kthread_work;

typedef void (*kthread_work_func_t)(struct kthread_work *);

struct kthread_worker;

struct kthread_work {
	struct list_head node;
	kthread_work_func_t func;
	struct kthread_worker *worker;
	int canceling;
};

enum {
	KTW_FREEZABLE = 1,
};

struct kthread_worker {
	unsigned int flags;
	raw_spinlock_t lock;
	struct list_head work_list;
	struct list_head delayed_work_list;
	struct task_struct *task;
	struct kthread_work *current_work;
};

struct kthread_delayed_work {
	struct kthread_work work;
	struct timer_list timer;
};

struct kthread_create_info {
	int (*threadfn)(void *);
	void *data;
	int node;
	struct task_struct *result;
	struct completion *done;
	struct list_head list;
};

struct kthread {
	long unsigned int flags;
	unsigned int cpu;
	int result;
	int (*threadfn)(void *);
	void *data;
	struct completion parked;
	struct completion exited;
	char *full_name;
};

enum KTHREAD_BITS {
	KTHREAD_IS_PER_CPU = 0,
	KTHREAD_SHOULD_STOP = 1,
	KTHREAD_SHOULD_PARK = 2,
};

struct kthread_flush_work {
	struct kthread_work work;
	struct completion done;
};

struct ipc_ids {
	int in_use;
	short unsigned int seq;
	struct rw_semaphore rwsem;
	struct idr ipcs_idr;
	int max_idx;
	int last_idx;
	struct rhashtable key_ht;
};

struct ipc_namespace {
	struct ipc_ids ids[3];
	int sem_ctls[4];
	int used_sems;
	unsigned int msg_ctlmax;
	unsigned int msg_ctlmnb;
	unsigned int msg_ctlmni;
	atomic_t msg_bytes;
	atomic_t msg_hdrs;
	size_t shm_ctlmax;
	size_t shm_ctlall;
	long unsigned int shm_tot;
	int shm_ctlmni;
	int shm_rmid_forced;
	struct notifier_block ipcns_nb;
	struct vfsmount *mq_mnt;
	unsigned int mq_queues_count;
	unsigned int mq_queues_max;
	unsigned int mq_msg_max;
	unsigned int mq_msgsize_max;
	unsigned int mq_msg_default;
	unsigned int mq_msgsize_default;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	struct llist_node mnt_llist;
	struct ns_common ns;
};

enum {
	KERNEL_PARAM_OPS_FL_NOARG = 1,
};

enum {
	KERNEL_PARAM_FL_UNSAFE = 1,
	KERNEL_PARAM_FL_HWPARAM = 2,
};

struct param_attribute {
	struct module_attribute mattr;
	const struct kernel_param *param;
};

struct module_param_attrs {
	unsigned int num;
	struct attribute_group grp;
	struct param_attribute attrs[0];
};

struct module_version_attribute {
	struct module_attribute mattr;
	const char *module_name;
	const char *version;
};

enum lockdown_reason {
	LOCKDOWN_NONE = 0,
	LOCKDOWN_MODULE_SIGNATURE = 1,
	LOCKDOWN_DEV_MEM = 2,
	LOCKDOWN_EFI_TEST = 3,
	LOCKDOWN_KEXEC = 4,
	LOCKDOWN_HIBERNATION = 5,
	LOCKDOWN_PCI_ACCESS = 6,
	LOCKDOWN_IOPORT = 7,
	LOCKDOWN_MSR = 8,
	LOCKDOWN_ACPI_TABLES = 9,
	LOCKDOWN_PCMCIA_CIS = 10,
	LOCKDOWN_TIOCSSERIAL = 11,
	LOCKDOWN_MODULE_PARAMETERS = 12,
	LOCKDOWN_MMIOTRACE = 13,
	LOCKDOWN_DEBUGFS = 14,
	LOCKDOWN_XMON_WR = 15,
	LOCKDOWN_BPF_WRITE_USER = 16,
	LOCKDOWN_INTEGRITY_MAX = 17,
	LOCKDOWN_KCORE = 18,
	LOCKDOWN_KPROBES = 19,
	LOCKDOWN_BPF_READ_KERNEL = 20,
	LOCKDOWN_PERF = 21,
	LOCKDOWN_TRACEFS = 22,
	LOCKDOWN_XMON_RW = 23,
	LOCKDOWN_XFRM_SECRET = 24,
	LOCKDOWN_CONFIDENTIALITY_MAX = 25,
};

struct kmalloced_param {
	struct list_head list;
	char val[0];
};

struct srcu_notifier_head {
	struct mutex mutex;
	struct srcu_struct srcu;
	struct notifier_block *head;
};

struct kobj_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kobject *, struct kobj_attribute *, char *);
	ssize_t (*store)(struct kobject *, struct kobj_attribute *, const char *, size_t);
};

enum what {
	PROC_EVENT_NONE = 0,
	PROC_EVENT_FORK = 1,
	PROC_EVENT_EXEC = 2,
	PROC_EVENT_UID = 4,
	PROC_EVENT_GID = 64,
	PROC_EVENT_SID = 128,
	PROC_EVENT_PTRACE = 256,
	PROC_EVENT_COMM = 512,
	PROC_EVENT_COREDUMP = 1073741824,
	PROC_EVENT_EXIT = 2147483648,
};

enum reboot_type {
	BOOT_TRIPLE = 116,
	BOOT_KBD = 107,
	BOOT_BIOS = 98,
	BOOT_ACPI = 97,
	BOOT_EFI = 101,
	BOOT_CF9_FORCE = 112,
	BOOT_CF9_SAFE = 113,
};

struct async_entry {
	struct list_head domain_list;
	struct list_head global_list;
	struct work_struct work;
	async_cookie_t cookie;
	async_func_t func;
	void *data;
	struct async_domain *domain;
};

struct range {
	u64 start;
	u64 end;
};

struct smpboot_thread_data {
	unsigned int cpu;
	unsigned int status;
	struct smp_hotplug_thread *ht;
};

enum {
	HP_THREAD_NONE = 0,
	HP_THREAD_ACTIVE = 1,
	HP_THREAD_PARKED = 2,
};

struct pin_cookie {};

struct util_est {
	unsigned int enqueued;
	unsigned int ewma;
};

struct sched_avg {
	u64 last_update_time;
	u64 load_sum;
	u64 runnable_sum;
	u32 util_sum;
	u32 period_contrib;
	long unsigned int load_avg;
	long unsigned int runnable_avg;
	long unsigned int util_avg;
	int: 32;
	struct util_est util_est;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

enum sched_tunable_scaling {
	SCHED_TUNABLESCALING_NONE = 0,
	SCHED_TUNABLESCALING_LOG = 1,
	SCHED_TUNABLESCALING_LINEAR = 2,
	SCHED_TUNABLESCALING_END = 3,
};

typedef int (*cpu_stop_fn_t)(void *);

struct cpu_stop_work {
	struct work_struct work;
	cpu_stop_fn_t fn;
	void *arg;
};

struct rt_prio_array {
	long unsigned int bitmap[4];
	struct list_head queue[100];
};

struct dl_bw {
	raw_spinlock_t lock;
	u64 bw;
	u64 total_bw;
};

struct cfs_bandwidth {};

struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running;
	unsigned int h_nr_running;
	unsigned int idle_nr_running;
	unsigned int idle_h_nr_running;
	u64 exec_clock;
	u64 min_vruntime;
	u64 min_vruntime_copy;
	struct rb_root_cached tasks_timeline;
	struct sched_entity *curr;
	struct sched_entity *next;
	struct sched_entity *last;
	struct sched_entity *skip;
	unsigned int nr_spread_over;
};

struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
	unsigned int rr_nr_running;
	int rt_queued;
	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	raw_spinlock_t rt_runtime_lock;
};

struct dl_rq {
	struct rb_root_cached root;
	unsigned int dl_nr_running;
	struct dl_bw dl_bw;
	u64 running_bw;
	u64 this_bw;
	u64 extra_bw;
	u64 bw_ratio;
};

struct rq {
	raw_spinlock_t __lock;
	unsigned int nr_running;
	unsigned int nohz_tick_stopped;
	atomic_t nohz_flags;
	u64 nr_switches;
	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;
	unsigned int nr_uninterruptible;
	struct task_struct *curr;
	struct task_struct *idle;
	struct task_struct *stop;
	long unsigned int next_balance;
	struct mm_struct *prev_mm;
	unsigned int clock_update_flags;
	u64 clock;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	u64 clock_task;
	u64 clock_pelt;
	long unsigned int lost_idle_time;
	atomic_t nr_iowait;
	u64 last_seen_need_resched_ns;
	int ticks_without_resched;
	int membarrier_state;
	long unsigned int calc_load_update;
	long int calc_load_active;
	unsigned int push_busy;
	struct cpu_stop_work push_work;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct rq_flags {
	long unsigned int flags;
	struct pin_cookie cookie;
	unsigned int clock_update_flags;
};

enum {
	__SCHED_FEAT_GENTLE_FAIR_SLEEPERS = 0,
	__SCHED_FEAT_START_DEBIT = 1,
	__SCHED_FEAT_NEXT_BUDDY = 2,
	__SCHED_FEAT_LAST_BUDDY = 3,
	__SCHED_FEAT_CACHE_HOT_BUDDY = 4,
	__SCHED_FEAT_WAKEUP_PREEMPTION = 5,
	__SCHED_FEAT_HRTICK = 6,
	__SCHED_FEAT_HRTICK_DL = 7,
	__SCHED_FEAT_DOUBLE_TICK = 8,
	__SCHED_FEAT_NONTASK_CAPACITY = 9,
	__SCHED_FEAT_TTWU_QUEUE = 10,
	__SCHED_FEAT_SIS_PROP = 11,
	__SCHED_FEAT_WARN_DOUBLE_CLOCK = 12,
	__SCHED_FEAT_RT_RUNTIME_SHARE = 13,
	__SCHED_FEAT_LB_MIN = 14,
	__SCHED_FEAT_ATTACH_AGE_LOAD = 15,
	__SCHED_FEAT_WA_IDLE = 16,
	__SCHED_FEAT_WA_WEIGHT = 17,
	__SCHED_FEAT_WA_BIAS = 18,
	__SCHED_FEAT_UTIL_EST = 19,
	__SCHED_FEAT_UTIL_EST_FASTUP = 20,
	__SCHED_FEAT_LATENCY_WARN = 21,
	__SCHED_FEAT_ALT_PERIOD = 22,
	__SCHED_FEAT_BASE_SLICE = 23,
	__SCHED_FEAT_NR = 24,
};

struct root_domain;

struct task_group;

typedef int (*task_call_f)(struct task_struct *, void *);

enum ctx_state {
	CONTEXT_DISABLED = 4294967295,
	CONTEXT_KERNEL = 0,
	CONTEXT_USER = 1,
	CONTEXT_GUEST = 2,
};

struct kernel_cpustat {
	u64 cpustat[10];
};

enum {
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_READY = 1,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED = 2,
	MEMBARRIER_STATE_GLOBAL_EXPEDITED_READY = 4,
	MEMBARRIER_STATE_GLOBAL_EXPEDITED = 8,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE_READY = 16,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_SYNC_CORE = 32,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ_READY = 64,
	MEMBARRIER_STATE_PRIVATE_EXPEDITED_RSEQ = 128,
};

struct wake_q_head {
	struct wake_q_node *first;
	struct wake_q_node **lastp;
};

struct sched_attr {
	__u32 size;
	__u32 sched_policy;
	__u64 sched_flags;
	__s32 sched_nice;
	__u32 sched_priority;
	__u64 sched_runtime;
	__u64 sched_deadline;
	__u64 sched_period;
	__u32 sched_util_min;
	__u32 sched_util_max;
};

struct trace_event_raw_sched_kthread_stop {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	char __data[0];
};

struct trace_event_raw_sched_kthread_stop_ret {
	struct trace_entry ent;
	int ret;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_queue_work {
	struct trace_entry ent;
	void *work;
	void *function;
	void *worker;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_start {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_kthread_work_execute_end {
	struct trace_entry ent;
	void *work;
	void *function;
	char __data[0];
};

struct trace_event_raw_sched_wakeup_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int target_cpu;
	char __data[0];
};

struct trace_event_raw_sched_switch {
	struct trace_entry ent;
	char prev_comm[16];
	pid_t prev_pid;
	int prev_prio;
	long int prev_state;
	char next_comm[16];
	pid_t next_pid;
	int next_prio;
	char __data[0];
};

struct trace_event_raw_sched_migrate_task {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	int orig_cpu;
	int dest_cpu;
	char __data[0];
};

struct trace_event_raw_sched_process_template {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_wait {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int prio;
	char __data[0];
};

struct trace_event_raw_sched_process_fork {
	struct trace_entry ent;
	char parent_comm[16];
	pid_t parent_pid;
	char child_comm[16];
	pid_t child_pid;
	char __data[0];
};

struct trace_event_raw_sched_process_exec {
	struct trace_entry ent;
	u32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

struct trace_event_raw_sched_stat_runtime {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	u64 runtime;
	u64 vruntime;
	char __data[0];
};

struct trace_event_raw_sched_pi_setprio {
	struct trace_entry ent;
	char comm[16];
	pid_t pid;
	int oldprio;
	int newprio;
	char __data[0];
};

struct trace_event_raw_sched_move_numa {
	struct trace_entry ent;
	pid_t pid;
	pid_t tgid;
	pid_t ngid;
	int src_cpu;
	int src_nid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_numa_pair_template {
	struct trace_entry ent;
	pid_t src_pid;
	pid_t src_tgid;
	pid_t src_ngid;
	int src_cpu;
	int src_nid;
	pid_t dst_pid;
	pid_t dst_tgid;
	pid_t dst_ngid;
	int dst_cpu;
	int dst_nid;
	char __data[0];
};

struct trace_event_raw_sched_wake_idle_without_ipi {
	struct trace_entry ent;
	int cpu;
	char __data[0];
};

struct trace_event_data_offsets_sched_kthread_stop {};

struct trace_event_data_offsets_sched_kthread_stop_ret {};

struct trace_event_data_offsets_sched_kthread_work_queue_work {};

struct trace_event_data_offsets_sched_kthread_work_execute_start {};

struct trace_event_data_offsets_sched_kthread_work_execute_end {};

struct trace_event_data_offsets_sched_wakeup_template {};

struct trace_event_data_offsets_sched_switch {};

struct trace_event_data_offsets_sched_migrate_task {};

struct trace_event_data_offsets_sched_process_template {};

struct trace_event_data_offsets_sched_process_wait {};

struct trace_event_data_offsets_sched_process_fork {};

struct trace_event_data_offsets_sched_process_exec {
	u32 filename;
};

struct trace_event_data_offsets_sched_stat_runtime {};

struct trace_event_data_offsets_sched_pi_setprio {};

struct trace_event_data_offsets_sched_move_numa {};

struct trace_event_data_offsets_sched_numa_pair_template {};

struct trace_event_data_offsets_sched_wake_idle_without_ipi {};

typedef void (*btf_trace_sched_kthread_stop)(void *, struct task_struct *);

typedef void (*btf_trace_sched_kthread_stop_ret)(void *, int);

typedef void (*btf_trace_sched_kthread_work_queue_work)(void *, struct kthread_worker *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_start)(void *, struct kthread_work *);

typedef void (*btf_trace_sched_kthread_work_execute_end)(void *, struct kthread_work *, kthread_work_func_t);

typedef void (*btf_trace_sched_waking)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wakeup_new)(void *, struct task_struct *);

typedef void (*btf_trace_sched_switch)(void *, bool, unsigned int, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_migrate_task)(void *, struct task_struct *, int);

typedef void (*btf_trace_sched_process_free)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_exit)(void *, struct task_struct *);

typedef void (*btf_trace_sched_wait_task)(void *, struct task_struct *);

typedef void (*btf_trace_sched_process_wait)(void *, struct pid *);

typedef void (*btf_trace_sched_process_fork)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_process_exec)(void *, struct task_struct *, pid_t, struct linux_binprm *);

typedef void (*btf_trace_sched_stat_runtime)(void *, struct task_struct *, u64, u64);

typedef void (*btf_trace_sched_pi_setprio)(void *, struct task_struct *, struct task_struct *);

typedef void (*btf_trace_sched_move_numa)(void *, struct task_struct *, int, int);

typedef void (*btf_trace_sched_stick_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_swap_numa)(void *, struct task_struct *, int, struct task_struct *, int);

typedef void (*btf_trace_sched_wake_idle_without_ipi)(void *, int);

typedef void (*btf_trace_pelt_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_pelt_rt_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_dl_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_thermal_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_irq_tp)(void *, struct rq *);

typedef void (*btf_trace_pelt_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_cpu_capacity_tp)(void *, struct rq *);

typedef void (*btf_trace_sched_overutilized_tp)(void *, struct root_domain *, bool);

typedef void (*btf_trace_sched_util_est_cfs_tp)(void *, struct cfs_rq *);

typedef void (*btf_trace_sched_util_est_se_tp)(void *, struct sched_entity *);

typedef void (*btf_trace_sched_update_nr_running_tp)(void *, struct rq *, int);

struct rt_bandwidth {
	raw_spinlock_t rt_runtime_lock;
	ktime_t rt_period;
	u64 rt_runtime;
	struct hrtimer rt_period_timer;
	unsigned int rt_period_active;
};

struct task_cputime {
	u64 stime;
	u64 utime;
	long long unsigned int sum_exec_runtime;
};

struct cpuidle_state_usage {
	long long unsigned int disable;
	long long unsigned int usage;
	u64 time_ns;
	long long unsigned int above;
	long long unsigned int below;
	long long unsigned int rejected;
};

struct cpuidle_device;

struct cpuidle_driver;

struct cpuidle_state {
	char name[16];
	char desc[32];
	s64 exit_latency_ns;
	s64 target_residency_ns;
	unsigned int flags;
	unsigned int exit_latency;
	int power_usage;
	unsigned int target_residency;
	int (*enter)(struct cpuidle_device *, struct cpuidle_driver *, int);
	int (*enter_dead)(struct cpuidle_device *, int);
	int (*enter_s2idle)(struct cpuidle_device *, struct cpuidle_driver *, int);
};

struct cpuidle_state_kobj;

struct cpuidle_driver_kobj;

struct cpuidle_device_kobj;

struct cpuidle_device {
	unsigned int registered: 1;
	unsigned int enabled: 1;
	unsigned int poll_time_limit: 1;
	unsigned int cpu;
	ktime_t next_hrtimer;
	int last_state_idx;
	u64 last_residency_ns;
	u64 poll_limit_ns;
	u64 forced_idle_latency_limit_ns;
	struct cpuidle_state_usage states_usage[10];
	struct cpuidle_state_kobj *kobjs[10];
	struct cpuidle_driver_kobj *kobj_driver;
	struct cpuidle_device_kobj *kobj_dev;
	struct list_head device_list;
};

struct cpuidle_driver {
	const char *name;
	struct module *owner;
	unsigned int bctimer: 1;
	struct cpuidle_state states[10];
	int state_count;
	int safe_state_index;
	struct cpumask *cpumask;
	const char *governor;
};

struct dl_bandwidth {
	raw_spinlock_t dl_runtime_lock;
	u64 dl_runtime;
	u64 dl_period;
};

struct idle_timer {
	struct hrtimer timer;
	int done;
};

typedef struct rt_rq *rt_rq_iter_t;

struct ww_acquire_ctx;

struct ww_mutex {
	struct mutex base;
	struct ww_acquire_ctx *ctx;
};

struct ww_acquire_ctx {
	struct task_struct *task;
	long unsigned int stamp;
	unsigned int acquired;
	short unsigned int wounded;
	short unsigned int is_wait_die;
};

struct mutex_waiter {
	struct list_head list;
	struct task_struct *task;
	struct ww_acquire_ctx *ww_ctx;
};

struct swait_queue {
	struct task_struct *task;
	struct list_head task_list;
};

enum {
	MEMBARRIER_FLAG_SYNC_CORE = 1,
	MEMBARRIER_FLAG_RSEQ = 2,
};

enum membarrier_cmd {
	MEMBARRIER_CMD_QUERY = 0,
	MEMBARRIER_CMD_GLOBAL = 1,
	MEMBARRIER_CMD_GLOBAL_EXPEDITED = 2,
	MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED = 4,
	MEMBARRIER_CMD_PRIVATE_EXPEDITED = 8,
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED = 16,
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE = 32,
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE = 64,
	MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ = 128,
	MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ = 256,
	MEMBARRIER_CMD_SHARED = 1,
};

enum membarrier_cmd_flag {
	MEMBARRIER_CMD_FLAG_CPU = 1,
};

struct semaphore {
	raw_spinlock_t lock;
	unsigned int count;
	struct list_head wait_list;
};

struct semaphore_waiter {
	struct list_head list;
	struct task_struct *task;
	bool up;
};

enum rwsem_waiter_type {
	RWSEM_WAITING_FOR_WRITE = 0,
	RWSEM_WAITING_FOR_READ = 1,
};

struct rwsem_waiter {
	struct list_head list;
	struct task_struct *task;
	enum rwsem_waiter_type type;
	long unsigned int timeout;
	bool handoff_set;
};

enum rwsem_wake_type {
	RWSEM_WAKE_ANY = 0,
	RWSEM_WAKE_READERS = 1,
	RWSEM_WAKE_READ_OWNED = 2,
};

enum owner_state {
	OWNER_NULL = 1,
	OWNER_WRITER = 2,
	OWNER_READER = 4,
	OWNER_NONSPINNABLE = 8,
};

struct rt_mutex_base {
	raw_spinlock_t wait_lock;
	struct rb_root_cached waiters;
	struct task_struct *owner;
};

struct rt_mutex {
	struct rt_mutex_base rtmutex;
};

struct hrtimer_sleeper {
	struct hrtimer timer;
	struct task_struct *task;
};

struct rt_mutex_waiter {
	struct rb_node tree_entry;
	struct rb_node pi_tree_entry;
	struct task_struct *task;
	struct rt_mutex_base *lock;
	unsigned int wake_state;
	int prio;
	u64 deadline;
	struct ww_acquire_ctx *ww_ctx;
};

struct rt_wake_q_head {
	struct wake_q_head head;
	struct task_struct *rtlock_task;
};

enum rtmutex_chainwalk {
	RT_MUTEX_MIN_CHAINWALK = 0,
	RT_MUTEX_FULL_CHAINWALK = 1,
};

enum pm_qos_req_action {
	PM_QOS_ADD_REQ = 0,
	PM_QOS_UPDATE_REQ = 1,
	PM_QOS_REMOVE_REQ = 2,
};

struct dev_printk_info;

typedef unsigned int uint;

enum {
	CSD_FLAG_LOCK = 1,
	IRQ_WORK_PENDING = 1,
	IRQ_WORK_BUSY = 2,
	IRQ_WORK_LAZY = 4,
	IRQ_WORK_HARD_IRQ = 8,
	IRQ_WORK_CLAIMED = 3,
	CSD_TYPE_ASYNC = 0,
	CSD_TYPE_SYNC = 16,
	CSD_TYPE_IRQ_WORK = 32,
	CSD_TYPE_TTWU = 48,
	CSD_FLAG_TYPE_MASK = 240,
};

typedef struct {
	seqcount_t seqcount;
} seqcount_latch_t;

struct dev_printk_info {
	char subsystem[16];
	char device[48];
};

struct console {
	char name[16];
	void (*write)(struct console *, const char *, unsigned int);
	int (*read)(struct console *, char *, unsigned int);
	struct tty_driver * (*device)(struct console *, int *);
	void (*unblank)();
	int (*setup)(struct console *, char *);
	int (*exit)(struct console *);
	int (*match)(struct console *, char *, int, char *);
	short int flags;
	short int index;
	int cflag;
	uint ispeed;
	uint ospeed;
	void *data;
	struct console *next;
};

struct kmsg_dump_iter {
	u64 cur_seq;
	u64 next_seq;
};

struct kmsg_dumper {
	struct list_head list;
	void (*dump)(struct kmsg_dumper *, enum kmsg_dump_reason);
	enum kmsg_dump_reason max_reason;
	bool registered;
};

struct trace_event_raw_console {
	struct trace_entry ent;
	u32 __data_loc_msg;
	char __data[0];
};

struct trace_event_data_offsets_console {
	u32 msg;
};

typedef void (*btf_trace_console)(void *, const char *, size_t);

struct printk_info {
	u64 seq;
	u64 ts_nsec;
	u16 text_len;
	u8 facility;
	u8 flags: 5;
	u8 level: 3;
	u32 caller_id;
	struct dev_printk_info dev_info;
};

struct printk_record {
	struct printk_info *info;
	char *text_buf;
	unsigned int text_buf_size;
};

struct prb_data_blk_lpos {
	long unsigned int begin;
	long unsigned int next;
};

struct prb_desc {
	atomic_long_t state_var;
	struct prb_data_blk_lpos text_blk_lpos;
};

struct prb_data_ring {
	unsigned int size_bits;
	char *data;
	atomic_long_t head_lpos;
	atomic_long_t tail_lpos;
};

struct prb_desc_ring {
	unsigned int count_bits;
	struct prb_desc *descs;
	struct printk_info *infos;
	atomic_long_t head_id;
	atomic_long_t tail_id;
	atomic_long_t last_finalized_id;
};

struct printk_ringbuffer {
	struct prb_desc_ring desc_ring;
	struct prb_data_ring text_data_ring;
	atomic_long_t fail;
};

struct prb_reserved_entry {
	struct printk_ringbuffer *rb;
	long unsigned int irqflags;
	long unsigned int id;
	unsigned int text_space;
};

enum desc_state {
	desc_miss = 4294967295,
	desc_reserved = 0,
	desc_committed = 1,
	desc_finalized = 2,
	desc_reusable = 3,
};

struct console_cmdline {
	char name[16];
	int index;
	bool user_specified;
	char *options;
};

enum printk_info_flags {
	LOG_NEWLINE = 2,
	LOG_CONT = 8,
};

enum devkmsg_log_bits {
	__DEVKMSG_LOG_BIT_ON = 0,
	__DEVKMSG_LOG_BIT_OFF = 1,
	__DEVKMSG_LOG_BIT_LOCK = 2,
};

enum devkmsg_log_masks {
	DEVKMSG_LOG_MASK_ON = 1,
	DEVKMSG_LOG_MASK_OFF = 2,
	DEVKMSG_LOG_MASK_LOCK = 4,
};

enum con_msg_format_flags {
	MSG_FORMAT_DEFAULT = 0,
	MSG_FORMAT_SYSLOG = 1,
};

struct latched_seq {
	seqcount_latch_t latch;
	u64 val[2];
};

struct devkmsg_user {
	atomic64_t seq;
	struct ratelimit_state rs;
	struct mutex lock;
	char buf[8192];
	struct printk_info info;
	char text_buf[8192];
	struct printk_record record;
};

struct prb_data_block {
	long unsigned int id;
	char data[0];
};

enum {
	IRQD_TRIGGER_MASK = 15,
	IRQD_SETAFFINITY_PENDING = 256,
	IRQD_ACTIVATED = 512,
	IRQD_NO_BALANCING = 1024,
	IRQD_PER_CPU = 2048,
	IRQD_AFFINITY_SET = 4096,
	IRQD_LEVEL = 8192,
	IRQD_WAKEUP_STATE = 16384,
	IRQD_MOVE_PCNTXT = 32768,
	IRQD_IRQ_DISABLED = 65536,
	IRQD_IRQ_MASKED = 131072,
	IRQD_IRQ_INPROGRESS = 262144,
	IRQD_WAKEUP_ARMED = 524288,
	IRQD_FORWARDED_TO_VCPU = 1048576,
	IRQD_AFFINITY_MANAGED = 2097152,
	IRQD_IRQ_STARTED = 4194304,
	IRQD_MANAGED_SHUTDOWN = 8388608,
	IRQD_SINGLE_TARGET = 16777216,
	IRQD_DEFAULT_TRIGGER_SET = 33554432,
	IRQD_CAN_RESERVE = 67108864,
	IRQD_MSI_NOMASK_QUIRK = 134217728,
	IRQD_HANDLE_ENFORCE_IRQCTX = 268435456,
	IRQD_AFFINITY_ON_ACTIVATE = 536870912,
	IRQD_IRQ_ENABLED_ON_SUSPEND = 1073741824,
};

enum {
	IRQTF_RUNTHREAD = 0,
	IRQTF_WARNED = 1,
	IRQTF_AFFINITY = 2,
	IRQTF_FORCED_THREAD = 3,
};

enum {
	IRQS_AUTODETECT = 1,
	IRQS_SPURIOUS_DISABLED = 2,
	IRQS_POLL_INPROGRESS = 8,
	IRQS_ONESHOT = 32,
	IRQS_REPLAY = 64,
	IRQS_WAITING = 128,
	IRQS_PENDING = 512,
	IRQS_SUSPENDED = 2048,
	IRQS_TIMINGS = 4096,
	IRQS_NMI = 8192,
};

enum {
	_IRQ_DEFAULT_INIT_FLAGS = 0,
	_IRQ_PER_CPU = 512,
	_IRQ_LEVEL = 256,
	_IRQ_NOPROBE = 1024,
	_IRQ_NOREQUEST = 2048,
	_IRQ_NOTHREAD = 65536,
	_IRQ_NOAUTOEN = 4096,
	_IRQ_MOVE_PCNTXT = 16384,
	_IRQ_NO_BALANCING = 8192,
	_IRQ_NESTED_THREAD = 32768,
	_IRQ_PER_CPU_DEVID = 131072,
	_IRQ_IS_POLLED = 262144,
	_IRQ_DISABLE_UNLAZY = 524288,
	_IRQ_HIDDEN = 1048576,
	_IRQ_NO_DEBUG = 2097152,
	_IRQF_MODIFY_MASK = 2096911,
};

enum {
	IRQC_IS_HARDIRQ = 0,
	IRQC_IS_NESTED = 1,
};

enum {
	IRQ_SET_MASK_OK = 0,
	IRQ_SET_MASK_OK_NOCOPY = 1,
	IRQ_SET_MASK_OK_DONE = 2,
};

enum {
	IRQCHIP_SET_TYPE_MASKED = 1,
	IRQCHIP_EOI_IF_HANDLED = 2,
	IRQCHIP_MASK_ON_SUSPEND = 4,
	IRQCHIP_ONOFFLINE_ENABLED = 8,
	IRQCHIP_SKIP_SET_WAKE = 16,
	IRQCHIP_ONESHOT_SAFE = 32,
	IRQCHIP_EOI_THREADED = 64,
	IRQCHIP_SUPPORTS_LEVEL_MSI = 128,
	IRQCHIP_SUPPORTS_NMI = 256,
	IRQCHIP_ENABLE_WAKEUP_ON_SUSPEND = 512,
	IRQCHIP_AFFINITY_PRE_STARTUP = 1024,
};

struct arch_msi_msg_addr_lo {
	u32 address_lo;
};

typedef struct arch_msi_msg_addr_lo arch_msi_msg_addr_lo_t;

struct arch_msi_msg_addr_hi {
	u32 address_hi;
};

typedef struct arch_msi_msg_addr_hi arch_msi_msg_addr_hi_t;

struct arch_msi_msg_data {
	u32 data;
};

typedef struct arch_msi_msg_data arch_msi_msg_data_t;

struct msi_msg {
	union {
		u32 address_lo;
		arch_msi_msg_addr_lo_t arch_addr_lo;
	};
	union {
		u32 address_hi;
		arch_msi_msg_addr_hi_t arch_addr_hi;
	};
	union {
		u32 data;
		arch_msi_msg_data_t arch_data;
	};
};

struct pci_msi_desc {
	union {
		u32 msi_mask;
		u32 msix_ctrl;
	};
	struct {
		u8 is_msix: 1;
		u8 multiple: 3;
		u8 multi_cap: 3;
		u8 can_mask: 1;
		u8 is_64: 1;
		u8 is_virtual: 1;
		unsigned int default_irq;
	} msi_attrib;
	union {
		u8 mask_pos;
		void *mask_base;
	};
};

struct msi_desc {
	unsigned int irq;
	unsigned int nvec_used;
	struct device *dev;
	struct msi_msg msg;
	struct irq_affinity_desc *affinity;
	struct device_attribute *sysfs_attrs;
	void (*write_msi_msg)(struct msi_desc *, void *);
	void *write_msi_msg_data;
	u16 msi_index;
	struct pci_msi_desc pci;
};

enum {
	IRQ_STARTUP_NORMAL = 0,
	IRQ_STARTUP_MANAGED = 1,
	IRQ_STARTUP_ABORT = 2,
};

struct irq_devres {
	unsigned int irq;
	void *dev_id;
};

struct irq_desc_devres {
	unsigned int from;
	unsigned int cnt;
};

struct of_phandle_args {
	struct device_node *np;
	int args_count;
	uint32_t args[16];
};

enum {
	IRQ_DOMAIN_FLAG_HIERARCHY = 1,
	IRQ_DOMAIN_NAME_ALLOCATED = 2,
	IRQ_DOMAIN_FLAG_IPI_PER_CPU = 4,
	IRQ_DOMAIN_FLAG_IPI_SINGLE = 8,
	IRQ_DOMAIN_FLAG_MSI = 16,
	IRQ_DOMAIN_FLAG_MSI_REMAP = 32,
	IRQ_DOMAIN_MSI_NOMASK_QUIRK = 64,
	IRQ_DOMAIN_FLAG_NO_MAP = 128,
	IRQ_DOMAIN_FLAG_NONCORE = 65536,
};

enum {
	IRQCHIP_FWNODE_REAL = 0,
	IRQCHIP_FWNODE_NAMED = 1,
	IRQCHIP_FWNODE_NAMED_ID = 2,
};

struct irqchip_fwid {
	struct fwnode_handle fwnode;
	unsigned int type;
	char *name;
	phys_addr_t *pa;
};

enum {
	GP_IDLE = 0,
	GP_ENTER = 1,
	GP_PASSED = 2,
	GP_EXIT = 3,
	GP_REPLAY = 4,
};

typedef long unsigned int ulong;

struct rcu_synchronize {
	struct callback_head head;
	struct completion completion;
};

struct rcu_cblist {
	struct callback_head *head;
	struct callback_head **tail;
	long int len;
};

enum rcutorture_type {
	RCU_FLAVOR = 0,
	RCU_TASKS_FLAVOR = 1,
	RCU_TASKS_RUDE_FLAVOR = 2,
	RCU_TASKS_TRACING_FLAVOR = 3,
	RCU_TRIVIAL_FLAVOR = 4,
	SRCU_FLAVOR = 5,
	INVALID_RCU_FLAVOR = 6,
};

typedef void (*call_rcu_func_t)(struct callback_head *, rcu_callback_t);

struct trace_event_raw_rcu_utilization {
	struct trace_entry ent;
	const char *s;
	char __data[0];
};

struct trace_event_raw_rcu_grace_period {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	const char *gpevent;
	char __data[0];
};

struct trace_event_raw_rcu_future_grace_period {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	long int gp_seq_req;
	u8 level;
	int grplo;
	int grphi;
	const char *gpevent;
	char __data[0];
};

struct trace_event_raw_rcu_grace_period_init {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	u8 level;
	int grplo;
	int grphi;
	long unsigned int qsmask;
	char __data[0];
};

struct trace_event_raw_rcu_exp_grace_period {
	struct trace_entry ent;
	const char *rcuname;
	long int gpseq;
	const char *gpevent;
	char __data[0];
};

struct trace_event_raw_rcu_exp_funnel_lock {
	struct trace_entry ent;
	const char *rcuname;
	u8 level;
	int grplo;
	int grphi;
	const char *gpevent;
	char __data[0];
};

struct trace_event_raw_rcu_preempt_task {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	int pid;
	char __data[0];
};

struct trace_event_raw_rcu_unlock_preempted_task {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	int pid;
	char __data[0];
};

struct trace_event_raw_rcu_quiescent_state_report {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	long unsigned int mask;
	long unsigned int qsmask;
	u8 level;
	int grplo;
	int grphi;
	u8 gp_tasks;
	char __data[0];
};

struct trace_event_raw_rcu_fqs {
	struct trace_entry ent;
	const char *rcuname;
	long int gp_seq;
	int cpu;
	const char *qsevent;
	char __data[0];
};

struct trace_event_raw_rcu_stall_warning {
	struct trace_entry ent;
	const char *rcuname;
	const char *msg;
	char __data[0];
};

struct trace_event_raw_rcu_dyntick {
	struct trace_entry ent;
	const char *polarity;
	long int oldnesting;
	long int newnesting;
	int dynticks;
	char __data[0];
};

struct trace_event_raw_rcu_callback {
	struct trace_entry ent;
	const char *rcuname;
	void *rhp;
	void *func;
	long int qlen;
	char __data[0];
};

struct trace_event_raw_rcu_segcb_stats {
	struct trace_entry ent;
	const char *ctx;
	long unsigned int gp_seq[4];
	long int seglen[4];
	char __data[0];
};

struct trace_event_raw_rcu_kvfree_callback {
	struct trace_entry ent;
	const char *rcuname;
	void *rhp;
	long unsigned int offset;
	long int qlen;
	char __data[0];
};

struct trace_event_raw_rcu_batch_start {
	struct trace_entry ent;
	const char *rcuname;
	long int qlen;
	long int blimit;
	char __data[0];
};

struct trace_event_raw_rcu_invoke_callback {
	struct trace_entry ent;
	const char *rcuname;
	void *rhp;
	void *func;
	char __data[0];
};

struct trace_event_raw_rcu_invoke_kvfree_callback {
	struct trace_entry ent;
	const char *rcuname;
	void *rhp;
	long unsigned int offset;
	char __data[0];
};

struct trace_event_raw_rcu_invoke_kfree_bulk_callback {
	struct trace_entry ent;
	const char *rcuname;
	long unsigned int nr_records;
	void **p;
	char __data[0];
};

struct trace_event_raw_rcu_batch_end {
	struct trace_entry ent;
	const char *rcuname;
	int callbacks_invoked;
	char cb;
	char nr;
	char iit;
	char risk;
	char __data[0];
};

struct trace_event_raw_rcu_torture_read {
	struct trace_entry ent;
	char rcutorturename[8];
	struct callback_head *rhp;
	long unsigned int secs;
	long unsigned int c_old;
	long unsigned int c;
	char __data[0];
};

struct trace_event_raw_rcu_barrier {
	struct trace_entry ent;
	const char *rcuname;
	const char *s;
	int cpu;
	int cnt;
	long unsigned int done;
	char __data[0];
};

struct trace_event_data_offsets_rcu_utilization {};

struct trace_event_data_offsets_rcu_grace_period {};

struct trace_event_data_offsets_rcu_future_grace_period {};

struct trace_event_data_offsets_rcu_grace_period_init {};

struct trace_event_data_offsets_rcu_exp_grace_period {};

struct trace_event_data_offsets_rcu_exp_funnel_lock {};

struct trace_event_data_offsets_rcu_preempt_task {};

struct trace_event_data_offsets_rcu_unlock_preempted_task {};

struct trace_event_data_offsets_rcu_quiescent_state_report {};

struct trace_event_data_offsets_rcu_fqs {};

struct trace_event_data_offsets_rcu_stall_warning {};

struct trace_event_data_offsets_rcu_dyntick {};

struct trace_event_data_offsets_rcu_callback {};

struct trace_event_data_offsets_rcu_segcb_stats {};

struct trace_event_data_offsets_rcu_kvfree_callback {};

struct trace_event_data_offsets_rcu_batch_start {};

struct trace_event_data_offsets_rcu_invoke_callback {};

struct trace_event_data_offsets_rcu_invoke_kvfree_callback {};

struct trace_event_data_offsets_rcu_invoke_kfree_bulk_callback {};

struct trace_event_data_offsets_rcu_batch_end {};

struct trace_event_data_offsets_rcu_torture_read {};

struct trace_event_data_offsets_rcu_barrier {};

typedef void (*btf_trace_rcu_utilization)(void *, const char *);

typedef void (*btf_trace_rcu_grace_period)(void *, const char *, long unsigned int, const char *);

typedef void (*btf_trace_rcu_future_grace_period)(void *, const char *, long unsigned int, long unsigned int, u8, int, int, const char *);

typedef void (*btf_trace_rcu_grace_period_init)(void *, const char *, long unsigned int, u8, int, int, long unsigned int);

typedef void (*btf_trace_rcu_exp_grace_period)(void *, const char *, long unsigned int, const char *);

typedef void (*btf_trace_rcu_exp_funnel_lock)(void *, const char *, u8, int, int, const char *);

typedef void (*btf_trace_rcu_preempt_task)(void *, const char *, int, long unsigned int);

typedef void (*btf_trace_rcu_unlock_preempted_task)(void *, const char *, long unsigned int, int);

typedef void (*btf_trace_rcu_quiescent_state_report)(void *, const char *, long unsigned int, long unsigned int, long unsigned int, u8, int, int, int);

typedef void (*btf_trace_rcu_fqs)(void *, const char *, long unsigned int, int, const char *);

typedef void (*btf_trace_rcu_stall_warning)(void *, const char *, const char *);

typedef void (*btf_trace_rcu_dyntick)(void *, const char *, long int, long int, int);

typedef void (*btf_trace_rcu_callback)(void *, const char *, struct callback_head *, long int);

typedef void (*btf_trace_rcu_segcb_stats)(void *, struct rcu_segcblist *, const char *);

typedef void (*btf_trace_rcu_kvfree_callback)(void *, const char *, struct callback_head *, long unsigned int, long int);

typedef void (*btf_trace_rcu_batch_start)(void *, const char *, long int, long int);

typedef void (*btf_trace_rcu_invoke_callback)(void *, const char *, struct callback_head *);

typedef void (*btf_trace_rcu_invoke_kvfree_callback)(void *, const char *, struct callback_head *, long unsigned int);

typedef void (*btf_trace_rcu_invoke_kfree_bulk_callback)(void *, const char *, long unsigned int, void **);

typedef void (*btf_trace_rcu_batch_end)(void *, const char *, int, char, char, char, char);

typedef void (*btf_trace_rcu_torture_read)(void *, const char *, struct callback_head *, long unsigned int, long unsigned int, long unsigned int);

typedef void (*btf_trace_rcu_barrier)(void *, const char *, const char *, int, int, long unsigned int);

struct rcu_tasks;

typedef void (*rcu_tasks_gp_func_t)(struct rcu_tasks *);

typedef void (*pregp_func_t)();

typedef void (*pertask_func_t)(struct task_struct *, struct list_head *);

typedef void (*postscan_func_t)(struct list_head *);

typedef void (*holdouts_func_t)(struct list_head *, bool, bool *);

typedef void (*postgp_func_t)(struct rcu_tasks *);

struct rcu_tasks_percpu;

struct rcu_tasks {
	struct wait_queue_head cbs_wq;
	raw_spinlock_t cbs_gbl_lock;
	int gp_state;
	int gp_sleep;
	int init_fract;
	long unsigned int gp_jiffies;
	long unsigned int gp_start;
	long unsigned int tasks_gp_seq;
	long unsigned int n_ipis;
	long unsigned int n_ipis_fails;
	struct task_struct *kthread_ptr;
	rcu_tasks_gp_func_t gp_func;
	pregp_func_t pregp_func;
	pertask_func_t pertask_func;
	postscan_func_t postscan_func;
	holdouts_func_t holdouts_func;
	postgp_func_t postgp_func;
	call_rcu_func_t call_func;
	struct rcu_tasks_percpu *rtpcpu;
	int percpu_enqueue_shift;
	int percpu_enqueue_lim;
	int percpu_dequeue_lim;
	long unsigned int percpu_dequeue_gpseq;
	struct mutex barrier_q_mutex;
	atomic_t barrier_q_count;
	struct completion barrier_q_completion;
	long unsigned int barrier_q_seq;
	char *name;
	char *kname;
};

struct rcu_tasks_percpu {
	struct rcu_segcblist cblist;
	raw_spinlock_t lock;
	long unsigned int rtp_jiffies;
	long unsigned int rtp_n_lock_retries;
	struct work_struct rtp_work;
	struct irq_work rtp_irq_work;
	struct callback_head barrier_q_head;
	int cpu;
	struct rcu_tasks *rtpp;
};

struct trc_stall_chk_rdr {
	int nesting;
	int ipi_to_cpu;
	u8 needqs;
};

struct scatterlist {
	long unsigned int page_link;
	unsigned int offset;
	unsigned int length;
	dma_addr_t dma_address;
};

struct sg_table {
	struct scatterlist *sgl;
	unsigned int nents;
	unsigned int orig_nents;
};

struct dma_map_ops {
	void * (*alloc)(struct device *, size_t, dma_addr_t *, gfp_t, long unsigned int);
	void (*free)(struct device *, size_t, void *, dma_addr_t, long unsigned int);
	struct page * (*alloc_pages)(struct device *, size_t, dma_addr_t *, enum dma_data_direction, gfp_t);
	void (*free_pages)(struct device *, size_t, struct page *, dma_addr_t, enum dma_data_direction);
	struct sg_table * (*alloc_noncontiguous)(struct device *, size_t, enum dma_data_direction, gfp_t, long unsigned int);
	void (*free_noncontiguous)(struct device *, size_t, struct sg_table *, enum dma_data_direction);
	int (*mmap)(struct device *, struct vm_area_struct *, void *, dma_addr_t, size_t, long unsigned int);
	int (*get_sgtable)(struct device *, struct sg_table *, void *, dma_addr_t, size_t, long unsigned int);
	dma_addr_t (*map_page)(struct device *, struct page *, long unsigned int, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_page)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	int (*map_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	void (*unmap_sg)(struct device *, struct scatterlist *, int, enum dma_data_direction, long unsigned int);
	dma_addr_t (*map_resource)(struct device *, phys_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*unmap_resource)(struct device *, dma_addr_t, size_t, enum dma_data_direction, long unsigned int);
	void (*sync_single_for_cpu)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_single_for_device)(struct device *, dma_addr_t, size_t, enum dma_data_direction);
	void (*sync_sg_for_cpu)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*sync_sg_for_device)(struct device *, struct scatterlist *, int, enum dma_data_direction);
	void (*cache_sync)(struct device *, void *, size_t, enum dma_data_direction);
	int (*dma_supported)(struct device *, u64);
	u64 (*get_required_mask)(struct device *);
	size_t (*max_mapping_size)(struct device *);
	long unsigned int (*get_merge_boundary)(struct device *);
};

struct dma_sgt_handle {
	struct sg_table sgt;
	struct page **pages;
};

enum swiotlb_force {
	SWIOTLB_NORMAL = 0,
	SWIOTLB_FORCE = 1,
	SWIOTLB_NO_FORCE = 2,
};

struct dma_devres {
	size_t size;
	void *vaddr;
	dma_addr_t dma_handle;
	long unsigned int attrs;
};

struct rcu_exp_work {
	long unsigned int rew_s;
	struct work_struct rew_work;
};

struct rcu_node {
	raw_spinlock_t lock;
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	long unsigned int completedqs;
	long unsigned int qsmask;
	long unsigned int rcu_gp_init_mask;
	long unsigned int qsmaskinit;
	long unsigned int qsmaskinitnext;
	long unsigned int expmask;
	long unsigned int expmaskinit;
	long unsigned int expmaskinitnext;
	long unsigned int cbovldmask;
	long unsigned int ffmask;
	long unsigned int grpmask;
	int grplo;
	int grphi;
	u8 grpnum;
	u8 level;
	bool wait_blkd_tasks;
	struct rcu_node *parent;
	struct list_head blkd_tasks;
	struct list_head *gp_tasks;
	struct list_head *exp_tasks;
	struct list_head *boost_tasks;
	struct rt_mutex boost_mtx;
	long unsigned int boost_time;
	struct mutex boost_kthread_mutex;
	struct task_struct *boost_kthread_task;
	unsigned int boost_kthread_status;
	long unsigned int n_boosts;
	raw_spinlock_t fqslock;
	spinlock_t exp_lock;
	long unsigned int exp_seq_rq;
	wait_queue_head_t exp_wq[4];
	struct rcu_exp_work rew;
	bool exp_need_flush;
};

enum tick_dep_bits {
	TICK_DEP_BIT_POSIX_TIMER = 0,
	TICK_DEP_BIT_PERF_EVENTS = 1,
	TICK_DEP_BIT_SCHED = 2,
	TICK_DEP_BIT_CLOCK_UNSTABLE = 3,
	TICK_DEP_BIT_RCU = 4,
	TICK_DEP_BIT_RCU_EXP = 5,
};

struct sysrq_key_op {
	void (* const handler)(int);
	const char * const help_msg;
	const char * const action_msg;
	const int enable_mask;
};

union rcu_noqs {
	struct {
		u8 norm;
		u8 exp;
	} b;
	u16 s;
};

struct rcu_data {
	long unsigned int gp_seq;
	long unsigned int gp_seq_needed;
	union rcu_noqs cpu_no_qs;
	bool core_needs_qs;
	bool beenonline;
	bool gpwrap;
	bool cpu_started;
	struct rcu_node *mynode;
	long unsigned int grpmask;
	long unsigned int ticks_this_gp;
	struct irq_work defer_qs_iw;
	bool defer_qs_iw_pending;
	struct work_struct strict_work;
	struct rcu_segcblist cblist;
	long int qlen_last_fqs_check;
	long unsigned int n_cbs_invoked;
	long unsigned int n_force_qs_snap;
	long int blimit;
	int dynticks_snap;
	long int dynticks_nesting;
	long int dynticks_nmi_nesting;
	atomic_t dynticks;
	bool rcu_need_heavy_qs;
	bool rcu_urgent_qs;
	bool rcu_forced_tick;
	bool rcu_forced_tick_exp;
	long unsigned int barrier_seq_snap;
	struct callback_head barrier_head;
	int exp_dynticks_snap;
	struct task_struct *rcu_cpu_kthread_task;
	unsigned int rcu_cpu_kthread_status;
	char rcu_cpu_has_work;
	long unsigned int rcuc_activity;
	unsigned int softirq_snap;
	struct irq_work rcu_iw;
	bool rcu_iw_pending;
	long unsigned int rcu_iw_gp_seq;
	long unsigned int rcu_ofl_gp_seq;
	short int rcu_ofl_gp_flags;
	long unsigned int rcu_onl_gp_seq;
	short int rcu_onl_gp_flags;
	long unsigned int last_fqs_resched;
	int cpu;
};

struct rcu_state {
	struct rcu_node node[1];
	struct rcu_node *level[2];
	int ncpus;
	int n_online_cpus;
	long unsigned int gp_seq;
	long unsigned int gp_max;
	struct task_struct *gp_kthread;
	struct swait_queue_head gp_wq;
	short int gp_flags;
	short int gp_state;
	long unsigned int gp_wake_time;
	long unsigned int gp_wake_seq;
	struct mutex barrier_mutex;
	atomic_t barrier_cpu_count;
	struct completion barrier_completion;
	long unsigned int barrier_sequence;
	raw_spinlock_t barrier_lock;
	struct mutex exp_mutex;
	struct mutex exp_wake_mutex;
	long unsigned int expedited_sequence;
	atomic_t expedited_need_qs;
	struct swait_queue_head expedited_wq;
	int ncpus_snap;
	u8 cbovld;
	u8 cbovldnext;
	long unsigned int jiffies_force_qs;
	long unsigned int jiffies_kick_kthreads;
	long unsigned int n_force_qs;
	long unsigned int gp_start;
	long unsigned int gp_end;
	long unsigned int gp_activity;
	long unsigned int gp_req_activity;
	long unsigned int jiffies_stall;
	long unsigned int jiffies_resched;
	long unsigned int n_force_qs_gpstart;
	const char *name;
	char abbr;
	arch_spinlock_t ofl_lock;
};

struct kvfree_rcu_bulk_data {
	long unsigned int nr_records;
	struct kvfree_rcu_bulk_data *next;
	void *records[0];
};

struct kfree_rcu_cpu;

struct kfree_rcu_cpu_work {
	struct rcu_work rcu_work;
	struct callback_head *head_free;
	struct kvfree_rcu_bulk_data *bkvhead_free[2];
	struct kfree_rcu_cpu *krcp;
};

struct kfree_rcu_cpu {
	struct callback_head *head;
	struct kvfree_rcu_bulk_data *bkvhead[2];
	struct kfree_rcu_cpu_work krw_arr[2];
	raw_spinlock_t lock;
	struct delayed_work monitor_work;
	bool monitor_todo;
	bool initialized;
	int count;
	struct delayed_work page_cache_work;
	atomic_t backoff_page_cache_fill;
	atomic_t work_in_progress;
	struct hrtimer hrtimer;
	struct llist_head bkvcache;
	int nr_bkv_objs;
};

struct rcu_stall_chk_rdr {
	int nesting;
	union rcu_special rs;
	bool on_blkd_list;
};

enum {
	MEMREMAP_WB = 1,
	MEMREMAP_WT = 2,
	MEMREMAP_WC = 4,
	MEMREMAP_ENC = 8,
	MEMREMAP_DEC = 16,
};

struct dma_coherent_mem {
	void *virt_base;
	dma_addr_t device_base;
	long unsigned int pfn_base;
	int size;
	long unsigned int *bitmap;
	spinlock_t spinlock;
	bool use_dev_dma_pfn_offset;
};

struct reserved_mem_ops;

struct reserved_mem {
	const char *name;
	long unsigned int fdt_node;
	long unsigned int phandle;
	const struct reserved_mem_ops *ops;
	phys_addr_t base;
	phys_addr_t size;
	void *priv;
};

struct reserved_mem_ops {
	int (*device_init)(struct reserved_mem *, struct device *);
	void (*device_release)(struct reserved_mem *, struct device *);
};

typedef int (*reservedmem_of_init_fn)(struct reserved_mem *);

struct gen_pool;

typedef long unsigned int (*genpool_algo_t)(long unsigned int *, long unsigned int, long unsigned int, unsigned int, void *, struct gen_pool *, long unsigned int);

struct gen_pool {
	spinlock_t lock;
	struct list_head chunks;
	int min_alloc_order;
	genpool_algo_t algo;
	void *data;
	const char *name;
};

struct cma;

typedef __kernel_long_t __kernel_suseconds_t;

typedef __kernel_suseconds_t suseconds_t;

typedef __u64 timeu64_t;

struct itimerspec64 {
	struct timespec64 it_interval;
	struct timespec64 it_value;
};

struct trace_event_raw_timer_class {
	struct trace_entry ent;
	void *timer;
	char __data[0];
};

struct trace_event_raw_timer_start {
	struct trace_entry ent;
	void *timer;
	void *function;
	long unsigned int expires;
	long unsigned int now;
	unsigned int flags;
	char __data[0];
};

struct trace_event_raw_timer_expire_entry {
	struct trace_entry ent;
	void *timer;
	long unsigned int now;
	void *function;
	long unsigned int baseclk;
	char __data[0];
};

struct trace_event_raw_hrtimer_init {
	struct trace_entry ent;
	void *hrtimer;
	clockid_t clockid;
	enum hrtimer_mode mode;
	char __data[0];
};

struct trace_event_raw_hrtimer_start {
	struct trace_entry ent;
	void *hrtimer;
	void *function;
	s64 expires;
	s64 softexpires;
	enum hrtimer_mode mode;
	char __data[0];
};

struct trace_event_raw_hrtimer_expire_entry {
	struct trace_entry ent;
	void *hrtimer;
	s64 now;
	void *function;
	char __data[0];
};

struct trace_event_raw_hrtimer_class {
	struct trace_entry ent;
	void *hrtimer;
	char __data[0];
};

struct trace_event_raw_itimer_state {
	struct trace_entry ent;
	int which;
	long long unsigned int expires;
	long int value_sec;
	long int value_nsec;
	long int interval_sec;
	long int interval_nsec;
	char __data[0];
};

struct trace_event_raw_itimer_expire {
	struct trace_entry ent;
	int which;
	pid_t pid;
	long long unsigned int now;
	char __data[0];
};

struct trace_event_raw_tick_stop {
	struct trace_entry ent;
	int success;
	int dependency;
	char __data[0];
};

struct trace_event_data_offsets_timer_class {};

struct trace_event_data_offsets_timer_start {};

struct trace_event_data_offsets_timer_expire_entry {};

struct trace_event_data_offsets_hrtimer_init {};

struct trace_event_data_offsets_hrtimer_start {};

struct trace_event_data_offsets_hrtimer_expire_entry {};

struct trace_event_data_offsets_hrtimer_class {};

struct trace_event_data_offsets_itimer_state {};

struct trace_event_data_offsets_itimer_expire {};

struct trace_event_data_offsets_tick_stop {};

typedef void (*btf_trace_timer_init)(void *, struct timer_list *);

typedef void (*btf_trace_timer_start)(void *, struct timer_list *, long unsigned int, unsigned int);

typedef void (*btf_trace_timer_expire_entry)(void *, struct timer_list *, long unsigned int);

typedef void (*btf_trace_timer_expire_exit)(void *, struct timer_list *);

typedef void (*btf_trace_timer_cancel)(void *, struct timer_list *);

typedef void (*btf_trace_hrtimer_init)(void *, struct hrtimer *, clockid_t, enum hrtimer_mode);

typedef void (*btf_trace_hrtimer_start)(void *, struct hrtimer *, enum hrtimer_mode);

typedef void (*btf_trace_hrtimer_expire_entry)(void *, struct hrtimer *, ktime_t *);

typedef void (*btf_trace_hrtimer_expire_exit)(void *, struct hrtimer *);

typedef void (*btf_trace_hrtimer_cancel)(void *, struct hrtimer *);

typedef void (*btf_trace_itimer_state)(void *, int, const struct itimerspec64 * const, long long unsigned int);

typedef void (*btf_trace_itimer_expire)(void *, int, struct pid *, long long unsigned int);

typedef void (*btf_trace_tick_stop)(void *, int, int);

struct timer_base {
	raw_spinlock_t lock;
	struct timer_list *running_timer;
	long unsigned int clk;
	long unsigned int next_expiry;
	unsigned int cpu;
	bool next_expiry_recalc;
	bool is_idle;
	bool timers_pending;
	long unsigned int pending_map[16];
	struct hlist_head vectors[512];
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct process_timer {
	struct timer_list timer;
	struct task_struct *task;
};

enum clock_event_state {
	CLOCK_EVT_STATE_DETACHED = 0,
	CLOCK_EVT_STATE_SHUTDOWN = 1,
	CLOCK_EVT_STATE_PERIODIC = 2,
	CLOCK_EVT_STATE_ONESHOT = 3,
	CLOCK_EVT_STATE_ONESHOT_STOPPED = 4,
};

struct clock_event_device {
	void (*event_handler)(struct clock_event_device *);
	int (*set_next_event)(long unsigned int, struct clock_event_device *);
	int (*set_next_ktime)(ktime_t, struct clock_event_device *);
	ktime_t next_event;
	u64 max_delta_ns;
	u64 min_delta_ns;
	u32 mult;
	u32 shift;
	enum clock_event_state state_use_accessors;
	unsigned int features;
	long unsigned int retries;
	int (*set_state_periodic)(struct clock_event_device *);
	int (*set_state_oneshot)(struct clock_event_device *);
	int (*set_state_oneshot_stopped)(struct clock_event_device *);
	int (*set_state_shutdown)(struct clock_event_device *);
	int (*tick_resume)(struct clock_event_device *);
	void (*broadcast)(const struct cpumask *);
	void (*suspend)(struct clock_event_device *);
	void (*resume)(struct clock_event_device *);
	long unsigned int min_delta_ticks;
	long unsigned int max_delta_ticks;
	const char *name;
	int rating;
	int irq;
	int bound_on;
	const struct cpumask *cpumask;
	struct list_head list;
	struct module *owner;
};

enum clocksource_ids {
	CSID_GENERIC = 0,
	CSID_ARM_ARCH_COUNTER = 1,
	CSID_MAX = 2,
};

struct ktime_timestamps {
	u64 mono;
	u64 boot;
	u64 real;
};

struct system_time_snapshot {
	u64 cycles;
	ktime_t real;
	ktime_t raw;
	enum clocksource_ids cs_id;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
};

struct system_device_crosststamp {
	ktime_t device;
	ktime_t sys_realtime;
	ktime_t sys_monoraw;
};

struct clocksource;

struct system_counterval_t {
	u64 cycles;
	struct clocksource *cs;
};

enum vdso_clock_mode {
	VDSO_CLOCKMODE_NONE = 0,
	VDSO_CLOCKMODE_MAX = 1,
	VDSO_CLOCKMODE_TIMENS = 2147483647,
};

struct clocksource {
	u64 (*read)(struct clocksource *);
	u64 mask;
	u32 mult;
	u32 shift;
	u64 max_idle_ns;
	u32 maxadj;
	u32 uncertainty_margin;
	u64 max_cycles;
	const char *name;
	struct list_head list;
	int rating;
	enum clocksource_ids id;
	enum vdso_clock_mode vdso_clock_mode;
	long unsigned int flags;
	int (*enable)(struct clocksource *);
	void (*disable)(struct clocksource *);
	void (*suspend)(struct clocksource *);
	void (*resume)(struct clocksource *);
	void (*mark_unstable)(struct clocksource *);
	void (*tick_stable)(struct clocksource *);
	struct module *owner;
};

struct tk_read_base {
	struct clocksource *clock;
	u64 mask;
	u64 cycle_last;
	u32 mult;
	u32 shift;
	u64 xtime_nsec;
	ktime_t base;
	u64 base_real;
};

struct timekeeper {
	struct tk_read_base tkr_mono;
	struct tk_read_base tkr_raw;
	u64 xtime_sec;
	long unsigned int ktime_sec;
	struct timespec64 wall_to_monotonic;
	ktime_t offs_real;
	ktime_t offs_boot;
	ktime_t offs_tai;
	s32 tai_offset;
	unsigned int clock_was_set_seq;
	u8 cs_was_changed_seq;
	ktime_t next_leap_ktime;
	u64 raw_sec;
	struct timespec64 monotonic_to_boot;
	u64 cycle_interval;
	u64 xtime_interval;
	s64 xtime_remainder;
	u64 raw_interval;
	u64 ntp_tick;
	s64 ntp_error;
	u32 ntp_error_shift;
	u32 ntp_err_mult;
	u32 skip_second_overflow;
};

struct syscore_ops {
	struct list_head node;
	int (*suspend)();
	void (*resume)();
	void (*shutdown)();
};

struct audit_ntp_data {};

enum timekeeping_adv_mode {
	TK_ADV_TICK = 0,
	TK_ADV_FREQ = 1,
};

struct tk_fast {
	seqcount_latch_t seq;
	struct tk_read_base base[2];
};

enum audit_ntp_type {
	AUDIT_NTP_OFFSET = 0,
	AUDIT_NTP_FREQ = 1,
	AUDIT_NTP_STATUS = 2,
	AUDIT_NTP_TAI = 3,
	AUDIT_NTP_TICK = 4,
	AUDIT_NTP_ADJUST = 5,
	AUDIT_NTP_NVALS = 6,
};

struct tm {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	long int tm_year;
	int tm_wday;
	int tm_yday;
};

struct cyclecounter {
	u64 (*read)(const struct cyclecounter *);
	u64 mask;
	u32 mult;
	u32 shift;
};

struct timecounter {
	const struct cyclecounter *cc;
	u64 cycle_last;
	u64 nsec;
	u64 mask;
	u64 frac;
};

enum tick_device_mode {
	TICKDEV_MODE_PERIODIC = 0,
	TICKDEV_MODE_ONESHOT = 1,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};

enum tick_nohz_mode {
	NOHZ_MODE_INACTIVE = 0,
	NOHZ_MODE_LOWRES = 1,
	NOHZ_MODE_HIGHRES = 2,
};

struct tick_sched {
	struct hrtimer sched_timer;
	long unsigned int check_clocks;
	enum tick_nohz_mode nohz_mode;
	unsigned int inidle: 1;
	unsigned int tick_stopped: 1;
	unsigned int idle_active: 1;
	unsigned int do_timer_last: 1;
	unsigned int got_idle_tick: 1;
	ktime_t last_tick;
	ktime_t next_tick;
	long unsigned int idle_jiffies;
	long unsigned int idle_calls;
	long unsigned int idle_sleeps;
	ktime_t idle_entrytime;
	ktime_t idle_waketime;
	ktime_t idle_exittime;
	ktime_t idle_sleeptime;
	ktime_t iowait_sleeptime;
	long unsigned int last_jiffies;
	u64 timer_expires;
	u64 timer_expires_base;
	u64 next_timer;
	ktime_t idle_expires;
	atomic_t tick_dep_mask;
	long unsigned int last_tick_jiffies;
	unsigned int stalled_jiffies;
};

struct timer_list_iter {
	int cpu;
	bool second_pass;
	u64 now;
};

enum alarmtimer_type {
	ALARM_REALTIME = 0,
	ALARM_BOOTTIME = 1,
	ALARM_NUMTYPE = 2,
	ALARM_REALTIME_FREEZER = 3,
	ALARM_BOOTTIME_FREEZER = 4,
};

enum alarmtimer_restart {
	ALARMTIMER_NORESTART = 0,
	ALARMTIMER_RESTART = 1,
};

struct alarm {
	struct timerqueue_node node;
	struct hrtimer timer;
	enum alarmtimer_restart (*function)(struct alarm *, ktime_t);
	enum alarmtimer_type type;
	int state;
	void *data;
};

struct cpu_timer {
	struct timerqueue_node node;
	struct timerqueue_head *head;
	struct pid *pid;
	struct list_head elist;
	int firing;
};

struct k_clock;

struct k_itimer {
	struct list_head list;
	struct hlist_node t_hash;
	spinlock_t it_lock;
	const struct k_clock *kclock;
	clockid_t it_clock;
	timer_t it_id;
	int it_active;
	s64 it_overrun;
	s64 it_overrun_last;
	int it_requeue_pending;
	int it_sigev_notify;
	ktime_t it_interval;
	struct signal_struct *it_signal;
	union {
		struct pid *it_pid;
		struct task_struct *it_process;
	};
	struct sigqueue *sigq;
	union {
		struct {
			struct hrtimer timer;
		} real;
		struct cpu_timer cpu;
		struct {
			struct alarm alarmtimer;
		} alarm;
	} it;
	struct callback_head rcu;
};

struct k_clock {
	int (*clock_getres)(const clockid_t, struct timespec64 *);
	int (*clock_set)(const clockid_t, const struct timespec64 *);
	int (*clock_get_timespec)(const clockid_t, struct timespec64 *);
	ktime_t (*clock_get_ktime)(const clockid_t);
	int (*clock_adj)(const clockid_t, struct __kernel_timex *);
	int (*timer_create)(struct k_itimer *);
	int (*nsleep)(const clockid_t, int, const struct timespec64 *);
	int (*timer_set)(struct k_itimer *, int, struct itimerspec64 *, struct itimerspec64 *);
	int (*timer_del)(struct k_itimer *);
	void (*timer_get)(struct k_itimer *, struct itimerspec64 *);
	void (*timer_rearm)(struct k_itimer *);
	s64 (*timer_forward)(struct k_itimer *, ktime_t);
	ktime_t (*timer_remaining)(struct k_itimer *, ktime_t);
	int (*timer_try_to_cancel)(struct k_itimer *);
	void (*timer_arm)(struct k_itimer *, ktime_t, bool, bool);
	void (*timer_wait_running)(struct k_itimer *);
};

struct rtc_time {
	int tm_sec;
	int tm_min;
	int tm_hour;
	int tm_mday;
	int tm_mon;
	int tm_year;
	int tm_wday;
	int tm_yday;
	int tm_isdst;
};

struct rtc_wkalrm {
	unsigned char enabled;
	unsigned char pending;
	struct rtc_time time;
};

struct rtc_param {
	__u64 param;
	union {
		__u64 uvalue;
		__s64 svalue;
		__u64 ptr;
	};
	__u32 index;
	__u32 __pad;
};

struct rtc_class_ops {
	int (*ioctl)(struct device *, unsigned int, long unsigned int);
	int (*read_time)(struct device *, struct rtc_time *);
	int (*set_time)(struct device *, struct rtc_time *);
	int (*read_alarm)(struct device *, struct rtc_wkalrm *);
	int (*set_alarm)(struct device *, struct rtc_wkalrm *);
	int (*proc)(struct device *, struct seq_file *);
	int (*alarm_irq_enable)(struct device *, unsigned int);
	int (*read_offset)(struct device *, long int *);
	int (*set_offset)(struct device *, long int);
	int (*param_get)(struct device *, struct rtc_param *);
	int (*param_set)(struct device *, struct rtc_param *);
};

struct rtc_device;

struct rtc_timer {
	struct timerqueue_node node;
	ktime_t period;
	void (*func)(struct rtc_device *);
	struct rtc_device *rtc;
	int enabled;
};

struct rtc_device {
	struct device dev;
	struct module *owner;
	int id;
	const struct rtc_class_ops *ops;
	struct mutex ops_lock;
	struct cdev char_dev;
	long unsigned int flags;
	long unsigned int irq_data;
	spinlock_t irq_lock;
	wait_queue_head_t irq_queue;
	struct fasync_struct *async_queue;
	int irq_freq;
	int max_user_freq;
	struct timerqueue_head timerqueue;
	struct rtc_timer aie_timer;
	struct rtc_timer uie_rtctimer;
	struct hrtimer pie_timer;
	int pie_enabled;
	struct work_struct irqwork;
	long unsigned int set_offset_nsec;
	long unsigned int features[1];
	time64_t range_min;
	timeu64_t range_max;
	time64_t start_secs;
	time64_t offset_secs;
	bool set_start_time;
};

struct trace_event_raw_alarmtimer_suspend {
	struct trace_entry ent;
	s64 expires;
	unsigned char alarm_type;
	char __data[0];
};

struct trace_event_raw_alarm_class {
	struct trace_entry ent;
	void *alarm;
	unsigned char alarm_type;
	s64 expires;
	s64 now;
	char __data[0];
};

struct trace_event_data_offsets_alarmtimer_suspend {};

struct trace_event_data_offsets_alarm_class {};

typedef void (*btf_trace_alarmtimer_suspend)(void *, ktime_t, int);

typedef void (*btf_trace_alarmtimer_fired)(void *, struct alarm *, ktime_t);

typedef void (*btf_trace_alarmtimer_start)(void *, struct alarm *, ktime_t);

typedef void (*btf_trace_alarmtimer_cancel)(void *, struct alarm *, ktime_t);

struct alarm_base {
	spinlock_t lock;
	struct timerqueue_head timerqueue;
	ktime_t (*get_ktime)();
	void (*get_timespec)(struct timespec64 *);
	clockid_t base_clockid;
};

typedef struct sigevent sigevent_t;

struct posix_clock;

struct posix_clock_operations {
	struct module *owner;
	int (*clock_adjtime)(struct posix_clock *, struct __kernel_timex *);
	int (*clock_gettime)(struct posix_clock *, struct timespec64 *);
	int (*clock_getres)(struct posix_clock *, struct timespec64 *);
	int (*clock_settime)(struct posix_clock *, const struct timespec64 *);
	long int (*ioctl)(struct posix_clock *, unsigned int, long unsigned int);
	int (*open)(struct posix_clock *, fmode_t);
	__poll_t (*poll)(struct posix_clock *, struct file *, poll_table *);
	int (*release)(struct posix_clock *);
	ssize_t (*read)(struct posix_clock *, uint, char *, size_t);
};

struct posix_clock {
	struct posix_clock_operations ops;
	struct cdev cdev;
	struct device *dev;
	struct rw_semaphore rwsem;
	bool zombie;
};

struct posix_clock_desc {
	struct file *fp;
	struct posix_clock *clk;
};

typedef s64 int64_t;

struct ce_unbind {
	struct clock_event_device *ce;
	int res;
};

struct clock_read_data {
	u64 epoch_ns;
	u64 epoch_cyc;
	u64 sched_clock_mask;
	u64 (*read_sched_clock)();
	u32 mult;
	u32 shift;
};

struct clock_data {
	seqcount_latch_t seq;
	struct clock_read_data read_data[2];
	ktime_t wrap_kt;
	long unsigned int rate;
	u64 (*actual_read_sched_clock)();
};

enum tick_broadcast_state {
	TICK_BROADCAST_EXIT = 0,
	TICK_BROADCAST_ENTER = 1,
};

union futex_key {
	struct {
		u64 i_seq;
		long unsigned int pgoff;
		unsigned int offset;
	} shared;
	struct {
		union {
			struct mm_struct *mm;
			u64 __tmp;
		};
		long unsigned int address;
		unsigned int offset;
	} private;
	struct {
		u64 ptr;
		long unsigned int word;
		unsigned int offset;
	} both;
};

struct futex_pi_state {
	struct list_head list;
	struct rt_mutex_base pi_mutex;
	struct task_struct *owner;
	refcount_t refcount;
	union futex_key key;
};

struct futex_hash_bucket {
	atomic_t waiters;
	spinlock_t lock;
	struct plist_head chain;
};

struct futex_q {
	struct plist_node list;
	struct task_struct *task;
	spinlock_t *lock_ptr;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
	atomic_t requeue_state;
};

enum futex_access {
	FUTEX_READ = 0,
	FUTEX_WRITE = 1,
};

struct futex_waitv {
	__u64 val;
	__u64 uaddr;
	__u32 flags;
	__u32 __reserved;
};

struct futex_vector {
	struct futex_waitv w;
	struct futex_q q;
};

enum {
	Q_REQUEUE_PI_NONE = 0,
	Q_REQUEUE_PI_IGNORE = 1,
	Q_REQUEUE_PI_IN_PROGRESS = 2,
	Q_REQUEUE_PI_WAIT = 3,
	Q_REQUEUE_PI_DONE = 4,
	Q_REQUEUE_PI_LOCKED = 5,
};

struct __call_single_data {
	struct __call_single_node node;
	smp_call_func_t func;
	void *info;
};

struct proc_ops {
	unsigned int proc_flags;
	int (*proc_open)(struct inode *, struct file *);
	ssize_t (*proc_read)(struct file *, char *, size_t, loff_t *);
	ssize_t (*proc_read_iter)(struct kiocb *, struct iov_iter *);
	ssize_t (*proc_write)(struct file *, const char *, size_t, loff_t *);
	loff_t (*proc_lseek)(struct file *, loff_t, int);
	int (*proc_release)(struct inode *, struct file *);
	__poll_t (*proc_poll)(struct file *, struct poll_table_struct *);
	long int (*proc_ioctl)(struct file *, unsigned int, long unsigned int);
	int (*proc_mmap)(struct file *, struct vm_area_struct *);
	long unsigned int (*proc_get_unmapped_area)(struct file *, long unsigned int, long unsigned int, long unsigned int, long unsigned int);
};

struct kallsym_iter {
	loff_t pos;
	loff_t pos_arch_end;
	loff_t pos_mod_end;
	loff_t pos_ftrace_mod_end;
	loff_t pos_bpf_end;
	long unsigned int value;
	unsigned int nameoff;
	char type;
	char name[128];
	char module_name[60];
	int exported;
	int show_value;
};

struct latch_tree_root {
	seqcount_latch_t seq;
	struct rb_root tree[2];
};

struct latch_tree_ops {
	bool (*less)(struct latch_tree_node *, struct latch_tree_node *);
	int (*comp)(void *, struct latch_tree_node *);
};

struct module_sect_attr {
	struct bin_attribute battr;
	long unsigned int address;
};

struct module_sect_attrs {
	struct attribute_group grp;
	unsigned int nsections;
	struct module_sect_attr attrs[0];
};

struct module_notes_attrs {
	struct kobject *dir;
	unsigned int notes;
	struct bin_attribute attrs[0];
};

enum kernel_read_file_id {
	READING_UNKNOWN = 0,
	READING_FIRMWARE = 1,
	READING_MODULE = 2,
	READING_KEXEC_IMAGE = 3,
	READING_KEXEC_INITRAMFS = 4,
	READING_POLICY = 5,
	READING_X509_CERTIFICATE = 6,
	READING_MAX_ID = 7,
};

enum kernel_load_data_id {
	LOADING_UNKNOWN = 0,
	LOADING_FIRMWARE = 1,
	LOADING_MODULE = 2,
	LOADING_KEXEC_IMAGE = 3,
	LOADING_KEXEC_INITRAMFS = 4,
	LOADING_POLICY = 5,
	LOADING_X509_CERTIFICATE = 6,
	LOADING_MAX_ID = 7,
};

enum {
	PROC_ENTRY_PERMANENT = 1,
};

struct _ddebug {
	const char *modname;
	const char *function;
	const char *filename;
	const char *format;
	unsigned int lineno: 18;
	unsigned int flags: 8;
	int: 6;
	int: 32;
};

struct load_info {
	const char *name;
	struct module *mod;
	Elf32_Ehdr *hdr;
	long unsigned int len;
	Elf32_Shdr *sechdrs;
	char *secstrings;
	char *strtab;
	long unsigned int symoffs;
	long unsigned int stroffs;
	long unsigned int init_typeoffs;
	long unsigned int core_typeoffs;
	struct _ddebug *debug;
	unsigned int num_debug;
	bool sig_ok;
	long unsigned int mod_kallsyms_init_off;
	struct {
		unsigned int sym;
		unsigned int str;
		unsigned int mod;
		unsigned int vers;
		unsigned int info;
		unsigned int pcpu;
	} index;
};

struct trace_event_raw_module_load {
	struct trace_entry ent;
	unsigned int taints;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_module_free {
	struct trace_entry ent;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_module_request {
	struct trace_entry ent;
	long unsigned int ip;
	bool wait;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_data_offsets_module_load {
	u32 name;
};

struct trace_event_data_offsets_module_free {
	u32 name;
};

struct trace_event_data_offsets_module_request {
	u32 name;
};

typedef void (*btf_trace_module_load)(void *, struct module *);

typedef void (*btf_trace_module_free)(void *, struct module *);

typedef void (*btf_trace_module_request)(void *, char *, bool, long unsigned int);

struct mod_tree_root {
	struct latch_tree_root root;
	long unsigned int addr_min;
	long unsigned int addr_max;
};

enum mod_license {
	NOT_GPL_ONLY = 0,
	GPL_ONLY = 1,
};

struct symsearch {
	const struct kernel_symbol *start;
	const struct kernel_symbol *stop;
	const s32 *crcs;
	enum mod_license license;
};

struct find_symbol_arg {
	const char *name;
	bool gplok;
	bool warn;
	struct module *owner;
	const s32 *crc;
	const struct kernel_symbol *sym;
	enum mod_license license;
};

struct mod_initfree {
	struct llist_node node;
	void *module_init;
};

struct tp_module {
	struct list_head list;
	struct module *mod;
};

enum tp_func_state {
	TP_FUNC_0 = 0,
	TP_FUNC_1 = 1,
	TP_FUNC_2 = 2,
	TP_FUNC_N = 3,
};

enum tp_transition_sync {
	TP_TRANSITION_SYNC_1_0_1 = 0,
	TP_TRANSITION_SYNC_N_2_1 = 1,
	_NR_TP_TRANSITION_SYNC = 2,
};

struct tp_transition_snapshot {
	long unsigned int rcu;
	long unsigned int srcu;
	bool ongoing;
};

struct tp_probes {
	struct callback_head rcu;
	struct tracepoint_func probes[0];
};

struct kprobe_blacklist_entry {
	struct list_head list;
	long unsigned int start_addr;
	long unsigned int end_addr;
};

enum ring_buffer_type {
	RINGBUF_TYPE_DATA_TYPE_LEN_MAX = 28,
	RINGBUF_TYPE_PADDING = 29,
	RINGBUF_TYPE_TIME_EXTEND = 30,
	RINGBUF_TYPE_TIME_STAMP = 31,
};

enum ring_buffer_flags {
	RB_FL_OVERWRITE = 1,
};

struct ring_buffer_per_cpu;

struct buffer_page;

struct ring_buffer_iter {
	struct ring_buffer_per_cpu *cpu_buffer;
	long unsigned int head;
	long unsigned int next_event;
	struct buffer_page *head_page;
	struct buffer_page *cache_reader_page;
	long unsigned int cache_read;
	u64 read_stamp;
	u64 page_stamp;
	struct ring_buffer_event *event;
	int missed_events;
};

struct rb_irq_work {
	struct irq_work work;
	wait_queue_head_t waiters;
	wait_queue_head_t full_waiters;
	bool waiters_pending;
	bool full_waiters_pending;
	bool wakeup_full;
};

struct trace_buffer {
	unsigned int flags;
	int cpus;
	atomic_t record_disabled;
	cpumask_var_t cpumask;
	struct lock_class_key *reader_lock_key;
	struct mutex mutex;
	struct ring_buffer_per_cpu **buffers;
	struct hlist_node node;
	u64 (*clock)();
	struct rb_irq_work irq_work;
	bool time_stamp_abs;
};

enum {
	RB_LEN_TIME_EXTEND = 8,
	RB_LEN_TIME_STAMP = 8,
};

struct buffer_data_page {
	u64 time_stamp;
	local_t commit;
	unsigned char data[0];
};

struct buffer_page {
	struct list_head list;
	local_t write;
	unsigned int read;
	local_t entries;
	long unsigned int real_end;
	struct buffer_data_page *page;
};

struct rb_event_info {
	u64 ts;
	u64 delta;
	u64 before;
	u64 after;
	long unsigned int length;
	struct buffer_page *tail_page;
	int add_timestamp;
};

enum {
	RB_ADD_STAMP_NONE = 0,
	RB_ADD_STAMP_EXTEND = 2,
	RB_ADD_STAMP_ABSOLUTE = 4,
	RB_ADD_STAMP_FORCE = 8,
};

enum {
	RB_CTX_TRANSITION = 0,
	RB_CTX_NMI = 1,
	RB_CTX_IRQ = 2,
	RB_CTX_SOFTIRQ = 3,
	RB_CTX_NORMAL = 4,
	RB_CTX_MAX = 5,
};

struct rb_time_struct {
	local_t cnt;
	local_t top;
	local_t bottom;
};

typedef struct rb_time_struct rb_time_t;

struct ring_buffer_per_cpu {
	int cpu;
	atomic_t record_disabled;
	atomic_t resize_disabled;
	struct trace_buffer *buffer;
	raw_spinlock_t reader_lock;
	arch_spinlock_t lock;
	struct lock_class_key lock_key;
	struct buffer_data_page *free_page;
	long unsigned int nr_pages;
	unsigned int current_context;
	struct list_head *pages;
	struct buffer_page *head_page;
	struct buffer_page *tail_page;
	struct buffer_page *commit_page;
	struct buffer_page *reader_page;
	long unsigned int lost_events;
	long unsigned int last_overrun;
	long unsigned int nest;
	local_t entries_bytes;
	local_t entries;
	local_t overrun;
	local_t commit_overrun;
	local_t dropped_events;
	local_t committing;
	local_t commits;
	local_t pages_touched;
	local_t pages_read;
	long int last_pages_touch;
	size_t shortest_full;
	long unsigned int read;
	long unsigned int read_bytes;
	rb_time_t write_stamp;
	rb_time_t before_stamp;
	u64 event_stamp[5];
	u64 read_stamp;
	long int nr_pages_to_update;
	struct list_head new_pages;
	struct work_struct update_pages_work;
	struct completion update_done;
	struct rb_irq_work irq_work;
};

typedef struct {
	int val[2];
} __kernel_fsid_t;

typedef struct fsnotify_mark_connector *fsnotify_connp_t;

struct fsnotify_mark_connector {
	spinlock_t lock;
	short unsigned int type;
	short unsigned int flags;
	__kernel_fsid_t fsid;
	union {
		fsnotify_connp_t *obj;
		struct fsnotify_mark_connector *destroy_next;
	};
	struct hlist_head list;
};

typedef struct vfsmount * (*debugfs_automount_t)(struct dentry *, void *);

struct partial_page {
	unsigned int offset;
	unsigned int len;
	long unsigned int private;
};

struct splice_pipe_desc {
	struct page **pages;
	struct partial_page *partial;
	int nr_pages;
	unsigned int nr_pages_max;
	const struct pipe_buf_operations *ops;
	void (*spd_release)(struct splice_pipe_desc *, unsigned int);
};

struct trace_export {
	struct trace_export *next;
	void (*write)(struct trace_export *, const void *, unsigned int);
	int flags;
};

enum fsnotify_data_type {
	FSNOTIFY_EVENT_NONE = 0,
	FSNOTIFY_EVENT_PATH = 1,
	FSNOTIFY_EVENT_INODE = 2,
	FSNOTIFY_EVENT_DENTRY = 3,
	FSNOTIFY_EVENT_ERROR = 4,
};

enum fsnotify_iter_type {
	FSNOTIFY_ITER_TYPE_INODE = 0,
	FSNOTIFY_ITER_TYPE_VFSMOUNT = 1,
	FSNOTIFY_ITER_TYPE_SB = 2,
	FSNOTIFY_ITER_TYPE_PARENT = 3,
	FSNOTIFY_ITER_TYPE_INODE2 = 4,
	FSNOTIFY_ITER_TYPE_COUNT = 5,
};

struct prog_entry;

struct event_filter {
	struct prog_entry *prog;
	char *filter_string;
};

struct trace_array_cpu;

struct array_buffer {
	struct trace_array *tr;
	struct trace_buffer *buffer;
	struct trace_array_cpu *data;
	u64 time_start;
	int cpu;
};

struct trace_pid_list;

struct trace_options;

struct cond_snapshot;

struct trace_func_repeats;

struct trace_array {
	struct list_head list;
	char *name;
	struct array_buffer array_buffer;
	struct array_buffer max_buffer;
	bool allocated_snapshot;
	long unsigned int max_latency;
	struct dentry *d_max_latency;
	struct work_struct fsnotify_work;
	struct irq_work fsnotify_irqwork;
	struct trace_pid_list *filtered_pids;
	struct trace_pid_list *filtered_no_pids;
	arch_spinlock_t max_lock;
	int buffer_disabled;
	int sys_refcount_enter;
	int sys_refcount_exit;
	struct trace_event_file *enter_syscall_files[451];
	struct trace_event_file *exit_syscall_files[451];
	int stop_count;
	int clock_id;
	int nr_topts;
	bool clear_trace;
	int buffer_percent;
	unsigned int n_err_log_entries;
	struct tracer *current_trace;
	unsigned int trace_flags;
	unsigned char trace_flags_index[32];
	unsigned int flags;
	raw_spinlock_t start_lock;
	struct list_head err_log;
	struct dentry *dir;
	struct dentry *options;
	struct dentry *percpu_dir;
	struct dentry *event_dir;
	struct trace_options *topts;
	struct list_head systems;
	struct list_head events;
	struct trace_event_file *trace_marker_file;
	cpumask_var_t tracing_cpumask;
	int ref;
	int trace_ref;
	int no_filter_buffering_ref;
	struct list_head hist_vars;
	struct cond_snapshot *cond_snapshot;
	struct trace_func_repeats *last_func_repeats;
};

struct tracer_flags;

struct tracer {
	const char *name;
	int (*init)(struct trace_array *);
	void (*reset)(struct trace_array *);
	void (*start)(struct trace_array *);
	void (*stop)(struct trace_array *);
	int (*update_thresh)(struct trace_array *);
	void (*open)(struct trace_iterator *);
	void (*pipe_open)(struct trace_iterator *);
	void (*close)(struct trace_iterator *);
	void (*pipe_close)(struct trace_iterator *);
	ssize_t (*read)(struct trace_iterator *, struct file *, char *, size_t, loff_t *);
	ssize_t (*splice_read)(struct trace_iterator *, struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int);
	void (*print_header)(struct seq_file *);
	enum print_line_t (*print_line)(struct trace_iterator *);
	int (*set_flag)(struct trace_array *, u32, u32, int);
	int (*flag_changed)(struct trace_array *, u32, int);
	struct tracer *next;
	struct tracer_flags *flags;
	int enabled;
	bool print_max;
	bool allow_instances;
	bool use_max_tr;
	bool noboot;
};

enum trace_iter_flags {
	TRACE_FILE_LAT_FMT = 1,
	TRACE_FILE_ANNOTATE = 2,
	TRACE_FILE_TIME_IN_NS = 4,
};

enum trace_flag_type {
	TRACE_FLAG_IRQS_OFF = 1,
	TRACE_FLAG_IRQS_NOSUPPORT = 2,
	TRACE_FLAG_NEED_RESCHED = 4,
	TRACE_FLAG_HARDIRQ = 8,
	TRACE_FLAG_SOFTIRQ = 16,
	TRACE_FLAG_PREEMPT_RESCHED = 32,
	TRACE_FLAG_NMI = 64,
	TRACE_FLAG_BH_OFF = 128,
};

struct event_subsystem;

struct trace_subsystem_dir {
	struct list_head list;
	struct event_subsystem *subsystem;
	struct trace_array *tr;
	struct dentry *entry;
	int ref_count;
	int nr_events;
};

enum event_trigger_type {
	ETT_NONE = 0,
	ETT_TRACE_ONOFF = 1,
	ETT_SNAPSHOT = 2,
	ETT_STACKTRACE = 4,
	ETT_EVENT_ENABLE = 8,
	ETT_EVENT_HIST = 16,
	ETT_HIST_ENABLE = 32,
	ETT_EVENT_EPROBE = 64,
};

union lower_chunk {
	union lower_chunk *next;
	long unsigned int data[512];
};

union upper_chunk {
	union upper_chunk *next;
	union lower_chunk *data[256];
};

struct trace_pid_list {
	raw_spinlock_t lock;
	struct irq_work refill_irqwork;
	union upper_chunk *upper[256];
	union upper_chunk *upper_list;
	union lower_chunk *lower_list;
	int free_upper_chunks;
	int free_lower_chunks;
};

enum trace_type {
	__TRACE_FIRST_TYPE = 0,
	TRACE_FN = 1,
	TRACE_CTX = 2,
	TRACE_WAKE = 3,
	TRACE_STACK = 4,
	TRACE_PRINT = 5,
	TRACE_BPRINT = 6,
	TRACE_MMIO_RW = 7,
	TRACE_MMIO_MAP = 8,
	TRACE_BRANCH = 9,
	TRACE_GRAPH_RET = 10,
	TRACE_GRAPH_ENT = 11,
	TRACE_USER_STACK = 12,
	TRACE_BLK = 13,
	TRACE_BPUTS = 14,
	TRACE_HWLAT = 15,
	TRACE_OSNOISE = 16,
	TRACE_TIMERLAT = 17,
	TRACE_RAW_DATA = 18,
	TRACE_FUNC_REPEATS = 19,
	__TRACE_LAST_TYPE = 20,
};

struct ftrace_entry {
	struct trace_entry ent;
	long unsigned int ip;
	long unsigned int parent_ip;
};

struct stack_entry {
	struct trace_entry ent;
	int size;
	long unsigned int caller[8];
};

struct bprint_entry {
	struct trace_entry ent;
	long unsigned int ip;
	const char *fmt;
	u32 buf[0];
};

struct print_entry {
	struct trace_entry ent;
	long unsigned int ip;
	char buf[0];
};

struct raw_data_entry {
	struct trace_entry ent;
	unsigned int id;
	char buf[0];
};

struct bputs_entry {
	struct trace_entry ent;
	long unsigned int ip;
	const char *str;
};

struct func_repeats_entry {
	struct trace_entry ent;
	long unsigned int ip;
	long unsigned int parent_ip;
	u16 count;
	u16 top_delta_ts;
	u32 bottom_delta_ts;
};

struct trace_array_cpu {
	atomic_t disabled;
	void *buffer_page;
	long unsigned int entries;
	long unsigned int saved_latency;
	long unsigned int critical_start;
	long unsigned int critical_end;
	long unsigned int critical_sequence;
	long unsigned int nice;
	long unsigned int policy;
	long unsigned int rt_priority;
	long unsigned int skipped_entries;
	u64 preempt_timestamp;
	pid_t pid;
	kuid_t uid;
	char comm[16];
	bool ignore_pid;
};

struct trace_option_dentry;

struct trace_options {
	struct tracer *tracer;
	struct trace_option_dentry *topts;
};

struct tracer_opt;

struct trace_option_dentry {
	struct tracer_opt *opt;
	struct tracer_flags *flags;
	struct trace_array *tr;
	struct dentry *entry;
};

typedef bool (*cond_update_fn_t)(struct trace_array *, void *);

struct cond_snapshot {
	void *cond_data;
	cond_update_fn_t update;
};

struct trace_func_repeats {
	long unsigned int ip;
	long unsigned int parent_ip;
	long unsigned int count;
	u64 ts_last_call;
};

enum {
	TRACE_ARRAY_FL_GLOBAL = 1,
};

struct tracer_opt {
	const char *name;
	u32 bit;
};

struct tracer_flags {
	u32 val;
	struct tracer_opt *opts;
	struct tracer *trace;
};

struct trace_parser {
	bool cont;
	char *buffer;
	unsigned int idx;
	unsigned int size;
};

enum trace_iterator_bits {
	TRACE_ITER_PRINT_PARENT_BIT = 0,
	TRACE_ITER_SYM_OFFSET_BIT = 1,
	TRACE_ITER_SYM_ADDR_BIT = 2,
	TRACE_ITER_VERBOSE_BIT = 3,
	TRACE_ITER_RAW_BIT = 4,
	TRACE_ITER_HEX_BIT = 5,
	TRACE_ITER_BIN_BIT = 6,
	TRACE_ITER_BLOCK_BIT = 7,
	TRACE_ITER_PRINTK_BIT = 8,
	TRACE_ITER_ANNOTATE_BIT = 9,
	TRACE_ITER_USERSTACKTRACE_BIT = 10,
	TRACE_ITER_SYM_USEROBJ_BIT = 11,
	TRACE_ITER_PRINTK_MSGONLY_BIT = 12,
	TRACE_ITER_CONTEXT_INFO_BIT = 13,
	TRACE_ITER_LATENCY_FMT_BIT = 14,
	TRACE_ITER_RECORD_CMD_BIT = 15,
	TRACE_ITER_RECORD_TGID_BIT = 16,
	TRACE_ITER_OVERWRITE_BIT = 17,
	TRACE_ITER_STOP_ON_FREE_BIT = 18,
	TRACE_ITER_IRQ_INFO_BIT = 19,
	TRACE_ITER_MARKERS_BIT = 20,
	TRACE_ITER_EVENT_FORK_BIT = 21,
	TRACE_ITER_PAUSE_ON_TRACE_BIT = 22,
	TRACE_ITER_HASH_PTR_BIT = 23,
	TRACE_ITER_STACKTRACE_BIT = 24,
	TRACE_ITER_LAST_BIT = 25,
};

enum trace_iterator_flags {
	TRACE_ITER_PRINT_PARENT = 1,
	TRACE_ITER_SYM_OFFSET = 2,
	TRACE_ITER_SYM_ADDR = 4,
	TRACE_ITER_VERBOSE = 8,
	TRACE_ITER_RAW = 16,
	TRACE_ITER_HEX = 32,
	TRACE_ITER_BIN = 64,
	TRACE_ITER_BLOCK = 128,
	TRACE_ITER_PRINTK = 256,
	TRACE_ITER_ANNOTATE = 512,
	TRACE_ITER_USERSTACKTRACE = 1024,
	TRACE_ITER_SYM_USEROBJ = 2048,
	TRACE_ITER_PRINTK_MSGONLY = 4096,
	TRACE_ITER_CONTEXT_INFO = 8192,
	TRACE_ITER_LATENCY_FMT = 16384,
	TRACE_ITER_RECORD_CMD = 32768,
	TRACE_ITER_RECORD_TGID = 65536,
	TRACE_ITER_OVERWRITE = 131072,
	TRACE_ITER_STOP_ON_FREE = 262144,
	TRACE_ITER_IRQ_INFO = 524288,
	TRACE_ITER_MARKERS = 1048576,
	TRACE_ITER_EVENT_FORK = 2097152,
	TRACE_ITER_PAUSE_ON_TRACE = 4194304,
	TRACE_ITER_HASH_PTR = 8388608,
	TRACE_ITER_STACKTRACE = 16777216,
};

struct event_subsystem {
	struct list_head list;
	const char *name;
	struct event_filter *filter;
	int ref_count;
};

struct trace_min_max_param {
	struct mutex *lock;
	u64 *val;
	u64 *min;
	u64 *max;
};

struct saved_cmdlines_buffer {
	unsigned int map_pid_to_cmdline[32769];
	unsigned int *map_cmdline_to_pid;
	unsigned int cmdline_num;
	int cmdline_idx;
	char *saved_cmdlines;
};

struct ftrace_stack {
	long unsigned int calls[2048];
};

struct ftrace_stacks {
	struct ftrace_stack stacks[4];
};

struct trace_buffer_struct {
	int nesting;
	char buffer[4096];
};

struct ftrace_buffer_info {
	struct trace_iterator iter;
	void *spare;
	unsigned int spare_cpu;
	unsigned int read;
};

struct err_info {
	const char **errs;
	u8 type;
	u16 pos;
	u64 ts;
};

struct tracing_log_err {
	struct list_head list;
	struct err_info info;
	char loc[128];
	char *cmd;
};

struct buffer_ref {
	struct trace_buffer *buffer;
	void *page;
	int cpu;
	refcount_t refcount;
};

struct trace_print_flags_u64 {
	long long unsigned int mask;
	const char *name;
};

struct ctx_switch_entry {
	struct trace_entry ent;
	unsigned int prev_pid;
	unsigned int next_pid;
	unsigned int next_cpu;
	unsigned char prev_prio;
	unsigned char prev_state;
	unsigned char next_prio;
	unsigned char next_state;
};

struct userstack_entry {
	struct trace_entry ent;
	unsigned int tgid;
	long unsigned int caller[8];
};

struct hwlat_entry {
	struct trace_entry ent;
	u64 duration;
	u64 outer_duration;
	u64 nmi_total_ts;
	struct timespec64 timestamp;
	unsigned int nmi_count;
	unsigned int seqnum;
	unsigned int count;
};

struct osnoise_entry {
	struct trace_entry ent;
	u64 noise;
	u64 runtime;
	u64 max_sample;
	unsigned int hw_count;
	unsigned int nmi_count;
	unsigned int irq_count;
	unsigned int softirq_count;
	unsigned int thread_count;
};

struct timerlat_entry {
	struct trace_entry ent;
	unsigned int seqnum;
	int context;
	u64 timer_latency;
};

struct trace_mark {
	long long unsigned int val;
	char sym;
};

struct tracer_stat {
	const char *name;
	void * (*stat_start)(struct tracer_stat *);
	void * (*stat_next)(void *, int);
	cmp_func_t stat_cmp;
	int (*stat_show)(struct seq_file *, void *);
	void (*stat_release)(void *);
	int (*stat_headers)(struct seq_file *);
};

struct stat_node {
	struct rb_node node;
	void *stat;
};

struct stat_session {
	struct list_head session_list;
	struct tracer_stat *ts;
	struct rb_root stat_root;
	struct mutex stat_mutex;
	struct dentry *file;
};

struct trace_bprintk_fmt {
	struct list_head list;
	const char *fmt;
};

struct trace_event_raw_preemptirq_template {
	struct trace_entry ent;
	s32 caller_offs;
	s32 parent_offs;
	char __data[0];
};

struct trace_event_data_offsets_preemptirq_template {};

typedef void (*btf_trace_irq_disable)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_irq_enable)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_preempt_disable)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_preempt_enable)(void *, long unsigned int, long unsigned int);

enum {
	TRACER_IRQS_OFF = 2,
	TRACER_PREEMPT_OFF = 4,
};

enum {
	MODE_NONE = 0,
	MODE_ROUND_ROBIN = 1,
	MODE_PER_CPU = 2,
	MODE_MAX = 3,
};

struct hwlat_kthread_data {
	struct task_struct *kthread;
	u64 nmi_ts_start;
	u64 nmi_total_ts;
	int nmi_count;
	int nmi_cpu;
};

struct hwlat_sample {
	u64 seqnum;
	u64 duration;
	u64 outer_duration;
	u64 nmi_total_ts;
	struct timespec64 timestamp;
	int nmi_count;
	int count;
};

struct hwlat_data {
	struct mutex lock;
	u64 count;
	u64 sample_window;
	u64 sample_width;
	int thread_mode;
};

enum {
	TRACE_NOP_OPT_ACCEPT = 1,
	TRACE_NOP_OPT_REFUSE = 2,
};

struct io_cq {
	struct request_queue *q;
	struct io_context *ioc;
	union {
		struct list_head q_node;
		struct kmem_cache *__rcu_icq_cache;
	};
	union {
		struct hlist_node ioc_node;
		struct callback_head __rcu_head;
	};
	unsigned int flags;
};

enum req_opf {
	REQ_OP_READ = 0,
	REQ_OP_WRITE = 1,
	REQ_OP_FLUSH = 2,
	REQ_OP_DISCARD = 3,
	REQ_OP_SECURE_ERASE = 5,
	REQ_OP_WRITE_ZEROES = 9,
	REQ_OP_ZONE_OPEN = 10,
	REQ_OP_ZONE_CLOSE = 11,
	REQ_OP_ZONE_FINISH = 12,
	REQ_OP_ZONE_APPEND = 13,
	REQ_OP_ZONE_RESET = 15,
	REQ_OP_ZONE_RESET_ALL = 17,
	REQ_OP_DRV_IN = 34,
	REQ_OP_DRV_OUT = 35,
	REQ_OP_LAST = 36,
};

enum req_flag_bits {
	__REQ_FAILFAST_DEV = 8,
	__REQ_FAILFAST_TRANSPORT = 9,
	__REQ_FAILFAST_DRIVER = 10,
	__REQ_SYNC = 11,
	__REQ_META = 12,
	__REQ_PRIO = 13,
	__REQ_NOMERGE = 14,
	__REQ_IDLE = 15,
	__REQ_INTEGRITY = 16,
	__REQ_FUA = 17,
	__REQ_PREFLUSH = 18,
	__REQ_RAHEAD = 19,
	__REQ_BACKGROUND = 20,
	__REQ_NOWAIT = 21,
	__REQ_CGROUP_PUNT = 22,
	__REQ_NOUNMAP = 23,
	__REQ_POLLED = 24,
	__REQ_DRV = 25,
	__REQ_SWAP = 26,
	__REQ_NR_BITS = 27,
};

struct sbitmap_word {
	long unsigned int word;
	long unsigned int cleared;
};

struct sbitmap {
	unsigned int depth;
	unsigned int shift;
	unsigned int map_nr;
	bool round_robin;
	struct sbitmap_word *map;
	unsigned int *alloc_hint;
};

struct sbq_wait_state {
	atomic_t wait_cnt;
	wait_queue_head_t wait;
};

struct sbitmap_queue {
	struct sbitmap sb;
	unsigned int wake_batch;
	atomic_t wake_index;
	struct sbq_wait_state *ws;
	atomic_t ws_active;
	unsigned int min_shallow_depth;
};

typedef __u32 req_flags_t;

enum mq_rq_state {
	MQ_RQ_IDLE = 0,
	MQ_RQ_IN_FLIGHT = 1,
	MQ_RQ_COMPLETE = 2,
};

typedef void rq_end_io_fn(struct request *, blk_status_t);

struct request {
	struct request_queue *q;
	struct blk_mq_ctx *mq_ctx;
	struct blk_mq_hw_ctx *mq_hctx;
	unsigned int cmd_flags;
	req_flags_t rq_flags;
	int tag;
	int internal_tag;
	unsigned int timeout;
	unsigned int __data_len;
	sector_t __sector;
	struct bio *bio;
	struct bio *biotail;
	union {
		struct list_head queuelist;
		struct request *rq_next;
	};
	struct block_device *part;
	u64 start_time_ns;
	u64 io_start_time_ns;
	short unsigned int stats_sectors;
	short unsigned int nr_phys_segments;
	short unsigned int write_hint;
	short unsigned int ioprio;
	enum mq_rq_state state;
	atomic_t ref;
	long unsigned int deadline;
	union {
		struct hlist_node hash;
		struct llist_node ipi_list;
	};
	union {
		struct rb_node rb_node;
		struct bio_vec special_vec;
		void *completion_data;
		int error_count;
	};
	union {
		struct {
			struct io_cq *icq;
			void *priv[2];
		} elv;
		struct {
			unsigned int seq;
			struct list_head list;
			rq_end_io_fn *saved_end_io;
		} flush;
	};
	union {
		struct __call_single_data csd;
		u64 fifo_time;
	};
	rq_end_io_fn *end_io;
	void *end_io_data;
};

struct blk_mq_tags {
	unsigned int nr_tags;
	unsigned int nr_reserved_tags;
	atomic_t active_queues;
	struct sbitmap_queue bitmap_tags;
	struct sbitmap_queue breserved_tags;
	struct request **rqs;
	struct request **static_rqs;
	struct list_head page_list;
	spinlock_t lock;
};

struct blk_flush_queue {
	unsigned int flush_pending_idx: 1;
	unsigned int flush_running_idx: 1;
	blk_status_t rq_status;
	long unsigned int flush_pending_since;
	struct list_head flush_queue[2];
	struct list_head flush_data_in_flight;
	struct request *flush_rq;
	spinlock_t mq_flush_lock;
};

struct blk_mq_queue_map {
	unsigned int *mq_map;
	unsigned int nr_queues;
	unsigned int queue_offset;
};

struct blk_mq_tag_set {
	struct blk_mq_queue_map map[3];
	unsigned int nr_maps;
	const struct blk_mq_ops *ops;
	unsigned int nr_hw_queues;
	unsigned int queue_depth;
	unsigned int reserved_tags;
	unsigned int cmd_size;
	int numa_node;
	unsigned int timeout;
	unsigned int flags;
	void *driver_data;
	struct blk_mq_tags **tags;
	struct blk_mq_tags *shared_tags;
	struct mutex tag_list_lock;
	struct list_head tag_list;
};

struct blk_mq_hw_ctx {
	struct {
		spinlock_t lock;
		struct list_head dispatch;
		long unsigned int state;
	};
	struct delayed_work run_work;
	cpumask_var_t cpumask;
	int next_cpu;
	int next_cpu_batch;
	long unsigned int flags;
	void *sched_data;
	struct request_queue *queue;
	struct blk_flush_queue *fq;
	void *driver_data;
	struct sbitmap ctx_map;
	struct blk_mq_ctx *dispatch_from;
	unsigned int dispatch_busy;
	short unsigned int type;
	short unsigned int nr_ctx;
	struct blk_mq_ctx **ctxs;
	spinlock_t dispatch_wait_lock;
	wait_queue_entry_t dispatch_wait;
	atomic_t wait_index;
	struct blk_mq_tags *tags;
	struct blk_mq_tags *sched_tags;
	long unsigned int queued;
	long unsigned int run;
	unsigned int numa_node;
	unsigned int queue_num;
	atomic_t nr_active;
	struct hlist_node cpuhp_online;
	struct hlist_node cpuhp_dead;
	struct kobject kobj;
	struct dentry *debugfs_dir;
	struct dentry *sched_debugfs_dir;
	struct list_head hctx_list;
};

struct blk_mq_queue_data {
	struct request *rq;
	bool last;
};

enum {
	TRACE_PIDS = 1,
	TRACE_NO_PIDS = 2,
};

struct ftrace_event_field {
	struct list_head link;
	const char *name;
	const char *type;
	int filter_type;
	int offset;
	int size;
	int is_signed;
};

struct module_string {
	struct list_head next;
	struct module *module;
	char *str;
};

enum {
	FORMAT_HEADER = 1,
	FORMAT_FIELD_SEPERATOR = 2,
	FORMAT_PRINTFMT = 3,
};

struct syscall_trace_enter {
	struct trace_entry ent;
	int nr;
	long unsigned int args[0];
};

struct syscall_trace_exit {
	struct trace_entry ent;
	int nr;
	long int ret;
};

struct syscall_tp_t {
	long long unsigned int regs;
	long unsigned int syscall_nr;
	long unsigned int ret;
};

struct syscall_tp_t___2 {
	long long unsigned int regs;
	long unsigned int syscall_nr;
	long unsigned int args[6];
};

enum perf_event_sample_format {
	PERF_SAMPLE_IP = 1,
	PERF_SAMPLE_TID = 2,
	PERF_SAMPLE_TIME = 4,
	PERF_SAMPLE_ADDR = 8,
	PERF_SAMPLE_READ = 16,
	PERF_SAMPLE_CALLCHAIN = 32,
	PERF_SAMPLE_ID = 64,
	PERF_SAMPLE_CPU = 128,
	PERF_SAMPLE_PERIOD = 256,
	PERF_SAMPLE_STREAM_ID = 512,
	PERF_SAMPLE_RAW = 1024,
	PERF_SAMPLE_BRANCH_STACK = 2048,
	PERF_SAMPLE_REGS_USER = 4096,
	PERF_SAMPLE_STACK_USER = 8192,
	PERF_SAMPLE_WEIGHT = 16384,
	PERF_SAMPLE_DATA_SRC = 32768,
	PERF_SAMPLE_IDENTIFIER = 65536,
	PERF_SAMPLE_TRANSACTION = 131072,
	PERF_SAMPLE_REGS_INTR = 262144,
	PERF_SAMPLE_PHYS_ADDR = 524288,
	PERF_SAMPLE_AUX = 1048576,
	PERF_SAMPLE_CGROUP = 2097152,
	PERF_SAMPLE_DATA_PAGE_SIZE = 4194304,
	PERF_SAMPLE_CODE_PAGE_SIZE = 8388608,
	PERF_SAMPLE_WEIGHT_STRUCT = 16777216,
	PERF_SAMPLE_MAX = 33554432,
	__PERF_SAMPLE_CALLCHAIN_EARLY = 0,
};

typedef long unsigned int perf_trace_t[2048];

struct filter_pred;

struct prog_entry {
	int target;
	int when_to_branch;
	struct filter_pred *pred;
};

typedef int (*filter_pred_fn_t)(struct filter_pred *, void *);

struct regex;

typedef int (*regex_match_func)(char *, struct regex *, int);

struct regex {
	char pattern[256];
	int len;
	int field_len;
	regex_match_func match;
};

struct filter_pred {
	filter_pred_fn_t fn;
	u64 val;
	struct regex regex;
	short unsigned int *ops;
	struct ftrace_event_field *field;
	int offset;
	int not;
	int op;
};

enum regex_type {
	MATCH_FULL = 0,
	MATCH_FRONT_ONLY = 1,
	MATCH_MIDDLE_ONLY = 2,
	MATCH_END_ONLY = 3,
	MATCH_GLOB = 4,
	MATCH_INDEX = 5,
};

enum filter_op_ids {
	OP_GLOB = 0,
	OP_NE = 1,
	OP_EQ = 2,
	OP_LE = 3,
	OP_LT = 4,
	OP_GE = 5,
	OP_GT = 6,
	OP_BAND = 7,
	OP_MAX = 8,
};

enum {
	FILT_ERR_NONE = 0,
	FILT_ERR_INVALID_OP = 1,
	FILT_ERR_TOO_MANY_OPEN = 2,
	FILT_ERR_TOO_MANY_CLOSE = 3,
	FILT_ERR_MISSING_QUOTE = 4,
	FILT_ERR_OPERAND_TOO_LONG = 5,
	FILT_ERR_EXPECT_STRING = 6,
	FILT_ERR_EXPECT_DIGIT = 7,
	FILT_ERR_ILLEGAL_FIELD_OP = 8,
	FILT_ERR_FIELD_NOT_FOUND = 9,
	FILT_ERR_ILLEGAL_INTVAL = 10,
	FILT_ERR_BAD_SUBSYS_FILTER = 11,
	FILT_ERR_TOO_MANY_PREDS = 12,
	FILT_ERR_INVALID_FILTER = 13,
	FILT_ERR_IP_FIELD_ONLY = 14,
	FILT_ERR_INVALID_VALUE = 15,
	FILT_ERR_ERRNO = 16,
	FILT_ERR_NO_FILTER = 17,
};

struct filter_parse_error {
	int lasterr;
	int lasterr_pos;
};

typedef int (*parse_pred_fn)(const char *, void *, int, struct filter_parse_error *, struct filter_pred **);

enum {
	INVERT = 1,
	PROCESS_AND = 2,
	PROCESS_OR = 4,
};

struct ustring_buffer {
	char buffer[1024];
};

enum {
	TOO_MANY_CLOSE = 4294967295,
	TOO_MANY_OPEN = 4294967294,
	MISSING_QUOTE = 4294967293,
};

struct filter_list {
	struct list_head list;
	struct event_filter *filter;
};

enum {
	EVENT_TRIGGER_FL_PROBE = 1,
};

struct event_trigger_ops;

struct event_command;

struct event_trigger_data {
	long unsigned int count;
	int ref;
	int flags;
	struct event_trigger_ops *ops;
	struct event_command *cmd_ops;
	struct event_filter *filter;
	char *filter_str;
	void *private_data;
	bool paused;
	bool paused_tmp;
	struct list_head list;
	char *name;
	struct list_head named_list;
	struct event_trigger_data *named_data;
};

struct event_trigger_ops {
	void (*trigger)(struct event_trigger_data *, struct trace_buffer *, void *, struct ring_buffer_event *);
	int (*init)(struct event_trigger_ops *, struct event_trigger_data *);
	void (*free)(struct event_trigger_ops *, struct event_trigger_data *);
	int (*print)(struct seq_file *, struct event_trigger_ops *, struct event_trigger_data *);
};

struct event_command {
	struct list_head list;
	char *name;
	enum event_trigger_type trigger_type;
	int flags;
	int (*parse)(struct event_command *, struct trace_event_file *, char *, char *, char *);
	int (*reg)(char *, struct event_trigger_data *, struct trace_event_file *);
	void (*unreg)(char *, struct event_trigger_data *, struct trace_event_file *);
	void (*unreg_all)(struct trace_event_file *);
	int (*set_filter)(char *, struct event_trigger_data *, struct trace_event_file *);
	struct event_trigger_ops * (*get_trigger_ops)(char *, char *);
};

struct enable_trigger_data {
	struct trace_event_file *file;
	bool enable;
	bool hist;
};

enum event_command_flags {
	EVENT_CMD_FL_POST_TRIGGER = 1,
	EVENT_CMD_FL_NEEDS_REC = 2,
};

struct eprobe_trace_entry_head {
	struct trace_entry ent;
};

struct dyn_event;

struct dyn_event_operations {
	struct list_head list;
	int (*create)(const char *);
	int (*show)(struct seq_file *, struct dyn_event *);
	bool (*is_busy)(struct dyn_event *);
	int (*free)(struct dyn_event *);
	bool (*match)(const char *, const char *, int, const char **, struct dyn_event *);
};

struct dyn_event {
	struct list_head list;
	struct dyn_event_operations *ops;
};

typedef int (*print_type_func_t)(struct trace_seq *, void *, void *);

enum fetch_op {
	FETCH_OP_NOP = 0,
	FETCH_OP_REG = 1,
	FETCH_OP_STACK = 2,
	FETCH_OP_STACKP = 3,
	FETCH_OP_RETVAL = 4,
	FETCH_OP_IMM = 5,
	FETCH_OP_COMM = 6,
	FETCH_OP_ARG = 7,
	FETCH_OP_FOFFS = 8,
	FETCH_OP_DATA = 9,
	FETCH_OP_DEREF = 10,
	FETCH_OP_UDEREF = 11,
	FETCH_OP_ST_RAW = 12,
	FETCH_OP_ST_MEM = 13,
	FETCH_OP_ST_UMEM = 14,
	FETCH_OP_ST_STRING = 15,
	FETCH_OP_ST_USTRING = 16,
	FETCH_OP_MOD_BF = 17,
	FETCH_OP_LP_ARRAY = 18,
	FETCH_OP_TP_ARG = 19,
	FETCH_OP_END = 20,
	FETCH_NOP_SYMBOL = 21,
};

struct fetch_insn {
	enum fetch_op op;
	union {
		unsigned int param;
		struct {
			unsigned int size;
			int offset;
		};
		struct {
			unsigned char basesize;
			unsigned char lshift;
			unsigned char rshift;
		};
		long unsigned int immediate;
		void *data;
	};
};

struct fetch_type {
	const char *name;
	size_t size;
	int is_signed;
	print_type_func_t print;
	const char *fmt;
	const char *fmttype;
};

struct probe_arg {
	struct fetch_insn *code;
	bool dynamic;
	unsigned int offset;
	unsigned int count;
	const char *name;
	const char *comm;
	char *fmt;
	const struct fetch_type *type;
};

struct trace_uprobe_filter {
	rwlock_t rwlock;
	int nr_systemwide;
	struct list_head perf_events;
};

struct trace_probe_event {
	unsigned int flags;
	struct trace_event_class class;
	struct trace_event_call call;
	struct list_head files;
	struct list_head probes;
	struct trace_uprobe_filter filter[0];
};

struct trace_probe {
	struct list_head list;
	struct trace_probe_event *event;
	ssize_t size;
	unsigned int nr_args;
	struct probe_arg args[0];
};

struct event_file_link {
	struct trace_event_file *file;
	struct list_head list;
};

enum probe_print_type {
	PROBE_PRINT_NORMAL = 0,
	PROBE_PRINT_RETURN = 1,
	PROBE_PRINT_EVENT = 2,
};

enum {
	TP_ERR_FILE_NOT_FOUND = 0,
	TP_ERR_NO_REGULAR_FILE = 1,
	TP_ERR_BAD_REFCNT = 2,
	TP_ERR_REFCNT_OPEN_BRACE = 3,
	TP_ERR_BAD_REFCNT_SUFFIX = 4,
	TP_ERR_BAD_UPROBE_OFFS = 5,
	TP_ERR_MAXACT_NO_KPROBE = 6,
	TP_ERR_BAD_MAXACT = 7,
	TP_ERR_MAXACT_TOO_BIG = 8,
	TP_ERR_BAD_PROBE_ADDR = 9,
	TP_ERR_BAD_RETPROBE = 10,
	TP_ERR_BAD_ADDR_SUFFIX = 11,
	TP_ERR_NO_GROUP_NAME = 12,
	TP_ERR_GROUP_TOO_LONG = 13,
	TP_ERR_BAD_GROUP_NAME = 14,
	TP_ERR_NO_EVENT_NAME = 15,
	TP_ERR_EVENT_TOO_LONG = 16,
	TP_ERR_BAD_EVENT_NAME = 17,
	TP_ERR_EVENT_EXIST = 18,
	TP_ERR_RETVAL_ON_PROBE = 19,
	TP_ERR_BAD_STACK_NUM = 20,
	TP_ERR_BAD_ARG_NUM = 21,
	TP_ERR_BAD_VAR = 22,
	TP_ERR_BAD_REG_NAME = 23,
	TP_ERR_BAD_MEM_ADDR = 24,
	TP_ERR_BAD_IMM = 25,
	TP_ERR_IMMSTR_NO_CLOSE = 26,
	TP_ERR_FILE_ON_KPROBE = 27,
	TP_ERR_BAD_FILE_OFFS = 28,
	TP_ERR_SYM_ON_UPROBE = 29,
	TP_ERR_TOO_MANY_OPS = 30,
	TP_ERR_DEREF_NEED_BRACE = 31,
	TP_ERR_BAD_DEREF_OFFS = 32,
	TP_ERR_DEREF_OPEN_BRACE = 33,
	TP_ERR_COMM_CANT_DEREF = 34,
	TP_ERR_BAD_FETCH_ARG = 35,
	TP_ERR_ARRAY_NO_CLOSE = 36,
	TP_ERR_BAD_ARRAY_SUFFIX = 37,
	TP_ERR_BAD_ARRAY_NUM = 38,
	TP_ERR_ARRAY_TOO_BIG = 39,
	TP_ERR_BAD_TYPE = 40,
	TP_ERR_BAD_STRING = 41,
	TP_ERR_BAD_BITFIELD = 42,
	TP_ERR_ARG_NAME_TOO_LONG = 43,
	TP_ERR_NO_ARG_NAME = 44,
	TP_ERR_BAD_ARG_NAME = 45,
	TP_ERR_USED_ARG_NAME = 46,
	TP_ERR_ARG_TOO_LONG = 47,
	TP_ERR_NO_ARG_BODY = 48,
	TP_ERR_BAD_INSN_BNDRY = 49,
	TP_ERR_FAIL_REG_PROBE = 50,
	TP_ERR_DIFF_PROBE_TYPE = 51,
	TP_ERR_DIFF_ARG_TYPE = 52,
	TP_ERR_SAME_PROBE = 53,
};

struct trace_eprobe {
	const char *event_system;
	const char *event_name;
	struct trace_event_call *event;
	struct dyn_event devent;
	struct trace_probe tp;
};

struct eprobe_data {
	struct trace_event_file *file;
	struct trace_eprobe *ep;
};

enum bpf_func_id {
	BPF_FUNC_unspec = 0,
	BPF_FUNC_map_lookup_elem = 1,
	BPF_FUNC_map_update_elem = 2,
	BPF_FUNC_map_delete_elem = 3,
	BPF_FUNC_probe_read = 4,
	BPF_FUNC_ktime_get_ns = 5,
	BPF_FUNC_trace_printk = 6,
	BPF_FUNC_get_prandom_u32 = 7,
	BPF_FUNC_get_smp_processor_id = 8,
	BPF_FUNC_skb_store_bytes = 9,
	BPF_FUNC_l3_csum_replace = 10,
	BPF_FUNC_l4_csum_replace = 11,
	BPF_FUNC_tail_call = 12,
	BPF_FUNC_clone_redirect = 13,
	BPF_FUNC_get_current_pid_tgid = 14,
	BPF_FUNC_get_current_uid_gid = 15,
	BPF_FUNC_get_current_comm = 16,
	BPF_FUNC_get_cgroup_classid = 17,
	BPF_FUNC_skb_vlan_push = 18,
	BPF_FUNC_skb_vlan_pop = 19,
	BPF_FUNC_skb_get_tunnel_key = 20,
	BPF_FUNC_skb_set_tunnel_key = 21,
	BPF_FUNC_perf_event_read = 22,
	BPF_FUNC_redirect = 23,
	BPF_FUNC_get_route_realm = 24,
	BPF_FUNC_perf_event_output = 25,
	BPF_FUNC_skb_load_bytes = 26,
	BPF_FUNC_get_stackid = 27,
	BPF_FUNC_csum_diff = 28,
	BPF_FUNC_skb_get_tunnel_opt = 29,
	BPF_FUNC_skb_set_tunnel_opt = 30,
	BPF_FUNC_skb_change_proto = 31,
	BPF_FUNC_skb_change_type = 32,
	BPF_FUNC_skb_under_cgroup = 33,
	BPF_FUNC_get_hash_recalc = 34,
	BPF_FUNC_get_current_task = 35,
	BPF_FUNC_probe_write_user = 36,
	BPF_FUNC_current_task_under_cgroup = 37,
	BPF_FUNC_skb_change_tail = 38,
	BPF_FUNC_skb_pull_data = 39,
	BPF_FUNC_csum_update = 40,
	BPF_FUNC_set_hash_invalid = 41,
	BPF_FUNC_get_numa_node_id = 42,
	BPF_FUNC_skb_change_head = 43,
	BPF_FUNC_xdp_adjust_head = 44,
	BPF_FUNC_probe_read_str = 45,
	BPF_FUNC_get_socket_cookie = 46,
	BPF_FUNC_get_socket_uid = 47,
	BPF_FUNC_set_hash = 48,
	BPF_FUNC_setsockopt = 49,
	BPF_FUNC_skb_adjust_room = 50,
	BPF_FUNC_redirect_map = 51,
	BPF_FUNC_sk_redirect_map = 52,
	BPF_FUNC_sock_map_update = 53,
	BPF_FUNC_xdp_adjust_meta = 54,
	BPF_FUNC_perf_event_read_value = 55,
	BPF_FUNC_perf_prog_read_value = 56,
	BPF_FUNC_getsockopt = 57,
	BPF_FUNC_override_return = 58,
	BPF_FUNC_sock_ops_cb_flags_set = 59,
	BPF_FUNC_msg_redirect_map = 60,
	BPF_FUNC_msg_apply_bytes = 61,
	BPF_FUNC_msg_cork_bytes = 62,
	BPF_FUNC_msg_pull_data = 63,
	BPF_FUNC_bind = 64,
	BPF_FUNC_xdp_adjust_tail = 65,
	BPF_FUNC_skb_get_xfrm_state = 66,
	BPF_FUNC_get_stack = 67,
	BPF_FUNC_skb_load_bytes_relative = 68,
	BPF_FUNC_fib_lookup = 69,
	BPF_FUNC_sock_hash_update = 70,
	BPF_FUNC_msg_redirect_hash = 71,
	BPF_FUNC_sk_redirect_hash = 72,
	BPF_FUNC_lwt_push_encap = 73,
	BPF_FUNC_lwt_seg6_store_bytes = 74,
	BPF_FUNC_lwt_seg6_adjust_srh = 75,
	BPF_FUNC_lwt_seg6_action = 76,
	BPF_FUNC_rc_repeat = 77,
	BPF_FUNC_rc_keydown = 78,
	BPF_FUNC_skb_cgroup_id = 79,
	BPF_FUNC_get_current_cgroup_id = 80,
	BPF_FUNC_get_local_storage = 81,
	BPF_FUNC_sk_select_reuseport = 82,
	BPF_FUNC_skb_ancestor_cgroup_id = 83,
	BPF_FUNC_sk_lookup_tcp = 84,
	BPF_FUNC_sk_lookup_udp = 85,
	BPF_FUNC_sk_release = 86,
	BPF_FUNC_map_push_elem = 87,
	BPF_FUNC_map_pop_elem = 88,
	BPF_FUNC_map_peek_elem = 89,
	BPF_FUNC_msg_push_data = 90,
	BPF_FUNC_msg_pop_data = 91,
	BPF_FUNC_rc_pointer_rel = 92,
	BPF_FUNC_spin_lock = 93,
	BPF_FUNC_spin_unlock = 94,
	BPF_FUNC_sk_fullsock = 95,
	BPF_FUNC_tcp_sock = 96,
	BPF_FUNC_skb_ecn_set_ce = 97,
	BPF_FUNC_get_listener_sock = 98,
	BPF_FUNC_skc_lookup_tcp = 99,
	BPF_FUNC_tcp_check_syncookie = 100,
	BPF_FUNC_sysctl_get_name = 101,
	BPF_FUNC_sysctl_get_current_value = 102,
	BPF_FUNC_sysctl_get_new_value = 103,
	BPF_FUNC_sysctl_set_new_value = 104,
	BPF_FUNC_strtol = 105,
	BPF_FUNC_strtoul = 106,
	BPF_FUNC_sk_storage_get = 107,
	BPF_FUNC_sk_storage_delete = 108,
	BPF_FUNC_send_signal = 109,
	BPF_FUNC_tcp_gen_syncookie = 110,
	BPF_FUNC_skb_output = 111,
	BPF_FUNC_probe_read_user = 112,
	BPF_FUNC_probe_read_kernel = 113,
	BPF_FUNC_probe_read_user_str = 114,
	BPF_FUNC_probe_read_kernel_str = 115,
	BPF_FUNC_tcp_send_ack = 116,
	BPF_FUNC_send_signal_thread = 117,
	BPF_FUNC_jiffies64 = 118,
	BPF_FUNC_read_branch_records = 119,
	BPF_FUNC_get_ns_current_pid_tgid = 120,
	BPF_FUNC_xdp_output = 121,
	BPF_FUNC_get_netns_cookie = 122,
	BPF_FUNC_get_current_ancestor_cgroup_id = 123,
	BPF_FUNC_sk_assign = 124,
	BPF_FUNC_ktime_get_boot_ns = 125,
	BPF_FUNC_seq_printf = 126,
	BPF_FUNC_seq_write = 127,
	BPF_FUNC_sk_cgroup_id = 128,
	BPF_FUNC_sk_ancestor_cgroup_id = 129,
	BPF_FUNC_ringbuf_output = 130,
	BPF_FUNC_ringbuf_reserve = 131,
	BPF_FUNC_ringbuf_submit = 132,
	BPF_FUNC_ringbuf_discard = 133,
	BPF_FUNC_ringbuf_query = 134,
	BPF_FUNC_csum_level = 135,
	BPF_FUNC_skc_to_tcp6_sock = 136,
	BPF_FUNC_skc_to_tcp_sock = 137,
	BPF_FUNC_skc_to_tcp_timewait_sock = 138,
	BPF_FUNC_skc_to_tcp_request_sock = 139,
	BPF_FUNC_skc_to_udp6_sock = 140,
	BPF_FUNC_get_task_stack = 141,
	BPF_FUNC_load_hdr_opt = 142,
	BPF_FUNC_store_hdr_opt = 143,
	BPF_FUNC_reserve_hdr_opt = 144,
	BPF_FUNC_inode_storage_get = 145,
	BPF_FUNC_inode_storage_delete = 146,
	BPF_FUNC_d_path = 147,
	BPF_FUNC_copy_from_user = 148,
	BPF_FUNC_snprintf_btf = 149,
	BPF_FUNC_seq_printf_btf = 150,
	BPF_FUNC_skb_cgroup_classid = 151,
	BPF_FUNC_redirect_neigh = 152,
	BPF_FUNC_per_cpu_ptr = 153,
	BPF_FUNC_this_cpu_ptr = 154,
	BPF_FUNC_redirect_peer = 155,
	BPF_FUNC_task_storage_get = 156,
	BPF_FUNC_task_storage_delete = 157,
	BPF_FUNC_get_current_task_btf = 158,
	BPF_FUNC_bprm_opts_set = 159,
	BPF_FUNC_ktime_get_coarse_ns = 160,
	BPF_FUNC_ima_inode_hash = 161,
	BPF_FUNC_sock_from_file = 162,
	BPF_FUNC_check_mtu = 163,
	BPF_FUNC_for_each_map_elem = 164,
	BPF_FUNC_snprintf = 165,
	BPF_FUNC_sys_bpf = 166,
	BPF_FUNC_btf_find_by_name_kind = 167,
	BPF_FUNC_sys_close = 168,
	BPF_FUNC_timer_init = 169,
	BPF_FUNC_timer_set_callback = 170,
	BPF_FUNC_timer_start = 171,
	BPF_FUNC_timer_cancel = 172,
	BPF_FUNC_get_func_ip = 173,
	BPF_FUNC_get_attach_cookie = 174,
	BPF_FUNC_task_pt_regs = 175,
	BPF_FUNC_get_branch_snapshot = 176,
	BPF_FUNC_trace_vprintk = 177,
	BPF_FUNC_skc_to_unix_sock = 178,
	BPF_FUNC_kallsyms_lookup_name = 179,
	BPF_FUNC_find_vma = 180,
	BPF_FUNC_loop = 181,
	BPF_FUNC_strncmp = 182,
	BPF_FUNC_get_func_arg = 183,
	BPF_FUNC_get_func_ret = 184,
	BPF_FUNC_get_func_arg_cnt = 185,
	BPF_FUNC_get_retval = 186,
	BPF_FUNC_set_retval = 187,
	BPF_FUNC_xdp_get_buff_len = 188,
	BPF_FUNC_xdp_load_bytes = 189,
	BPF_FUNC_xdp_store_bytes = 190,
	BPF_FUNC_copy_from_user_task = 191,
	BPF_FUNC_skb_set_tstamp = 192,
	BPF_FUNC_ima_file_hash = 193,
	__BPF_FUNC_MAX_ID = 194,
};

enum {
	BPF_F_INDEX_MASK = 4294967295,
	BPF_F_CURRENT_CPU = 4294967295,
	BPF_F_CTXLEN_MASK = 0,
};

enum {
	BPF_F_GET_BRANCH_RECORDS_SIZE = 1,
};

struct bpf_perf_event_value {
	__u64 counter;
	__u64 enabled;
	__u64 running;
};

struct bpf_raw_tracepoint_args {
	__u64 args[0];
};

enum bpf_task_fd_type {
	BPF_FD_TYPE_RAW_TRACEPOINT = 0,
	BPF_FD_TYPE_TRACEPOINT = 1,
	BPF_FD_TYPE_KPROBE = 2,
	BPF_FD_TYPE_KRETPROBE = 3,
	BPF_FD_TYPE_UPROBE = 4,
	BPF_FD_TYPE_URETPROBE = 5,
};

struct btf_ptr {
	void *ptr;
	__u32 type_id;
	__u32 flags;
};

enum {
	BTF_F_COMPACT = 1,
	BTF_F_NONAME = 2,
	BTF_F_PTR_RAW = 4,
	BTF_F_ZERO = 8,
};

struct bpf_local_storage_data;

struct bpf_local_storage {
	struct bpf_local_storage_data *cache[16];
	struct hlist_head list;
	void *owner;
	struct callback_head rcu;
	raw_spinlock_t lock;
};

struct bpf_local_storage_map_bucket;

struct bpf_local_storage_map {
	struct bpf_map map;
	struct bpf_local_storage_map_bucket *buckets;
	u32 bucket_log;
	u16 elem_size;
	u16 cache_idx;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_func_proto {
	u64 (*func)(u64, u64, u64, u64, u64);
	bool gpl_only;
	bool pkt_access;
	enum bpf_return_type ret_type;
	union {
		struct {
			enum bpf_arg_type arg1_type;
			enum bpf_arg_type arg2_type;
			enum bpf_arg_type arg3_type;
			enum bpf_arg_type arg4_type;
			enum bpf_arg_type arg5_type;
		};
		enum bpf_arg_type arg_type[5];
	};
	union {
		struct {
			u32 *arg1_btf_id;
			u32 *arg2_btf_id;
			u32 *arg3_btf_id;
			u32 *arg4_btf_id;
			u32 *arg5_btf_id;
		};
		u32 *arg_btf_id[5];
	};
	int *ret_btf_id;
	bool (*allowed)(const struct bpf_prog *);
};

enum bpf_access_type {
	BPF_READ = 1,
	BPF_WRITE = 2,
};

struct bpf_verifier_log;

struct bpf_insn_access_aux {
	enum bpf_reg_type reg_type;
	union {
		int ctx_field_size;
		struct {
			struct btf *btf;
			u32 btf_id;
		};
	};
	struct bpf_verifier_log *log;
};

struct bpf_verifier_ops {
	const struct bpf_func_proto * (*get_func_proto)(enum bpf_func_id, const struct bpf_prog *);
	bool (*is_valid_access)(int, int, enum bpf_access_type, const struct bpf_prog *, struct bpf_insn_access_aux *);
	int (*gen_prologue)(struct bpf_insn *, bool, const struct bpf_prog *);
	int (*gen_ld_abs)(const struct bpf_insn *, struct bpf_insn *);
	u32 (*convert_ctx_access)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);
	int (*btf_struct_access)(struct bpf_verifier_log *, const struct btf *, const struct btf_type *, int, int, enum bpf_access_type, u32 *, enum bpf_type_flag *);
};

struct bpf_array_aux {
	struct list_head poke_progs;
	struct bpf_map *map;
	struct mutex poke_mutex;
	struct work_struct work;
};

struct bpf_array {
	struct bpf_map map;
	u32 elem_size;
	u32 index_mask;
	struct bpf_array_aux *aux;
	int: 32;
	union {
		char value[0];
		void *ptrs[0];
		void *pptrs[0];
	};
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_event_entry {
	struct perf_event *event;
	struct file *perf_file;
	struct file *map_file;
	struct callback_head rcu;
};

typedef long unsigned int (*bpf_ctx_copy_t)(void *, const void *, long unsigned int, long unsigned int);

struct bpf_trace_run_ctx {
	struct bpf_run_ctx run_ctx;
	u64 bpf_cookie;
};

typedef u32 (*bpf_prog_run_fn)(const struct bpf_prog *, const void *);

typedef struct user_regs_struct bpf_user_pt_regs_t;

struct bpf_perf_event_data {
	bpf_user_pt_regs_t regs;
	__u64 sample_period;
	__u64 addr;
};

struct btf_id_set {
	u32 cnt;
	u32 ids[0];
};

typedef unsigned int (*bpf_dispatcher_fn)(const void *, const struct bpf_insn *, unsigned int (*)(const void *, const struct bpf_insn *));

struct perf_event_query_bpf {
	__u32 ids_len;
	__u32 prog_cnt;
	__u32 ids[0];
};

struct bpf_perf_event_data_kern {
	bpf_user_pt_regs_t *regs;
	struct perf_sample_data *data;
	struct perf_event *event;
};

enum {
	BTF_TRACING_TYPE_TASK = 0,
	BTF_TRACING_TYPE_FILE = 1,
	BTF_TRACING_TYPE_VMA = 2,
	MAX_BTF_TRACING_TYPE = 3,
};

struct bpf_local_storage_map_bucket {
	struct hlist_head list;
	raw_spinlock_t lock;
};

struct bpf_local_storage_data {
	struct bpf_local_storage_map *smap;
	int: 32;
	u8 data[0];
};

struct trace_event_raw_bpf_trace_printk {
	struct trace_entry ent;
	u32 __data_loc_bpf_string;
	char __data[0];
};

struct trace_event_data_offsets_bpf_trace_printk {
	u32 bpf_string;
};

typedef void (*btf_trace_bpf_trace_printk)(void *, const char *);

struct bpf_trace_module {
	struct module *module;
	struct list_head list;
};

typedef u64 (*btf_bpf_probe_read_user)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_user_str)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_kernel)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_read_kernel_str)(void *, u32, const void *);

typedef u64 (*btf_bpf_probe_write_user)(void *, const void *, u32);

typedef u64 (*btf_bpf_trace_printk)(char *, u32, u64, u64, u64);

typedef u64 (*btf_bpf_trace_vprintk)(char *, u32, const void *, u32);

typedef u64 (*btf_bpf_seq_printf)(struct seq_file *, char *, u32, const void *, u32);

typedef u64 (*btf_bpf_seq_write)(struct seq_file *, const void *, u32);

typedef u64 (*btf_bpf_seq_printf_btf)(struct seq_file *, struct btf_ptr *, u32, u64);

typedef u64 (*btf_bpf_perf_event_read)(struct bpf_map *, u64);

typedef u64 (*btf_bpf_perf_event_read_value)(struct bpf_map *, u64, struct bpf_perf_event_value *, u32);

struct bpf_trace_sample_data {
	struct perf_sample_data sds[3];
};

typedef u64 (*btf_bpf_perf_event_output)(struct pt_regs *, struct bpf_map *, u64, void *, u64);

struct bpf_nested_pt_regs {
	struct pt_regs regs[3];
};

typedef u64 (*btf_bpf_get_current_task)();

typedef u64 (*btf_bpf_get_current_task_btf)();

typedef u64 (*btf_bpf_task_pt_regs)(struct task_struct *);

typedef u64 (*btf_bpf_current_task_under_cgroup)(struct bpf_map *, u32);

struct send_signal_irq_work {
	struct irq_work irq_work;
	struct task_struct *task;
	u32 sig;
	enum pid_type type;
};

typedef u64 (*btf_bpf_send_signal)(u32);

typedef u64 (*btf_bpf_send_signal_thread)(u32);

typedef u64 (*btf_bpf_d_path)(struct path *, char *, u32);

typedef u64 (*btf_bpf_snprintf_btf)(char *, u32, struct btf_ptr *, u32, u64);

typedef u64 (*btf_bpf_get_func_ip_tracing)(void *);

typedef u64 (*btf_bpf_get_func_ip_kprobe)(struct pt_regs *);

typedef u64 (*btf_bpf_get_func_ip_kprobe_multi)(struct pt_regs *);

typedef u64 (*btf_bpf_get_attach_cookie_kprobe_multi)(struct pt_regs *);

typedef u64 (*btf_bpf_get_attach_cookie_trace)(void *);

typedef u64 (*btf_bpf_get_attach_cookie_pe)(struct bpf_perf_event_data_kern *);

typedef u64 (*btf_bpf_get_branch_snapshot)(void *, u32, u64);

typedef u64 (*btf_get_func_arg)(void *, u32, u64 *);

typedef u64 (*btf_get_func_ret)(void *, u64 *);

typedef u64 (*btf_get_func_arg_cnt)(void *);

typedef u64 (*btf_bpf_perf_event_output_tp)(void *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_get_stackid_tp)(void *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stack_tp)(void *, void *, u32, u64);

typedef u64 (*btf_bpf_perf_prog_read_value)(struct bpf_perf_event_data_kern *, struct bpf_perf_event_value *, u32);

typedef u64 (*btf_bpf_read_branch_records)(struct bpf_perf_event_data_kern *, void *, u32, u64);

struct bpf_raw_tp_regs {
	struct pt_regs regs[3];
};

typedef u64 (*btf_bpf_perf_event_output_raw_tp)(struct bpf_raw_tracepoint_args *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_get_stackid_raw_tp)(struct bpf_raw_tracepoint_args *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stack_raw_tp)(struct bpf_raw_tracepoint_args *, void *, u32, u64);

enum dynevent_type {
	DYNEVENT_TYPE_SYNTH = 1,
	DYNEVENT_TYPE_KPROBE = 2,
	DYNEVENT_TYPE_NONE = 3,
};

struct dynevent_cmd;

typedef int (*dynevent_create_fn_t)(struct dynevent_cmd *);

struct dynevent_cmd {
	struct seq_buf seq;
	const char *event_name;
	unsigned int n_fields;
	enum dynevent_type type;
	dynevent_create_fn_t run_command;
	void *private_data;
};

struct kprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int ip;
};

struct kretprobe_trace_entry_head {
	struct trace_entry ent;
	long unsigned int func;
	long unsigned int ret_ip;
};

typedef int (*dynevent_check_arg_fn_t)(void *);

struct dynevent_arg {
	const char *str;
	char separator;
};

struct trace_kprobe {
	struct dyn_event devent;
	struct kretprobe rp;
	long unsigned int *nhit;
	const char *symbol;
	struct trace_probe tp;
};

struct trace_event_raw_error_report_template {
	struct trace_entry ent;
	enum error_detector error_detector;
	long unsigned int id;
	char __data[0];
};

struct trace_event_data_offsets_error_report_template {};

typedef void (*btf_trace_error_report_end)(void *, enum error_detector, long unsigned int);

enum cpufreq_table_sorting {
	CPUFREQ_TABLE_UNSORTED = 0,
	CPUFREQ_TABLE_SORTED_ASCENDING = 1,
	CPUFREQ_TABLE_SORTED_DESCENDING = 2,
};

struct cpufreq_cpuinfo {
	unsigned int max_freq;
	unsigned int min_freq;
	unsigned int transition_latency;
};

struct cpufreq_stats;

struct thermal_cooling_device;

struct clk;

struct cpufreq_governor;

struct cpufreq_frequency_table;

struct cpufreq_policy {
	cpumask_var_t cpus;
	cpumask_var_t related_cpus;
	cpumask_var_t real_cpus;
	unsigned int shared_type;
	unsigned int cpu;
	struct clk *clk;
	struct cpufreq_cpuinfo cpuinfo;
	unsigned int min;
	unsigned int max;
	unsigned int cur;
	unsigned int suspend_freq;
	unsigned int policy;
	unsigned int last_policy;
	struct cpufreq_governor *governor;
	void *governor_data;
	char last_governor[16];
	struct work_struct update;
	struct freq_constraints constraints;
	struct freq_qos_request *min_freq_req;
	struct freq_qos_request *max_freq_req;
	struct cpufreq_frequency_table *freq_table;
	enum cpufreq_table_sorting freq_table_sorted;
	struct list_head policy_list;
	struct kobject kobj;
	struct completion kobj_unregister;
	struct rw_semaphore rwsem;
	bool fast_switch_possible;
	bool fast_switch_enabled;
	bool strict_target;
	bool efficiencies_available;
	unsigned int transition_delay_us;
	bool dvfs_possible_from_any_cpu;
	unsigned int cached_target_freq;
	unsigned int cached_resolved_idx;
	bool transition_ongoing;
	spinlock_t transition_lock;
	wait_queue_head_t transition_wait;
	struct task_struct *transition_task;
	struct cpufreq_stats *stats;
	void *driver_data;
	struct thermal_cooling_device *cdev;
	struct notifier_block nb_min;
	struct notifier_block nb_max;
};

struct cpufreq_governor {
	char name[16];
	int (*init)(struct cpufreq_policy *);
	void (*exit)(struct cpufreq_policy *);
	int (*start)(struct cpufreq_policy *);
	void (*stop)(struct cpufreq_policy *);
	void (*limits)(struct cpufreq_policy *);
	ssize_t (*show_setspeed)(struct cpufreq_policy *, char *);
	int (*store_setspeed)(struct cpufreq_policy *, unsigned int);
	struct list_head governor_list;
	struct module *owner;
	u8 flags;
};

struct cpufreq_frequency_table {
	unsigned int flags;
	unsigned int driver_data;
	unsigned int frequency;
};

struct trace_event_raw_cpu {
	struct trace_entry ent;
	u32 state;
	u32 cpu_id;
	char __data[0];
};

struct trace_event_raw_powernv_throttle {
	struct trace_entry ent;
	int chip_id;
	u32 __data_loc_reason;
	int pmax;
	char __data[0];
};

struct trace_event_raw_pstate_sample {
	struct trace_entry ent;
	u32 core_busy;
	u32 scaled_busy;
	u32 from;
	u32 to;
	u64 mperf;
	u64 aperf;
	u64 tsc;
	u32 freq;
	u32 io_boost;
	char __data[0];
};

struct trace_event_raw_cpu_frequency_limits {
	struct trace_entry ent;
	u32 min_freq;
	u32 max_freq;
	u32 cpu_id;
	char __data[0];
};

struct trace_event_raw_device_pm_callback_start {
	struct trace_entry ent;
	u32 __data_loc_device;
	u32 __data_loc_driver;
	u32 __data_loc_parent;
	u32 __data_loc_pm_ops;
	int event;
	char __data[0];
};

struct trace_event_raw_device_pm_callback_end {
	struct trace_entry ent;
	u32 __data_loc_device;
	u32 __data_loc_driver;
	int error;
	char __data[0];
};

struct trace_event_raw_suspend_resume {
	struct trace_entry ent;
	const char *action;
	int val;
	bool start;
	char __data[0];
};

struct trace_event_raw_wakeup_source {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	char __data[0];
};

struct trace_event_raw_clock {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	u64 cpu_id;
	char __data[0];
};

struct trace_event_raw_power_domain {
	struct trace_entry ent;
	u32 __data_loc_name;
	u64 state;
	u64 cpu_id;
	char __data[0];
};

struct trace_event_raw_cpu_latency_qos_request {
	struct trace_entry ent;
	s32 value;
	char __data[0];
};

struct trace_event_raw_pm_qos_update {
	struct trace_entry ent;
	enum pm_qos_req_action action;
	int prev_value;
	int curr_value;
	char __data[0];
};

struct trace_event_raw_dev_pm_qos_request {
	struct trace_entry ent;
	u32 __data_loc_name;
	enum dev_pm_qos_req_type type;
	s32 new_value;
	char __data[0];
};

struct trace_event_data_offsets_cpu {};

struct trace_event_data_offsets_powernv_throttle {
	u32 reason;
};

struct trace_event_data_offsets_pstate_sample {};

struct trace_event_data_offsets_cpu_frequency_limits {};

struct trace_event_data_offsets_device_pm_callback_start {
	u32 device;
	u32 driver;
	u32 parent;
	u32 pm_ops;
};

struct trace_event_data_offsets_device_pm_callback_end {
	u32 device;
	u32 driver;
};

struct trace_event_data_offsets_suspend_resume {};

struct trace_event_data_offsets_wakeup_source {
	u32 name;
};

struct trace_event_data_offsets_clock {
	u32 name;
};

struct trace_event_data_offsets_power_domain {
	u32 name;
};

struct trace_event_data_offsets_cpu_latency_qos_request {};

struct trace_event_data_offsets_pm_qos_update {};

struct trace_event_data_offsets_dev_pm_qos_request {
	u32 name;
};

typedef void (*btf_trace_cpu_idle)(void *, unsigned int, unsigned int);

typedef void (*btf_trace_powernv_throttle)(void *, int, const char *, int);

typedef void (*btf_trace_pstate_sample)(void *, u32, u32, u32, u32, u64, u64, u64, u32, u32);

typedef void (*btf_trace_cpu_frequency)(void *, unsigned int, unsigned int);

typedef void (*btf_trace_cpu_frequency_limits)(void *, struct cpufreq_policy *);

typedef void (*btf_trace_device_pm_callback_start)(void *, struct device *, const char *, int);

typedef void (*btf_trace_device_pm_callback_end)(void *, struct device *, int);

typedef void (*btf_trace_suspend_resume)(void *, const char *, int, bool);

typedef void (*btf_trace_wakeup_source_activate)(void *, const char *, unsigned int);

typedef void (*btf_trace_wakeup_source_deactivate)(void *, const char *, unsigned int);

typedef void (*btf_trace_clock_enable)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_clock_disable)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_clock_set_rate)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_power_domain_target)(void *, const char *, unsigned int, unsigned int);

typedef void (*btf_trace_pm_qos_add_request)(void *, s32);

typedef void (*btf_trace_pm_qos_update_request)(void *, s32);

typedef void (*btf_trace_pm_qos_remove_request)(void *, s32);

typedef void (*btf_trace_pm_qos_update_target)(void *, enum pm_qos_req_action, int, int);

typedef void (*btf_trace_pm_qos_update_flags)(void *, enum pm_qos_req_action, int, int);

typedef void (*btf_trace_dev_pm_qos_add_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_dev_pm_qos_update_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

typedef void (*btf_trace_dev_pm_qos_remove_request)(void *, const char *, enum dev_pm_qos_req_type, s32);

struct dynevent_arg_pair {
	const char *lhs;
	const char *rhs;
	char operator;
	char separator;
};

struct trace_probe_log {
	const char *subsystem;
	const char **argv;
	int argc;
	int index;
};

typedef __u16 __le16;

typedef __u64 __le64;

typedef __u64 __be64;

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
};

struct static_key_true {
	struct static_key key;
};

struct rhash_lock_head;

struct bucket_table {
	unsigned int size;
	unsigned int nest;
	u32 hash_rnd;
	struct list_head walkers;
	struct callback_head rcu;
	struct bucket_table *future_tbl;
	struct lockdep_map dep_map;
	struct rhash_lock_head *buckets[0];
};

typedef sockptr_t bpfptr_t;

struct bpf_verifier_log {
	u32 level;
	char kbuf[1024];
	char *ubuf;
	u32 len_used;
	u32 len_total;
};

struct bpf_subprog_info {
	u32 start;
	u32 linfo_idx;
	u16 stack_depth;
	bool has_tail_call;
	bool tail_call_reachable;
	bool has_ld_abs;
	bool is_async_cb;
};

struct bpf_id_pair {
	u32 old;
	u32 cur;
};

struct bpf_verifier_stack_elem;

struct bpf_verifier_state;

struct bpf_verifier_state_list;

struct bpf_insn_aux_data;

struct bpf_verifier_env {
	u32 insn_idx;
	u32 prev_insn_idx;
	struct bpf_prog *prog;
	const struct bpf_verifier_ops *ops;
	struct bpf_verifier_stack_elem *head;
	int stack_size;
	bool strict_alignment;
	bool test_state_freq;
	struct bpf_verifier_state *cur_state;
	struct bpf_verifier_state_list **explored_states;
	struct bpf_verifier_state_list *free_list;
	struct bpf_map *used_maps[64];
	struct btf_mod_pair used_btfs[64];
	u32 used_map_cnt;
	u32 used_btf_cnt;
	u32 id_gen;
	bool explore_alu_limits;
	bool allow_ptr_leaks;
	bool allow_uninit_stack;
	bool allow_ptr_to_map_access;
	bool bpf_capable;
	bool bypass_spec_v1;
	bool bypass_spec_v4;
	bool seen_direct_write;
	struct bpf_insn_aux_data *insn_aux_data;
	const struct bpf_line_info *prev_linfo;
	struct bpf_verifier_log log;
	struct bpf_subprog_info subprog_info[257];
	struct bpf_id_pair idmap_scratch[75];
	struct {
		int *insn_state;
		int *insn_stack;
		int cur_stack;
	} cfg;
	u32 pass_cnt;
	u32 subprog_cnt;
	u32 prev_insn_processed;
	u32 insn_processed;
	u32 prev_jmps_processed;
	u32 jmps_processed;
	u64 verification_time;
	u32 max_states_per_insn;
	u32 total_states;
	u32 peak_states;
	u32 longest_mark_read_walk;
	bpfptr_t fd_array;
	u32 scratched_regs;
	u64 scratched_stack_slots;
	u32 prev_log_len;
	u32 prev_insn_print_len;
	char type_str_buf[64];
};

struct tnum {
	u64 value;
	u64 mask;
};

enum bpf_reg_liveness {
	REG_LIVE_NONE = 0,
	REG_LIVE_READ32 = 1,
	REG_LIVE_READ64 = 2,
	REG_LIVE_READ = 3,
	REG_LIVE_WRITTEN = 4,
	REG_LIVE_DONE = 8,
};

struct bpf_reg_state {
	enum bpf_reg_type type;
	s32 off;
	union {
		int range;
		struct {
			struct bpf_map *map_ptr;
			u32 map_uid;
		};
		struct {
			struct btf *btf;
			u32 btf_id;
		};
		u32 mem_size;
		struct {
			long unsigned int raw1;
			long unsigned int raw2;
		} raw;
		u32 subprogno;
	};
	u32 id;
	u32 ref_obj_id;
	struct tnum var_off;
	s64 smin_value;
	s64 smax_value;
	u64 umin_value;
	u64 umax_value;
	s32 s32_min_value;
	s32 s32_max_value;
	u32 u32_min_value;
	u32 u32_max_value;
	struct bpf_reg_state *parent;
	u32 frameno;
	s32 subreg_def;
	enum bpf_reg_liveness live;
	bool precise;
};

struct bpf_reference_state;

struct bpf_stack_state;

struct bpf_func_state {
	struct bpf_reg_state regs[11];
	int callsite;
	u32 frameno;
	u32 subprogno;
	u32 async_entry_cnt;
	bool in_callback_fn;
	bool in_async_callback_fn;
	int acquired_refs;
	struct bpf_reference_state *refs;
	int allocated_stack;
	struct bpf_stack_state *stack;
};

enum bpf_jit_poke_reason {
	BPF_POKE_REASON_TAIL_CALL = 0,
};

struct bpf_empty_prog_array {
	struct bpf_prog_array hdr;
	struct bpf_prog *null_prog;
};

enum bpf_text_poke_type {
	BPF_MOD_CALL = 0,
	BPF_MOD_JUMP = 1,
};

struct rnd_state {
	__u32 s1;
	__u32 s2;
	__u32 s3;
	__u32 s4;
};

enum xdp_mem_type {
	MEM_TYPE_PAGE_SHARED = 0,
	MEM_TYPE_PAGE_ORDER0 = 1,
	MEM_TYPE_PAGE_POOL = 2,
	MEM_TYPE_XSK_BUFF_POOL = 3,
	MEM_TYPE_MAX = 4,
};

struct xdp_cpumap_stats {
	unsigned int redirect;
	unsigned int pass;
	unsigned int drop;
};

enum btf_kfunc_type {
	BTF_KFUNC_TYPE_CHECK = 0,
	BTF_KFUNC_TYPE_ACQUIRE = 1,
	BTF_KFUNC_TYPE_RELEASE = 2,
	BTF_KFUNC_TYPE_RET_NULL = 3,
	BTF_KFUNC_TYPE_MAX = 4,
};

struct bpf_stack_state {
	struct bpf_reg_state spilled_ptr;
	u8 slot_type[8];
};

struct bpf_reference_state {
	int id;
	int insn_idx;
};

struct bpf_idx_pair {
	u32 prev_idx;
	u32 idx;
};

struct bpf_verifier_state {
	struct bpf_func_state *frame[8];
	struct bpf_verifier_state *parent;
	u32 branches;
	u32 insn_idx;
	u32 curframe;
	u32 active_spin_lock;
	bool speculative;
	u32 first_insn_idx;
	u32 last_insn_idx;
	struct bpf_idx_pair *jmp_history;
	u32 jmp_history_cnt;
};

struct bpf_verifier_state_list {
	struct bpf_verifier_state state;
	struct bpf_verifier_state_list *next;
	int miss_cnt;
	int hit_cnt;
};

struct bpf_insn_aux_data {
	union {
		enum bpf_reg_type ptr_type;
		long unsigned int map_ptr_state;
		s32 call_imm;
		u32 alu_limit;
		struct {
			u32 map_index;
			u32 map_off;
		};
		struct {
			enum bpf_reg_type reg_type;
			union {
				struct {
					struct btf *btf;
					u32 btf_id;
				};
				u32 mem_size;
			};
		} btf_var;
	};
	u64 map_key_state;
	int ctx_field_size;
	u32 seen;
	bool sanitize_stack_spill;
	bool zext_dst;
	u8 alu_state;
	unsigned int orig_idx;
	bool prune_point;
};

struct bpf_prog_pack {
	struct list_head list;
	void *ptr;
	long unsigned int bitmap[0];
};

struct bpf_prog_dummy {
	struct bpf_prog prog;
};

typedef u64 (*btf_bpf_user_rnd_u32)();

typedef u64 (*btf_bpf_get_raw_cpu_id)();

struct _bpf_dtab_netdev {
	struct net_device *dev;
};

struct rhash_lock_head {};

struct xdp_mem_allocator {
	struct xdp_mem_info mem;
	union {
		void *allocator;
		struct page_pool *page_pool;
	};
	struct rhash_head node;
	struct callback_head rcu;
};

struct trace_event_raw_xdp_exception {
	struct trace_entry ent;
	int prog_id;
	u32 act;
	int ifindex;
	char __data[0];
};

struct trace_event_raw_xdp_bulk_tx {
	struct trace_entry ent;
	int ifindex;
	u32 act;
	int drops;
	int sent;
	int err;
	char __data[0];
};

struct trace_event_raw_xdp_redirect_template {
	struct trace_entry ent;
	int prog_id;
	u32 act;
	int ifindex;
	int err;
	int to_ifindex;
	u32 map_id;
	int map_index;
	char __data[0];
};

struct trace_event_raw_xdp_cpumap_kthread {
	struct trace_entry ent;
	int map_id;
	u32 act;
	int cpu;
	unsigned int drops;
	unsigned int processed;
	int sched;
	unsigned int xdp_pass;
	unsigned int xdp_drop;
	unsigned int xdp_redirect;
	char __data[0];
};

struct trace_event_raw_xdp_cpumap_enqueue {
	struct trace_entry ent;
	int map_id;
	u32 act;
	int cpu;
	unsigned int drops;
	unsigned int processed;
	int to_cpu;
	char __data[0];
};

struct trace_event_raw_xdp_devmap_xmit {
	struct trace_entry ent;
	int from_ifindex;
	u32 act;
	int to_ifindex;
	int drops;
	int sent;
	int err;
	char __data[0];
};

struct trace_event_raw_mem_disconnect {
	struct trace_entry ent;
	const struct xdp_mem_allocator *xa;
	u32 mem_id;
	u32 mem_type;
	const void *allocator;
	char __data[0];
};

struct trace_event_raw_mem_connect {
	struct trace_entry ent;
	const struct xdp_mem_allocator *xa;
	u32 mem_id;
	u32 mem_type;
	const void *allocator;
	const struct xdp_rxq_info *rxq;
	int ifindex;
	char __data[0];
};

struct trace_event_raw_mem_return_failed {
	struct trace_entry ent;
	const struct page *page;
	u32 mem_id;
	u32 mem_type;
	char __data[0];
};

struct trace_event_data_offsets_xdp_exception {};

struct trace_event_data_offsets_xdp_bulk_tx {};

struct trace_event_data_offsets_xdp_redirect_template {};

struct trace_event_data_offsets_xdp_cpumap_kthread {};

struct trace_event_data_offsets_xdp_cpumap_enqueue {};

struct trace_event_data_offsets_xdp_devmap_xmit {};

struct trace_event_data_offsets_mem_disconnect {};

struct trace_event_data_offsets_mem_connect {};

struct trace_event_data_offsets_mem_return_failed {};

typedef void (*btf_trace_xdp_exception)(void *, const struct net_device *, const struct bpf_prog *, u32);

typedef void (*btf_trace_xdp_bulk_tx)(void *, const struct net_device *, int, int, int);

typedef void (*btf_trace_xdp_redirect)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_err)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_map)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_redirect_map_err)(void *, const struct net_device *, const struct bpf_prog *, const void *, int, enum bpf_map_type, u32, u32);

typedef void (*btf_trace_xdp_cpumap_kthread)(void *, int, unsigned int, unsigned int, int, struct xdp_cpumap_stats *);

typedef void (*btf_trace_xdp_cpumap_enqueue)(void *, int, unsigned int, unsigned int, int);

typedef void (*btf_trace_xdp_devmap_xmit)(void *, const struct net_device *, const struct net_device *, int, int, int);

typedef void (*btf_trace_mem_disconnect)(void *, const struct xdp_mem_allocator *);

typedef void (*btf_trace_mem_connect)(void *, const struct xdp_mem_allocator *, const struct xdp_rxq_info *);

typedef void (*btf_trace_mem_return_failed)(void *, const struct xdp_mem_info *, const struct page *);

enum bpf_cmd {
	BPF_MAP_CREATE = 0,
	BPF_MAP_LOOKUP_ELEM = 1,
	BPF_MAP_UPDATE_ELEM = 2,
	BPF_MAP_DELETE_ELEM = 3,
	BPF_MAP_GET_NEXT_KEY = 4,
	BPF_PROG_LOAD = 5,
	BPF_OBJ_PIN = 6,
	BPF_OBJ_GET = 7,
	BPF_PROG_ATTACH = 8,
	BPF_PROG_DETACH = 9,
	BPF_PROG_TEST_RUN = 10,
	BPF_PROG_RUN = 10,
	BPF_PROG_GET_NEXT_ID = 11,
	BPF_MAP_GET_NEXT_ID = 12,
	BPF_PROG_GET_FD_BY_ID = 13,
	BPF_MAP_GET_FD_BY_ID = 14,
	BPF_OBJ_GET_INFO_BY_FD = 15,
	BPF_PROG_QUERY = 16,
	BPF_RAW_TRACEPOINT_OPEN = 17,
	BPF_BTF_LOAD = 18,
	BPF_BTF_GET_FD_BY_ID = 19,
	BPF_TASK_FD_QUERY = 20,
	BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21,
	BPF_MAP_FREEZE = 22,
	BPF_BTF_GET_NEXT_ID = 23,
	BPF_MAP_LOOKUP_BATCH = 24,
	BPF_MAP_LOOKUP_AND_DELETE_BATCH = 25,
	BPF_MAP_UPDATE_BATCH = 26,
	BPF_MAP_DELETE_BATCH = 27,
	BPF_LINK_CREATE = 28,
	BPF_LINK_UPDATE = 29,
	BPF_LINK_GET_FD_BY_ID = 30,
	BPF_LINK_GET_NEXT_ID = 31,
	BPF_ENABLE_STATS = 32,
	BPF_ITER_CREATE = 33,
	BPF_LINK_DETACH = 34,
	BPF_PROG_BIND_MAP = 35,
};

enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	MAX_BPF_LINK_TYPE = 9,
};

enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

enum {
	BPF_F_NO_PREALLOC = 1,
	BPF_F_NO_COMMON_LRU = 2,
	BPF_F_NUMA_NODE = 4,
	BPF_F_RDONLY = 8,
	BPF_F_WRONLY = 16,
	BPF_F_STACK_BUILD_ID = 32,
	BPF_F_ZERO_SEED = 64,
	BPF_F_RDONLY_PROG = 128,
	BPF_F_WRONLY_PROG = 256,
	BPF_F_CLONE = 512,
	BPF_F_MMAPABLE = 1024,
	BPF_F_PRESERVE_ELEMS = 2048,
	BPF_F_INNER_MAP = 4096,
};

enum bpf_stats_type {
	BPF_STATS_RUN_TIME = 0,
};

struct bpf_prog_info {
	__u32 type;
	__u32 id;
	__u8 tag[8];
	__u32 jited_prog_len;
	__u32 xlated_prog_len;
	__u64 jited_prog_insns;
	__u64 xlated_prog_insns;
	__u64 load_time;
	__u32 created_by_uid;
	__u32 nr_map_ids;
	__u64 map_ids;
	char name[16];
	__u32 ifindex;
	__u32 gpl_compatible: 1;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 nr_jited_ksyms;
	__u32 nr_jited_func_lens;
	__u64 jited_ksyms;
	__u64 jited_func_lens;
	__u32 btf_id;
	__u32 func_info_rec_size;
	__u64 func_info;
	__u32 nr_func_info;
	__u32 nr_line_info;
	__u64 line_info;
	__u64 jited_line_info;
	__u32 nr_jited_line_info;
	__u32 line_info_rec_size;
	__u32 jited_line_info_rec_size;
	__u32 nr_prog_tags;
	__u64 prog_tags;
	__u64 run_time_ns;
	__u64 run_cnt;
	__u64 recursion_misses;
	__u32 verified_insns;
	int: 32;
};

struct bpf_map_info {
	__u32 type;
	__u32 id;
	__u32 key_size;
	__u32 value_size;
	__u32 max_entries;
	__u32 map_flags;
	char name[16];
	__u32 ifindex;
	__u32 btf_vmlinux_value_type_id;
	__u64 netns_dev;
	__u64 netns_ino;
	__u32 btf_id;
	__u32 btf_key_type_id;
	__u32 btf_value_type_id;
	int: 32;
	__u64 map_extra;
};

struct bpf_btf_info {
	__u64 btf;
	__u32 btf_size;
	__u32 id;
	__u64 name;
	__u32 name_len;
	__u32 kernel_btf;
};

struct bpf_link_info {
	__u32 type;
	__u32 id;
	__u32 prog_id;
	int: 32;
	union {
		struct {
			__u64 tp_name;
			__u32 tp_name_len;
			int: 32;
		} raw_tracepoint;
		struct {
			__u32 attach_type;
			__u32 target_obj_id;
			__u32 target_btf_id;
		} tracing;
		struct {
			__u64 cgroup_id;
			__u32 attach_type;
		} cgroup;
		struct {
			__u64 target_name;
			__u32 target_name_len;
			union {
				struct {
					__u32 map_id;
				} map;
			};
		} iter;
		struct {
			__u32 netns_ino;
			__u32 attach_type;
		} netns;
		struct {
			__u32 ifindex;
		} xdp;
	};
};

struct bpf_attach_target_info {
	struct btf_func_model fmodel;
	long int tgt_addr;
	const char *tgt_name;
	const struct btf_type *tgt_type;
};

struct bpf_link_ops;

struct bpf_link {
	atomic64_t refcnt;
	u32 id;
	enum bpf_link_type type;
	const struct bpf_link_ops *ops;
	struct bpf_prog *prog;
	struct work_struct work;
};

struct bpf_link_ops {
	void (*release)(struct bpf_link *);
	void (*dealloc)(struct bpf_link *);
	int (*detach)(struct bpf_link *);
	int (*update_prog)(struct bpf_link *, struct bpf_prog *, struct bpf_prog *);
	void (*show_fdinfo)(const struct bpf_link *, struct seq_file *);
	int (*fill_link_info)(const struct bpf_link *, struct bpf_link_info *);
};

struct bpf_link_primer {
	struct bpf_link *link;
	struct file *file;
	int fd;
	u32 id;
};

enum perf_bpf_event_type {
	PERF_BPF_EVENT_UNKNOWN = 0,
	PERF_BPF_EVENT_PROG_LOAD = 1,
	PERF_BPF_EVENT_PROG_UNLOAD = 2,
	PERF_BPF_EVENT_MAX = 3,
};

enum bpf_audit {
	BPF_AUDIT_LOAD = 0,
	BPF_AUDIT_UNLOAD = 1,
	BPF_AUDIT_MAX = 2,
};

struct bpf_prog_kstats {
	u64 nsecs;
	u64 cnt;
	u64 misses;
};

struct bpf_tracing_link {
	struct bpf_link link;
	enum bpf_attach_type attach_type;
	struct bpf_trampoline *trampoline;
	struct bpf_prog *tgt_prog;
	int: 32;
};

struct bpf_raw_tp_link {
	struct bpf_link link;
	struct bpf_raw_event_map *btp;
	int: 32;
};

struct bpf_perf_link {
	struct bpf_link link;
	struct file *perf_file;
	int: 32;
};

typedef u64 (*btf_bpf_sys_bpf)(int, union bpf_attr *, u32);

typedef u64 (*btf_bpf_sys_close)(u32);

typedef u64 (*btf_bpf_kallsyms_lookup_name)(const char *, int, int, u64 *);

struct audit_buffer;

struct tree_descr {
	const char *name;
	const struct file_operations *ops;
	int mode;
};

struct bpf_preload_info {
	char link_name[16];
	struct bpf_link *link;
};

struct bpf_preload_ops {
	int (*preload)(struct bpf_preload_info *);
	struct module *owner;
};

enum bpf_type {
	BPF_TYPE_UNSPEC = 0,
	BPF_TYPE_PROG = 1,
	BPF_TYPE_MAP = 2,
	BPF_TYPE_LINK = 3,
};

struct map_iter {
	void *key;
	bool done;
};

enum {
	OPT_MODE = 0,
};

struct bpf_mount_opts {
	umode_t mode;
};

enum {
	BTF_KIND_UNKN = 0,
	BTF_KIND_INT = 1,
	BTF_KIND_PTR = 2,
	BTF_KIND_ARRAY = 3,
	BTF_KIND_STRUCT = 4,
	BTF_KIND_UNION = 5,
	BTF_KIND_ENUM = 6,
	BTF_KIND_FWD = 7,
	BTF_KIND_TYPEDEF = 8,
	BTF_KIND_VOLATILE = 9,
	BTF_KIND_CONST = 10,
	BTF_KIND_RESTRICT = 11,
	BTF_KIND_FUNC = 12,
	BTF_KIND_FUNC_PROTO = 13,
	BTF_KIND_VAR = 14,
	BTF_KIND_DATASEC = 15,
	BTF_KIND_FLOAT = 16,
	BTF_KIND_DECL_TAG = 17,
	BTF_KIND_TYPE_TAG = 18,
	NR_BTF_KINDS = 19,
	BTF_KIND_MAX = 18,
};

struct btf_member {
	__u32 name_off;
	__u32 type;
	__u32 offset;
};

struct btf_param {
	__u32 name_off;
	__u32 type;
};

enum btf_func_linkage {
	BTF_FUNC_STATIC = 0,
	BTF_FUNC_GLOBAL = 1,
	BTF_FUNC_EXTERN = 2,
};

struct btf_var_secinfo {
	__u32 type;
	__u32 offset;
	__u32 size;
};

enum sk_action {
	SK_DROP = 0,
	SK_PASS = 1,
};

enum bpf_core_relo_kind {
	BPF_CORE_FIELD_BYTE_OFFSET = 0,
	BPF_CORE_FIELD_BYTE_SIZE = 1,
	BPF_CORE_FIELD_EXISTS = 2,
	BPF_CORE_FIELD_SIGNED = 3,
	BPF_CORE_FIELD_LSHIFT_U64 = 4,
	BPF_CORE_FIELD_RSHIFT_U64 = 5,
	BPF_CORE_TYPE_ID_LOCAL = 6,
	BPF_CORE_TYPE_ID_TARGET = 7,
	BPF_CORE_TYPE_EXISTS = 8,
	BPF_CORE_TYPE_SIZE = 9,
	BPF_CORE_ENUMVAL_EXISTS = 10,
	BPF_CORE_ENUMVAL_VALUE = 11,
};

struct bpf_core_relo {
	__u32 insn_off;
	__u32 type_id;
	__u32 access_str_off;
	enum bpf_core_relo_kind kind;
};

struct bpf_kfunc_desc {
	struct btf_func_model func_model;
	u32 func_id;
	s32 imm;
	u16 offset;
};

struct bpf_kfunc_desc_tab {
	struct bpf_kfunc_desc descs[256];
	u32 nr_descs;
};

struct bpf_kfunc_btf {
	struct btf *btf;
	struct module *module;
	u16 offset;
};

struct bpf_kfunc_btf_tab {
	struct bpf_kfunc_btf descs[256];
	u32 nr_descs;
};

struct bpf_struct_ops {
	const struct bpf_verifier_ops *verifier_ops;
	int (*init)(struct btf *);
	int (*check_member)(const struct btf_type *, const struct btf_member *);
	int (*init_member)(const struct btf_type *, const struct btf_member *, void *, const void *);
	int (*reg)(void *);
	void (*unreg)(void *);
	const struct btf_type *type;
	const struct btf_type *value_type;
	const char *name;
	struct btf_func_model func_models[64];
	u32 type_id;
	u32 value_id;
};

typedef u32 (*bpf_convert_ctx_access_t)(enum bpf_access_type, const struct bpf_insn *, struct bpf_insn *, struct bpf_prog *, u32 *);

struct bpf_core_ctx {
	struct bpf_verifier_log *log;
	const struct btf *btf;
};

enum bpf_stack_slot_type {
	STACK_INVALID = 0,
	STACK_SPILL = 1,
	STACK_MISC = 2,
	STACK_ZERO = 3,
};

struct bpf_verifier_stack_elem {
	struct bpf_verifier_state st;
	int insn_idx;
	int prev_insn_idx;
	struct bpf_verifier_stack_elem *next;
	u32 log_pos;
};

enum {
	BTF_SOCK_TYPE_INET = 0,
	BTF_SOCK_TYPE_INET_CONN = 1,
	BTF_SOCK_TYPE_INET_REQ = 2,
	BTF_SOCK_TYPE_INET_TW = 3,
	BTF_SOCK_TYPE_REQ = 4,
	BTF_SOCK_TYPE_SOCK = 5,
	BTF_SOCK_TYPE_SOCK_COMMON = 6,
	BTF_SOCK_TYPE_TCP = 7,
	BTF_SOCK_TYPE_TCP_REQ = 8,
	BTF_SOCK_TYPE_TCP_TW = 9,
	BTF_SOCK_TYPE_TCP6 = 10,
	BTF_SOCK_TYPE_UDP = 11,
	BTF_SOCK_TYPE_UDP6 = 12,
	BTF_SOCK_TYPE_UNIX = 13,
	MAX_BTF_SOCK_TYPE = 14,
};

typedef void (*bpf_insn_print_t)(void *, const char *, ...);

typedef const char * (*bpf_insn_revmap_call_t)(void *, const struct bpf_insn *);

typedef const char * (*bpf_insn_print_imm_t)(void *, const struct bpf_insn *, __u64);

struct bpf_insn_cbs {
	bpf_insn_print_t cb_print;
	bpf_insn_revmap_call_t cb_call;
	bpf_insn_print_imm_t cb_imm;
	void *private_data;
};

struct bpf_call_arg_meta {
	struct bpf_map *map_ptr;
	bool raw_mode;
	bool pkt_access;
	int regno;
	int access_size;
	int mem_size;
	u64 msize_max_value;
	int ref_obj_id;
	int map_uid;
	int func_id;
	struct btf *btf;
	u32 btf_id;
	struct btf *ret_btf;
	u32 ret_btf_id;
	u32 subprogno;
};

enum reg_arg_type {
	SRC_OP = 0,
	DST_OP = 1,
	DST_OP_NO_MARK = 2,
};

enum stack_access_src {
	ACCESS_DIRECT = 1,
	ACCESS_HELPER = 2,
};

struct bpf_reg_types {
	const enum bpf_reg_type types[10];
	u32 *btf_id;
};

enum {
	AT_PKT_END = 4294967295,
	BEYOND_PKT_END = 4294967294,
};

typedef int (*set_callee_state_fn)(struct bpf_verifier_env *, struct bpf_func_state *, struct bpf_func_state *, int);

enum {
	REASON_BOUNDS = 4294967295,
	REASON_TYPE = 4294967294,
	REASON_PATHS = 4294967293,
	REASON_LIMIT = 4294967292,
	REASON_STACK = 4294967291,
};

struct bpf_sanitize_info {
	struct bpf_insn_aux_data aux;
	bool mask_to_left;
};

enum {
	DISCOVERED = 16,
	EXPLORED = 32,
	FALLTHROUGH = 1,
	BRANCH = 2,
};

enum {
	DONE_EXPLORING = 0,
	KEEP_EXPLORING = 1,
};

typedef __kernel_ulong_t ino_t;

struct bpf_spin_lock {
	__u32 val;
};

struct bpf_timer {
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_pidns_info {
	__u32 pid;
	__u32 tgid;
};

typedef u64 (*btf_bpf_map_lookup_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_update_elem)(struct bpf_map *, void *, void *, u64);

typedef u64 (*btf_bpf_map_delete_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_push_elem)(struct bpf_map *, void *, u64);

typedef u64 (*btf_bpf_map_pop_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_map_peek_elem)(struct bpf_map *, void *);

typedef u64 (*btf_bpf_get_smp_processor_id)();

typedef u64 (*btf_bpf_get_numa_node_id)();

typedef u64 (*btf_bpf_ktime_get_ns)();

typedef u64 (*btf_bpf_ktime_get_boot_ns)();

typedef u64 (*btf_bpf_ktime_get_coarse_ns)();

typedef u64 (*btf_bpf_get_current_pid_tgid)();

typedef u64 (*btf_bpf_get_current_uid_gid)();

typedef u64 (*btf_bpf_get_current_comm)(char *, u32);

typedef u64 (*btf_bpf_spin_lock)(struct bpf_spin_lock *);

typedef u64 (*btf_bpf_spin_unlock)(struct bpf_spin_lock *);

typedef u64 (*btf_bpf_jiffies64)();

typedef u64 (*btf_bpf_strncmp)(const char *, u32, const char *);

typedef u64 (*btf_bpf_get_ns_current_pid_tgid)(u64, u64, struct bpf_pidns_info *, u32);

typedef u64 (*btf_bpf_event_output_data)(void *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_copy_from_user)(void *, u32, const void *);

typedef u64 (*btf_bpf_copy_from_user_task)(void *, u32, const void *, struct task_struct *, u64);

typedef u64 (*btf_bpf_per_cpu_ptr)(const void *, u32);

typedef u64 (*btf_bpf_this_cpu_ptr)(const void *);

struct bpf_bprintf_buffers {
	char tmp_bufs[1536];
};

typedef u64 (*btf_bpf_snprintf)(char *, u32, char *, const void *, u32);

struct bpf_hrtimer {
	struct hrtimer timer;
	struct bpf_map *map;
	struct bpf_prog *prog;
	void *callback_fn;
	void *value;
};

struct bpf_timer_kern {
	struct bpf_hrtimer *timer;
	struct bpf_spin_lock lock;
};

typedef u64 (*btf_bpf_timer_init)(struct bpf_timer_kern *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_timer_set_callback)(struct bpf_timer_kern *, void *, struct bpf_prog_aux *);

typedef u64 (*btf_bpf_timer_start)(struct bpf_timer_kern *, u64, u64);

typedef u64 (*btf_bpf_timer_cancel)(struct bpf_timer_kern *);

union bpf_iter_link_info {
	struct {
		__u32 map_fd;
	} map;
};

typedef int (*bpf_iter_attach_target_t)(struct bpf_prog *, union bpf_iter_link_info *, struct bpf_iter_aux_info *);

typedef void (*bpf_iter_detach_target_t)(struct bpf_iter_aux_info *);

typedef void (*bpf_iter_show_fdinfo_t)(const struct bpf_iter_aux_info *, struct seq_file *);

typedef int (*bpf_iter_fill_link_info_t)(const struct bpf_iter_aux_info *, struct bpf_link_info *);

typedef const struct bpf_func_proto * (*bpf_iter_get_func_proto_t)(enum bpf_func_id, const struct bpf_prog *);

enum bpf_iter_feature {
	BPF_ITER_RESCHED = 1,
};

struct bpf_iter_reg {
	const char *target;
	bpf_iter_attach_target_t attach_target;
	bpf_iter_detach_target_t detach_target;
	bpf_iter_show_fdinfo_t show_fdinfo;
	bpf_iter_fill_link_info_t fill_link_info;
	bpf_iter_get_func_proto_t get_func_proto;
	u32 ctx_arg_info_size;
	u32 feature;
	struct bpf_ctx_arg_aux ctx_arg_info[2];
	const struct bpf_iter_seq_info *seq_info;
};

struct bpf_iter_meta {
	union {
		struct seq_file *seq;
	};
	u64 session_id;
	u64 seq_num;
};

struct bpf_iter_target_info {
	struct list_head list;
	const struct bpf_iter_reg *reg_info;
	u32 btf_id;
};

struct bpf_iter_link {
	struct bpf_link link;
	struct bpf_iter_aux_info aux;
	struct bpf_iter_target_info *tinfo;
};

struct bpf_iter_priv_data {
	struct bpf_iter_target_info *tinfo;
	const struct bpf_iter_seq_info *seq_info;
	struct bpf_prog *prog;
	u64 session_id;
	u64 seq_num;
	bool done_stop;
	int: 24;
	u8 target_private[0];
};

typedef u64 (*btf_bpf_for_each_map_elem)(struct bpf_map *, void *, void *, u64);

typedef u64 (*btf_bpf_loop)(u32, void *, void *, u64);

struct bpf_iter_seq_map_info {
	u32 map_id;
};

struct bpf_iter__bpf_map {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
};

struct mmap_unlock_irq_work {
	struct irq_work irq_work;
	struct mm_struct *mm;
};

struct bpf_iter_seq_task_common {
	struct pid_namespace *ns;
};

struct bpf_iter_seq_task_info {
	struct bpf_iter_seq_task_common common;
	u32 tid;
};

struct bpf_iter__task {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
};

struct bpf_iter_seq_task_file_info {
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	u32 tid;
	u32 fd;
};

struct bpf_iter__task_file {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
	u32 fd;
	int: 32;
	union {
		struct file *file;
	};
};

struct bpf_iter_seq_task_vma_info {
	struct bpf_iter_seq_task_common common;
	struct task_struct *task;
	struct vm_area_struct *vma;
	u32 tid;
	long unsigned int prev_vm_start;
	long unsigned int prev_vm_end;
};

enum bpf_task_vma_iter_find_op {
	task_vma_iter_first_vma = 0,
	task_vma_iter_next_vma = 1,
	task_vma_iter_find_vma = 2,
};

struct bpf_iter__task_vma {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct task_struct *task;
	};
	union {
		struct vm_area_struct *vma;
	};
};

typedef u64 (*btf_bpf_find_vma)(struct task_struct *, u64, bpf_callback_t, void *, u64);

struct bpf_iter_seq_prog_info {
	u32 prog_id;
};

struct bpf_iter__bpf_prog {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_prog *prog;
	};
};

struct bpf_iter__bpf_map_elem {
	union {
		struct bpf_iter_meta *meta;
	};
	union {
		struct bpf_map *map;
	};
	union {
		void *key;
	};
	union {
		void *value;
	};
};

struct hlist_nulls_head {
	struct hlist_nulls_node *first;
};

struct pcpu_freelist_node;

struct pcpu_freelist_head {
	struct pcpu_freelist_node *first;
	raw_spinlock_t lock;
};

struct pcpu_freelist_node {
	struct pcpu_freelist_node *next;
};

struct pcpu_freelist {
	struct pcpu_freelist_head *freelist;
	struct pcpu_freelist_head extralist;
};

struct bpf_lru_node {
	struct list_head list;
	u16 cpu;
	u8 type;
	u8 ref;
};

struct bpf_lru_list {
	struct list_head lists[3];
	unsigned int counts[2];
	struct list_head *next_inactive_rotation;
	raw_spinlock_t lock;
};

struct bpf_lru_locallist {
	struct list_head lists[2];
	u16 next_steal;
	raw_spinlock_t lock;
};

struct bpf_common_lru {
	struct bpf_lru_list lru_list;
	struct bpf_lru_locallist *local_list;
};

typedef bool (*del_from_htab_func)(void *, struct bpf_lru_node *);

struct bpf_lru {
	union {
		struct bpf_common_lru common_lru;
		struct bpf_lru_list *percpu_lru;
	};
	del_from_htab_func del_from_htab;
	void *del_arg;
	unsigned int hash_offset;
	unsigned int nr_scans;
	bool percpu;
};

struct bucket {
	struct hlist_nulls_head head;
	union {
		raw_spinlock_t raw_lock;
		spinlock_t lock;
	};
};

struct htab_elem;

struct bpf_htab {
	struct bpf_map map;
	struct bucket *buckets;
	void *elems;
	union {
		struct pcpu_freelist freelist;
		struct bpf_lru lru;
	};
	struct htab_elem **extra_elems;
	atomic_t count;
	u32 n_buckets;
	u32 elem_size;
	u32 hashrnd;
	struct lock_class_key lockdep_key;
	int *map_locked[8];
	int: 32;
	int: 32;
};

struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct bpf_htab *htab;
				struct pcpu_freelist_node fnode;
				struct htab_elem *batch_flink;
			};
		};
	};
	union {
		struct callback_head rcu;
		struct bpf_lru_node lru_node;
	};
	u32 hash;
	char key[0];
};

struct bpf_iter_seq_hash_map_info {
	struct bpf_map *map;
	struct bpf_htab *htab;
	void *percpu_value_buf;
	u32 bucket_id;
	u32 skip_elems;
};

struct bpf_iter_seq_array_map_info {
	struct bpf_map *map;
	void *percpu_value_buf;
	u32 index;
};

struct prog_poke_elem {
	struct list_head list;
	struct bpf_prog_aux *aux;
};

enum bpf_lru_list_type {
	BPF_LRU_LIST_T_ACTIVE = 0,
	BPF_LRU_LIST_T_INACTIVE = 1,
	BPF_LRU_LIST_T_FREE = 2,
	BPF_LRU_LOCAL_LIST_T_FREE = 3,
	BPF_LRU_LOCAL_LIST_T_PENDING = 4,
};

struct bpf_lpm_trie_key {
	__u32 prefixlen;
	__u8 data[0];
};

struct lpm_trie_node {
	struct callback_head rcu;
	struct lpm_trie_node *child[2];
	u32 prefixlen;
	u32 flags;
	u8 data[0];
};

struct lpm_trie {
	struct bpf_map map;
	struct lpm_trie_node *root;
	size_t n_entries;
	size_t max_prefixlen;
	size_t data_size;
	spinlock_t lock;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_bloom_filter {
	struct bpf_map map;
	u32 bitset_mask;
	u32 hash_seed;
	u32 aligned_u32_count;
	u32 nr_hash_funcs;
	long unsigned int bitset[0];
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_queue_stack {
	struct bpf_map map;
	raw_spinlock_t lock;
	u32 head;
	u32 tail;
	u32 size;
	int: 32;
	char elements[0];
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

enum {
	BPF_RB_NO_WAKEUP = 1,
	BPF_RB_FORCE_WAKEUP = 2,
};

enum {
	BPF_RB_AVAIL_DATA = 0,
	BPF_RB_RING_SIZE = 1,
	BPF_RB_CONS_POS = 2,
	BPF_RB_PROD_POS = 3,
};

enum {
	BPF_RINGBUF_BUSY_BIT = 2147483648,
	BPF_RINGBUF_DISCARD_BIT = 1073741824,
	BPF_RINGBUF_HDR_SZ = 8,
};

struct bpf_ringbuf {
	wait_queue_head_t waitq;
	struct irq_work work;
	u64 mask;
	struct page **pages;
	int nr_pages;
	spinlock_t spinlock;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	long unsigned int consumer_pos;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	long unsigned int producer_pos;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	char data[0];
};

struct bpf_ringbuf_map {
	struct bpf_map map;
	struct bpf_ringbuf *rb;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_ringbuf_hdr {
	u32 len;
	u32 pg_off;
};

typedef u64 (*btf_bpf_ringbuf_reserve)(struct bpf_map *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_submit)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_discard)(void *, u64);

typedef u64 (*btf_bpf_ringbuf_output)(struct bpf_map *, void *, u64, u64);

typedef u64 (*btf_bpf_ringbuf_query)(struct bpf_map *, u64);

struct bpf_local_storage_elem {
	struct hlist_node map_node;
	struct hlist_node snode;
	struct bpf_local_storage *local_storage;
	struct callback_head rcu;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct bpf_local_storage_data sdata;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_local_storage_cache {
	spinlock_t idx_lock;
	u64 idx_usage_counts[16];
};

enum {
	BPF_LOCAL_STORAGE_GET_F_CREATE = 1,
	BPF_SK_STORAGE_GET_F_CREATE = 1,
};

typedef u64 (*btf_bpf_task_storage_get)(struct bpf_map *, struct task_struct *, void *, u64, gfp_t);

typedef u64 (*btf_bpf_task_storage_delete)(struct bpf_map *, struct task_struct *);

enum {
	__PERCPU_REF_ATOMIC = 1,
	__PERCPU_REF_DEAD = 2,
	__PERCPU_REF_ATOMIC_DEAD = 3,
	__PERCPU_REF_FLAG_BITS = 2,
};

struct bpf_tramp_progs {
	struct bpf_prog *progs[38];
	int nr_progs;
};

enum perf_record_ksymbol_type {
	PERF_RECORD_KSYMBOL_TYPE_UNKNOWN = 0,
	PERF_RECORD_KSYMBOL_TYPE_BPF = 1,
	PERF_RECORD_KSYMBOL_TYPE_OOL = 2,
	PERF_RECORD_KSYMBOL_TYPE_MAX = 3,
};

struct btf_enum {
	__u32 name_off;
	__s32 val;
};

struct btf_array {
	__u32 type;
	__u32 index_type;
	__u32 nelems;
};

enum {
	BTF_VAR_STATIC = 0,
	BTF_VAR_GLOBAL_ALLOCATED = 1,
	BTF_VAR_GLOBAL_EXTERN = 2,
};

struct btf_var {
	__u32 linkage;
};

struct btf_decl_tag {
	__s32 component_idx;
};

struct bpf_flow_keys {
	__u16 nhoff;
	__u16 thoff;
	__u16 addr_proto;
	__u8 is_frag;
	__u8 is_first_frag;
	__u8 is_encap;
	__u8 ip_proto;
	__be16 n_proto;
	__be16 sport;
	__be16 dport;
	union {
		struct {
			__be32 ipv4_src;
			__be32 ipv4_dst;
		};
		struct {
			__u32 ipv6_src[4];
			__u32 ipv6_dst[4];
		};
	};
	__u32 flags;
	__be32 flow_label;
};

struct bpf_sock {
	__u32 bound_dev_if;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 mark;
	__u32 priority;
	__u32 src_ip4;
	__u32 src_ip6[4];
	__u32 src_port;
	__be16 dst_port;
	__u32 dst_ip4;
	__u32 dst_ip6[4];
	__u32 state;
	__s32 rx_queue_mapping;
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	union {
		struct bpf_flow_keys *flow_keys;
	};
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	union {
		struct bpf_sock *sk;
	};
	__u32 gso_size;
	__u8 tstamp_type;
	__u64 hwtstamp;
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct sk_msg_md {
	union {
		void *data;
	};
	union {
		void *data_end;
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 size;
	union {
		struct bpf_sock *sk;
	};
};

struct sk_reuseport_md {
	union {
		void *data;
	};
	union {
		void *data_end;
	};
	__u32 len;
	__u32 eth_protocol;
	__u32 ip_protocol;
	__u32 bind_inany;
	__u32 hash;
	int: 32;
	union {
		struct bpf_sock *sk;
	};
	union {
		struct bpf_sock *migrating_sk;
	};
};

struct bpf_sock_ops {
	__u32 op;
	union {
		__u32 args[4];
		__u32 reply;
		__u32 replylong[4];
	};
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 is_fullsock;
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 bpf_sock_ops_cb_flags;
	__u32 state;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u32 sk_txhash;
	__u64 bytes_received;
	__u64 bytes_acked;
	union {
		struct bpf_sock *sk;
	};
	union {
		void *skb_data;
	};
	union {
		void *skb_data_end;
	};
	__u32 skb_len;
	__u32 skb_tcp_flags;
};

struct bpf_sk_lookup {
	union {
		union {
			struct bpf_sock *sk;
		};
		__u64 cookie;
	};
	__u32 family;
	__u32 protocol;
	__u32 remote_ip4;
	__u32 remote_ip6[4];
	__be16 remote_port;
	__u32 local_ip4;
	__u32 local_ip6[4];
	__u32 local_port;
	__u32 ingress_ifindex;
	int: 32;
};

struct sk_reuseport_kern {
	struct sk_buff *skb;
	struct sock *sk;
	struct sock *selected_sk;
	struct sock *migrating_sk;
	void *data_end;
	u32 hash;
	u32 reuseport_id;
	bool bind_inany;
};

struct btf_kfunc_id_set {
	struct module *owner;
	union {
		struct {
			struct btf_id_set *check_set;
			struct btf_id_set *acquire_set;
			struct btf_id_set *release_set;
			struct btf_id_set *ret_null_set;
		};
		struct btf_id_set *sets[4];
	};
};

struct bpf_flow_dissector {
	struct bpf_flow_keys *flow_keys;
	const struct sk_buff *skb;
	const void *data;
	const void *data_end;
};

struct inet_listen_hashbucket {
	spinlock_t lock;
	unsigned int count;
	union {
		struct hlist_head head;
		struct hlist_nulls_head nulls_head;
	};
};

struct inet_ehash_bucket;

struct inet_bind_hashbucket;

struct inet_hashinfo {
	struct inet_ehash_bucket *ehash;
	spinlock_t *ehash_locks;
	unsigned int ehash_mask;
	unsigned int ehash_locks_mask;
	struct kmem_cache *bind_bucket_cachep;
	struct inet_bind_hashbucket *bhash;
	unsigned int bhash_size;
	unsigned int lhash2_mask;
	struct inet_listen_hashbucket *lhash2;
	struct inet_listen_hashbucket listening_hash[32];
};

struct ip_ra_chain {
	struct ip_ra_chain *next;
	struct sock *sk;
	union {
		void (*destructor)(struct sock *);
		struct sock *saved_sk;
	};
	struct callback_head rcu;
};

struct inet_peer_base {
	struct rb_root rb_root;
	seqlock_t lock;
	int total;
};

struct tcp_fastopen_context {
	siphash_key_t key[2];
	int num;
	struct callback_head rcu;
};

struct bpf_sock_ops_kern {
	struct sock *sk;
	union {
		u32 args[4];
		u32 reply;
		u32 replylong[4];
	};
	struct sk_buff *syn_skb;
	struct sk_buff *skb;
	void *skb_data_end;
	u8 op;
	u8 is_fullsock;
	u8 remaining_opt_len;
	u64 temp;
};

struct bpf_sk_lookup_kern {
	u16 family;
	u16 protocol;
	__be16 sport;
	u16 dport;
	struct {
		__be32 saddr;
		__be32 daddr;
	} v4;
	struct {
		const struct in6_addr *saddr;
		const struct in6_addr *daddr;
	} v6;
	struct sock *selected_sk;
	u32 ingress_ifindex;
	bool no_reuseport;
};

struct lwtunnel_state {
	__u16 type;
	__u16 flags;
	__u16 headroom;
	atomic_t refcnt;
	int (*orig_output)(struct net *, struct sock *, struct sk_buff *);
	int (*orig_input)(struct sk_buff *);
	struct callback_head rcu;
	__u8 data[0];
};

struct sock_reuseport {
	struct callback_head rcu;
	u16 max_socks;
	u16 num_socks;
	u16 num_closed_socks;
	unsigned int synq_overflow_ts;
	unsigned int reuseport_id;
	unsigned int bind_inany: 1;
	unsigned int has_conns: 1;
	struct bpf_prog *prog;
	struct sock *socks[0];
};

struct sk_psock_progs {
	struct bpf_prog *msg_parser;
	struct bpf_prog *stream_parser;
	struct bpf_prog *stream_verdict;
	struct bpf_prog *skb_verdict;
};

struct sk_psock_work_state {
	struct sk_buff *skb;
	u32 len;
	u32 off;
};

struct sk_msg;

struct sk_psock {
	struct sock *sk;
	struct sock *sk_redir;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 eval;
	struct sk_msg *cork;
	struct sk_psock_progs progs;
	struct sk_buff_head ingress_skb;
	struct list_head ingress_msg;
	spinlock_t ingress_lock;
	long unsigned int state;
	struct list_head link;
	spinlock_t link_lock;
	refcount_t refcnt;
	void (*saved_unhash)(struct sock *);
	void (*saved_close)(struct sock *, long int);
	void (*saved_write_space)(struct sock *);
	void (*saved_data_ready)(struct sock *);
	int (*psock_update_sk_prot)(struct sock *, struct sk_psock *, bool);
	struct proto *sk_proto;
	struct mutex work_mutex;
	struct sk_psock_work_state work_state;
	struct work_struct work;
	struct rcu_work rwork;
};

enum {
	__ND_OPT_PREFIX_INFO_END = 0,
	ND_OPT_SOURCE_LL_ADDR = 1,
	ND_OPT_TARGET_LL_ADDR = 2,
	ND_OPT_PREFIX_INFO = 3,
	ND_OPT_REDIRECT_HDR = 4,
	ND_OPT_MTU = 5,
	ND_OPT_NONCE = 14,
	__ND_OPT_ARRAY_MAX = 15,
	ND_OPT_ROUTE_INFO = 24,
	ND_OPT_RDNSS = 25,
	ND_OPT_DNSSL = 31,
	ND_OPT_6CO = 34,
	ND_OPT_CAPTIVE_PORTAL = 37,
	ND_OPT_PREF64 = 38,
	__ND_OPT_MAX = 39,
};

struct inet_ehash_bucket {
	struct hlist_nulls_head chain;
};

struct inet_bind_hashbucket {
	spinlock_t lock;
	struct hlist_head chain;
};

struct ack_sample {
	u32 pkts_acked;
	s32 rtt_us;
	u32 in_flight;
};

struct rate_sample {
	u64 prior_mstamp;
	u32 prior_delivered;
	u32 prior_delivered_ce;
	s32 delivered;
	s32 delivered_ce;
	long int interval_us;
	u32 snd_interval_us;
	u32 rcv_interval_us;
	long int rtt_us;
	int losses;
	u32 acked_sacked;
	u32 prior_in_flight;
	bool is_app_limited;
	bool is_retrans;
	bool is_ack_delayed;
};

struct sk_msg_sg {
	u32 start;
	u32 curr;
	u32 end;
	u32 size;
	u32 copybreak;
	long unsigned int copy[1];
	struct scatterlist data[18];
};

struct sk_msg {
	struct sk_msg_sg sg;
	void *data;
	void *data_end;
	u32 apply_bytes;
	u32 cork_bytes;
	u32 flags;
	struct sk_buff *skb;
	struct sock *sk_redir;
	struct sock *sk;
	struct list_head list;
};

struct bpf_core_cand {
	const struct btf *btf;
	__u32 id;
};

struct bpf_core_cand_list {
	struct bpf_core_cand *cands;
	int len;
};

struct bpf_core_accessor {
	__u32 type_id;
	__u32 idx;
	const char *name;
};

struct bpf_core_spec {
	const struct btf *btf;
	struct bpf_core_accessor spec[64];
	__u32 root_type_id;
	enum bpf_core_relo_kind relo_kind;
	int len;
	int raw_spec[64];
	int raw_len;
	__u32 bit_offset;
};

struct bpf_core_relo_res {
	__u32 orig_val;
	__u32 new_val;
	bool poison;
	bool validate;
	bool fail_memsz_adjust;
	__u32 orig_sz;
	__u32 orig_type_id;
	__u32 new_sz;
	__u32 new_type_id;
};

enum btf_kfunc_hook {
	BTF_KFUNC_HOOK_XDP = 0,
	BTF_KFUNC_HOOK_TC = 1,
	BTF_KFUNC_HOOK_STRUCT_OPS = 2,
	BTF_KFUNC_HOOK_MAX = 3,
};

enum {
	BTF_KFUNC_SET_MAX_CNT = 32,
};

struct btf_kfunc_set_tab {
	struct btf_id_set *sets[12];
};

enum verifier_phase {
	CHECK_META = 0,
	CHECK_TYPE = 1,
};

struct resolve_vertex {
	const struct btf_type *t;
	u32 type_id;
	u16 next_member;
};

enum visit_state {
	NOT_VISITED = 0,
	VISITED = 1,
	RESOLVED = 2,
};

enum resolve_mode {
	RESOLVE_TBD = 0,
	RESOLVE_PTR = 1,
	RESOLVE_STRUCT_OR_ARRAY = 2,
};

struct btf_sec_info {
	u32 off;
	u32 len;
};

struct btf_verifier_env {
	struct btf *btf;
	u8 *visit_states;
	struct resolve_vertex stack[32];
	struct bpf_verifier_log log;
	u32 log_type_id;
	u32 top_stack;
	enum verifier_phase phase;
	enum resolve_mode resolve_mode;
};

struct btf_show {
	u64 flags;
	void *target;
	void (*showfn)(struct btf_show *, const char *, va_list);
	const struct btf *btf;
	struct {
		u8 depth;
		u8 depth_to_show;
		u8 depth_check;
		u8 array_member: 1;
		u8 array_terminated: 1;
		u16 array_encoding;
		u32 type_id;
		int status;
		const struct btf_type *type;
		const struct btf_member *member;
		char name[80];
	} state;
	struct {
		u32 size;
		void *head;
		void *data;
		u8 safe[32];
	} obj;
};

struct btf_kind_operations {
	s32 (*check_meta)(struct btf_verifier_env *, const struct btf_type *, u32);
	int (*resolve)(struct btf_verifier_env *, const struct resolve_vertex *);
	int (*check_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	int (*check_kflag_member)(struct btf_verifier_env *, const struct btf_type *, const struct btf_member *, const struct btf_type *);
	void (*log_details)(struct btf_verifier_env *, const struct btf_type *);
	void (*show)(const struct btf *, const struct btf_type *, u32, void *, u8, struct btf_show *);
};

struct bpf_ctx_convert {
	struct __sk_buff BPF_PROG_TYPE_SOCKET_FILTER_prog;
	struct sk_buff BPF_PROG_TYPE_SOCKET_FILTER_kern;
	struct __sk_buff BPF_PROG_TYPE_SCHED_CLS_prog;
	struct sk_buff BPF_PROG_TYPE_SCHED_CLS_kern;
	struct __sk_buff BPF_PROG_TYPE_SCHED_ACT_prog;
	struct sk_buff BPF_PROG_TYPE_SCHED_ACT_kern;
	struct xdp_md BPF_PROG_TYPE_XDP_prog;
	struct xdp_buff BPF_PROG_TYPE_XDP_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_IN_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_IN_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_OUT_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_OUT_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_XMIT_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_XMIT_kern;
	struct __sk_buff BPF_PROG_TYPE_LWT_SEG6LOCAL_prog;
	struct sk_buff BPF_PROG_TYPE_LWT_SEG6LOCAL_kern;
	struct bpf_sock_ops BPF_PROG_TYPE_SOCK_OPS_prog;
	struct bpf_sock_ops_kern BPF_PROG_TYPE_SOCK_OPS_kern;
	int: 32;
	struct __sk_buff BPF_PROG_TYPE_SK_SKB_prog;
	struct sk_buff BPF_PROG_TYPE_SK_SKB_kern;
	struct sk_msg_md BPF_PROG_TYPE_SK_MSG_prog;
	struct sk_msg BPF_PROG_TYPE_SK_MSG_kern;
	struct __sk_buff BPF_PROG_TYPE_FLOW_DISSECTOR_prog;
	struct bpf_flow_dissector BPF_PROG_TYPE_FLOW_DISSECTOR_kern;
	bpf_user_pt_regs_t BPF_PROG_TYPE_KPROBE_prog;
	struct pt_regs BPF_PROG_TYPE_KPROBE_kern;
	__u64 BPF_PROG_TYPE_TRACEPOINT_prog;
	u64 BPF_PROG_TYPE_TRACEPOINT_kern;
	struct bpf_perf_event_data BPF_PROG_TYPE_PERF_EVENT_prog;
	struct bpf_perf_event_data_kern BPF_PROG_TYPE_PERF_EVENT_kern;
	struct bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_prog;
	u64 BPF_PROG_TYPE_RAW_TRACEPOINT_kern;
	struct bpf_raw_tracepoint_args BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_prog;
	u64 BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE_kern;
	void *BPF_PROG_TYPE_TRACING_prog;
	void *BPF_PROG_TYPE_TRACING_kern;
	int: 32;
	struct sk_reuseport_md BPF_PROG_TYPE_SK_REUSEPORT_prog;
	struct sk_reuseport_kern BPF_PROG_TYPE_SK_REUSEPORT_kern;
	struct bpf_sk_lookup BPF_PROG_TYPE_SK_LOOKUP_prog;
	struct bpf_sk_lookup_kern BPF_PROG_TYPE_SK_LOOKUP_kern;
	void *BPF_PROG_TYPE_STRUCT_OPS_prog;
	void *BPF_PROG_TYPE_STRUCT_OPS_kern;
	void *BPF_PROG_TYPE_EXT_prog;
	void *BPF_PROG_TYPE_EXT_kern;
	void *BPF_PROG_TYPE_SYSCALL_prog;
	void *BPF_PROG_TYPE_SYSCALL_kern;
	int: 32;
};

enum {
	__ctx_convertBPF_PROG_TYPE_SOCKET_FILTER = 0,
	__ctx_convertBPF_PROG_TYPE_SCHED_CLS = 1,
	__ctx_convertBPF_PROG_TYPE_SCHED_ACT = 2,
	__ctx_convertBPF_PROG_TYPE_XDP = 3,
	__ctx_convertBPF_PROG_TYPE_LWT_IN = 4,
	__ctx_convertBPF_PROG_TYPE_LWT_OUT = 5,
	__ctx_convertBPF_PROG_TYPE_LWT_XMIT = 6,
	__ctx_convertBPF_PROG_TYPE_LWT_SEG6LOCAL = 7,
	__ctx_convertBPF_PROG_TYPE_SOCK_OPS = 8,
	__ctx_convertBPF_PROG_TYPE_SK_SKB = 9,
	__ctx_convertBPF_PROG_TYPE_SK_MSG = 10,
	__ctx_convertBPF_PROG_TYPE_FLOW_DISSECTOR = 11,
	__ctx_convertBPF_PROG_TYPE_KPROBE = 12,
	__ctx_convertBPF_PROG_TYPE_TRACEPOINT = 13,
	__ctx_convertBPF_PROG_TYPE_PERF_EVENT = 14,
	__ctx_convertBPF_PROG_TYPE_RAW_TRACEPOINT = 15,
	__ctx_convertBPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE = 16,
	__ctx_convertBPF_PROG_TYPE_TRACING = 17,
	__ctx_convertBPF_PROG_TYPE_SK_REUSEPORT = 18,
	__ctx_convertBPF_PROG_TYPE_SK_LOOKUP = 19,
	__ctx_convertBPF_PROG_TYPE_STRUCT_OPS = 20,
	__ctx_convertBPF_PROG_TYPE_EXT = 21,
	__ctx_convertBPF_PROG_TYPE_SYSCALL = 22,
	__ctx_convert_unused = 23,
};

enum bpf_struct_walk_result {
	WALK_SCALAR = 0,
	WALK_PTR = 1,
	WALK_STRUCT = 2,
};

struct btf_show_snprintf {
	struct btf_show show;
	int len_left;
	int len;
};

enum {
	BTF_MODULE_F_LIVE = 1,
};

struct btf_module {
	struct list_head list;
	struct module *module;
	struct btf *btf;
	struct bin_attribute *sysfs_attr;
	int flags;
};

typedef u64 (*btf_bpf_btf_find_by_name_kind)(char *, int, u32, int);

struct bpf_cand_cache {
	const char *name;
	u32 name_len;
	u16 kind;
	u16 cnt;
	struct {
		const struct btf *btf;
		u32 id;
	} cands[0];
};

struct bpf_dispatcher_prog {
	struct bpf_prog *prog;
	refcount_t users;
};

struct bpf_dispatcher {
	struct mutex mutex;
	void *func;
	struct bpf_dispatcher_prog progs[48];
	int num_progs;
	void *image;
	u32 image_off;
	struct bpf_ksym ksym;
};

enum {
	BPF_F_BROADCAST = 8,
	BPF_F_EXCLUDE_INGRESS = 16,
};

struct bpf_devmap_val {
	__u32 ifindex;
	union {
		int fd;
		__u32 id;
	} bpf_prog;
};

enum skb_drop_reason {
	SKB_NOT_DROPPED_YET = 0,
	SKB_DROP_REASON_NOT_SPECIFIED = 1,
	SKB_DROP_REASON_NO_SOCKET = 2,
	SKB_DROP_REASON_PKT_TOO_SMALL = 3,
	SKB_DROP_REASON_TCP_CSUM = 4,
	SKB_DROP_REASON_SOCKET_FILTER = 5,
	SKB_DROP_REASON_UDP_CSUM = 6,
	SKB_DROP_REASON_NETFILTER_DROP = 7,
	SKB_DROP_REASON_OTHERHOST = 8,
	SKB_DROP_REASON_IP_CSUM = 9,
	SKB_DROP_REASON_IP_INHDR = 10,
	SKB_DROP_REASON_IP_RPFILTER = 11,
	SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST = 12,
	SKB_DROP_REASON_XFRM_POLICY = 13,
	SKB_DROP_REASON_IP_NOPROTO = 14,
	SKB_DROP_REASON_SOCKET_RCVBUFF = 15,
	SKB_DROP_REASON_PROTO_MEM = 16,
	SKB_DROP_REASON_TCP_MD5NOTFOUND = 17,
	SKB_DROP_REASON_TCP_MD5UNEXPECTED = 18,
	SKB_DROP_REASON_TCP_MD5FAILURE = 19,
	SKB_DROP_REASON_SOCKET_BACKLOG = 20,
	SKB_DROP_REASON_TCP_FLAGS = 21,
	SKB_DROP_REASON_TCP_ZEROWINDOW = 22,
	SKB_DROP_REASON_TCP_OLD_DATA = 23,
	SKB_DROP_REASON_TCP_OVERWINDOW = 24,
	SKB_DROP_REASON_TCP_OFOMERGE = 25,
	SKB_DROP_REASON_IP_OUTNOROUTES = 26,
	SKB_DROP_REASON_BPF_CGROUP_EGRESS = 27,
	SKB_DROP_REASON_IPV6DISABLED = 28,
	SKB_DROP_REASON_NEIGH_CREATEFAIL = 29,
	SKB_DROP_REASON_NEIGH_FAILED = 30,
	SKB_DROP_REASON_NEIGH_QUEUEFULL = 31,
	SKB_DROP_REASON_NEIGH_DEAD = 32,
	SKB_DROP_REASON_TC_EGRESS = 33,
	SKB_DROP_REASON_QDISC_DROP = 34,
	SKB_DROP_REASON_CPU_BACKLOG = 35,
	SKB_DROP_REASON_XDP = 36,
	SKB_DROP_REASON_TC_INGRESS = 37,
	SKB_DROP_REASON_PTYPE_ABSENT = 38,
	SKB_DROP_REASON_SKB_CSUM = 39,
	SKB_DROP_REASON_SKB_GSO_SEG = 40,
	SKB_DROP_REASON_SKB_UCOPY_FAULT = 41,
	SKB_DROP_REASON_DEV_HDR = 42,
	SKB_DROP_REASON_DEV_READY = 43,
	SKB_DROP_REASON_FULL_RING = 44,
	SKB_DROP_REASON_NOMEM = 45,
	SKB_DROP_REASON_HDR_TRUNC = 46,
	SKB_DROP_REASON_TAP_FILTER = 47,
	SKB_DROP_REASON_TAP_TXFILTER = 48,
	SKB_DROP_REASON_MAX = 49,
};

enum net_device_flags {
	IFF_UP = 1,
	IFF_BROADCAST = 2,
	IFF_DEBUG = 4,
	IFF_LOOPBACK = 8,
	IFF_POINTOPOINT = 16,
	IFF_NOTRAILERS = 32,
	IFF_RUNNING = 64,
	IFF_NOARP = 128,
	IFF_PROMISC = 256,
	IFF_ALLMULTI = 512,
	IFF_MASTER = 1024,
	IFF_SLAVE = 2048,
	IFF_MULTICAST = 4096,
	IFF_PORTSEL = 8192,
	IFF_AUTOMEDIA = 16384,
	IFF_DYNAMIC = 32768,
	IFF_LOWER_UP = 65536,
	IFF_DORMANT = 131072,
	IFF_ECHO = 262144,
};

enum netdev_priv_flags {
	IFF_802_1Q_VLAN = 1,
	IFF_EBRIDGE = 2,
	IFF_BONDING = 4,
	IFF_ISATAP = 8,
	IFF_WAN_HDLC = 16,
	IFF_XMIT_DST_RELEASE = 32,
	IFF_DONT_BRIDGE = 64,
	IFF_DISABLE_NETPOLL = 128,
	IFF_MACVLAN_PORT = 256,
	IFF_BRIDGE_PORT = 512,
	IFF_OVS_DATAPATH = 1024,
	IFF_TX_SKB_SHARING = 2048,
	IFF_UNICAST_FLT = 4096,
	IFF_TEAM_PORT = 8192,
	IFF_SUPP_NOFCS = 16384,
	IFF_LIVE_ADDR_CHANGE = 32768,
	IFF_MACVLAN = 65536,
	IFF_XMIT_DST_RELEASE_PERM = 131072,
	IFF_L3MDEV_MASTER = 262144,
	IFF_NO_QUEUE = 524288,
	IFF_OPENVSWITCH = 1048576,
	IFF_L3MDEV_SLAVE = 2097152,
	IFF_TEAM = 4194304,
	IFF_RXFH_CONFIGURED = 8388608,
	IFF_PHONY_HEADROOM = 16777216,
	IFF_MACSEC = 33554432,
	IFF_NO_RX_HANDLER = 67108864,
	IFF_FAILOVER = 134217728,
	IFF_FAILOVER_SLAVE = 268435456,
	IFF_L3MDEV_RX_HANDLER = 536870912,
	IFF_LIVE_RENAME_OK = 1073741824,
	IFF_TX_SKB_NO_LINEAR = 2147483648,
	IFF_CHANGE_PROTO_DOWN = 0,
};

struct xdp_dev_bulk_queue {
	struct xdp_frame *q[16];
	struct list_head flush_node;
	struct net_device *dev;
	struct net_device *dev_rx;
	struct bpf_prog *xdp_prog;
	unsigned int count;
};

enum netdev_cmd {
	NETDEV_UP = 1,
	NETDEV_DOWN = 2,
	NETDEV_REBOOT = 3,
	NETDEV_CHANGE = 4,
	NETDEV_REGISTER = 5,
	NETDEV_UNREGISTER = 6,
	NETDEV_CHANGEMTU = 7,
	NETDEV_CHANGEADDR = 8,
	NETDEV_PRE_CHANGEADDR = 9,
	NETDEV_GOING_DOWN = 10,
	NETDEV_CHANGENAME = 11,
	NETDEV_FEAT_CHANGE = 12,
	NETDEV_BONDING_FAILOVER = 13,
	NETDEV_PRE_UP = 14,
	NETDEV_PRE_TYPE_CHANGE = 15,
	NETDEV_POST_TYPE_CHANGE = 16,
	NETDEV_POST_INIT = 17,
	NETDEV_RELEASE = 18,
	NETDEV_NOTIFY_PEERS = 19,
	NETDEV_JOIN = 20,
	NETDEV_CHANGEUPPER = 21,
	NETDEV_RESEND_IGMP = 22,
	NETDEV_PRECHANGEMTU = 23,
	NETDEV_CHANGEINFODATA = 24,
	NETDEV_BONDING_INFO = 25,
	NETDEV_PRECHANGEUPPER = 26,
	NETDEV_CHANGELOWERSTATE = 27,
	NETDEV_UDP_TUNNEL_PUSH_INFO = 28,
	NETDEV_UDP_TUNNEL_DROP_INFO = 29,
	NETDEV_CHANGE_TX_QUEUE_LEN = 30,
	NETDEV_CVLAN_FILTER_PUSH_INFO = 31,
	NETDEV_CVLAN_FILTER_DROP_INFO = 32,
	NETDEV_SVLAN_FILTER_PUSH_INFO = 33,
	NETDEV_SVLAN_FILTER_DROP_INFO = 34,
	NETDEV_OFFLOAD_XSTATS_ENABLE = 35,
	NETDEV_OFFLOAD_XSTATS_DISABLE = 36,
	NETDEV_OFFLOAD_XSTATS_REPORT_USED = 37,
	NETDEV_OFFLOAD_XSTATS_REPORT_DELTA = 38,
};

struct netdev_notifier_info {
	struct net_device *dev;
	struct netlink_ext_ack *extack;
};

struct bpf_nh_params {
	u32 nh_family;
	union {
		u32 ipv4_nh;
		struct in6_addr ipv6_nh;
	};
};

struct bpf_redirect_info {
	u32 flags;
	u32 tgt_index;
	void *tgt_value;
	struct bpf_map *map;
	u32 map_id;
	enum bpf_map_type map_type;
	u32 kern_flags;
	struct bpf_nh_params nh;
};

struct bpf_dtab;

struct bpf_dtab_netdev {
	struct net_device *dev;
	struct hlist_node index_hlist;
	struct bpf_dtab *dtab;
	struct bpf_prog *xdp_prog;
	struct callback_head rcu;
	unsigned int idx;
	struct bpf_devmap_val val;
};

struct bpf_dtab {
	struct bpf_map map;
	struct bpf_dtab_netdev **netdev_map;
	struct list_head list;
	struct hlist_head *dev_index_head;
	spinlock_t index_lock;
	unsigned int items;
	u32 n_buckets;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_cpumap_val {
	__u32 qsize;
	union {
		int fd;
		__u32 id;
	} bpf_prog;
};

struct bpf_cpu_map_entry;

struct xdp_bulk_queue {
	void *q[8];
	struct list_head flush_node;
	struct bpf_cpu_map_entry *obj;
	unsigned int count;
};

struct bpf_cpu_map;

struct bpf_cpu_map_entry {
	u32 cpu;
	int map_id;
	struct xdp_bulk_queue *bulkq;
	struct bpf_cpu_map *cmap;
	struct ptr_ring *queue;
	struct task_struct *kthread;
	struct bpf_cpumap_val value;
	struct bpf_prog *prog;
	atomic_t refcnt;
	struct callback_head rcu;
	struct work_struct kthread_stop_wq;
};

struct bpf_cpu_map {
	struct bpf_map map;
	struct bpf_cpu_map_entry **cpu_map;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct rhlist_head {
	struct rhash_head rhead;
	struct rhlist_head *next;
};

struct bpf_prog_offload_ops {
	int (*insn_hook)(struct bpf_verifier_env *, int, int);
	int (*finalize)(struct bpf_verifier_env *);
	int (*replace_insn)(struct bpf_verifier_env *, u32, struct bpf_insn *);
	int (*remove_insns)(struct bpf_verifier_env *, u32, u32);
	int (*prepare)(struct bpf_prog *);
	int (*translate)(struct bpf_prog *);
	void (*destroy)(struct bpf_prog *);
};

struct bpf_offload_dev {
	const struct bpf_prog_offload_ops *ops;
	struct list_head netdevs;
	void *priv;
};

typedef struct ns_common *ns_get_path_helper_t(void *);

struct bpf_offload_netdev {
	struct rhash_head l;
	struct net_device *netdev;
	struct bpf_offload_dev *offdev;
	struct list_head progs;
	struct list_head maps;
	struct list_head offdev_netdevs;
};

struct ns_get_path_bpf_prog_args {
	struct bpf_prog *prog;
	struct bpf_prog_info *info;
};

struct ns_get_path_bpf_map_args {
	struct bpf_offloaded_map *offmap;
	struct bpf_map_info *info;
};

struct pernet_operations {
	struct list_head list;
	int (*init)(struct net *);
	void (*pre_exit)(struct net *);
	void (*exit)(struct net *);
	void (*exit_batch)(struct list_head *);
	unsigned int *id;
	size_t size;
};

struct bpf_netns_link {
	struct bpf_link link;
	enum bpf_attach_type type;
	enum netns_bpf_attach_type netns_type;
	struct net *net;
	struct list_head node;
	int: 32;
};

enum bpf_stack_build_id_status {
	BPF_STACK_BUILD_ID_EMPTY = 0,
	BPF_STACK_BUILD_ID_VALID = 1,
	BPF_STACK_BUILD_ID_IP = 2,
};

struct bpf_stack_build_id {
	__s32 status;
	unsigned char build_id[20];
	union {
		__u64 offset;
		__u64 ip;
	};
};

enum {
	BPF_F_SKIP_FIELD_MASK = 255,
	BPF_F_USER_STACK = 256,
	BPF_F_FAST_STACK_CMP = 512,
	BPF_F_REUSE_STACKID = 1024,
	BPF_F_USER_BUILD_ID = 2048,
};

enum perf_callchain_context {
	PERF_CONTEXT_HV = 4294967264,
	PERF_CONTEXT_KERNEL = 4294967168,
	PERF_CONTEXT_USER = 4294966784,
	PERF_CONTEXT_GUEST = 4294965248,
	PERF_CONTEXT_GUEST_KERNEL = 4294965120,
	PERF_CONTEXT_GUEST_USER = 4294964736,
	PERF_CONTEXT_MAX = 4294963201,
};

struct stack_map_bucket {
	struct pcpu_freelist_node fnode;
	u32 hash;
	u32 nr;
	u64 data[0];
};

struct bpf_stack_map {
	struct bpf_map map;
	void *elems;
	struct pcpu_freelist freelist;
	u32 n_buckets;
	struct stack_map_bucket *buckets[0];
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

typedef u64 (*btf_bpf_get_stackid)(struct pt_regs *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stackid_pe)(struct bpf_perf_event_data_kern *, struct bpf_map *, u64);

typedef u64 (*btf_bpf_get_stack)(struct pt_regs *, void *, u32, u64);

typedef u64 (*btf_bpf_get_task_stack)(struct task_struct *, void *, u32, u64);

typedef u64 (*btf_bpf_get_stack_pe)(struct bpf_perf_event_data_kern *, void *, u32, u64);

enum sock_type {
	SOCK_STREAM = 1,
	SOCK_DGRAM = 2,
	SOCK_RAW = 3,
	SOCK_RDM = 4,
	SOCK_SEQPACKET = 5,
	SOCK_DCCP = 6,
	SOCK_PACKET = 10,
};

enum sock_flags {
	SOCK_DEAD = 0,
	SOCK_DONE = 1,
	SOCK_URGINLINE = 2,
	SOCK_KEEPOPEN = 3,
	SOCK_LINGER = 4,
	SOCK_DESTROY = 5,
	SOCK_BROADCAST = 6,
	SOCK_TIMESTAMP = 7,
	SOCK_ZAPPED = 8,
	SOCK_USE_WRITE_QUEUE = 9,
	SOCK_DBG = 10,
	SOCK_RCVTSTAMP = 11,
	SOCK_RCVTSTAMPNS = 12,
	SOCK_LOCALROUTE = 13,
	SOCK_MEMALLOC = 14,
	SOCK_TIMESTAMPING_RX_SOFTWARE = 15,
	SOCK_FASYNC = 16,
	SOCK_RXQ_OVFL = 17,
	SOCK_ZEROCOPY = 18,
	SOCK_WIFI_STATUS = 19,
	SOCK_NOFCS = 20,
	SOCK_FILTER_LOCKED = 21,
	SOCK_SELECT_ERR_QUEUE = 22,
	SOCK_RCU_FREE = 23,
	SOCK_TXTIME = 24,
	SOCK_XDP = 25,
	SOCK_TSTAMP_NEW = 26,
};

struct reuseport_array {
	struct bpf_map map;
	struct sock *ptrs[0];
};

enum libbpf_print_level {
	LIBBPF_WARN = 0,
	LIBBPF_INFO = 1,
	LIBBPF_DEBUG = 2,
};

struct bpf_dummy_ops_state {
	int val;
};

struct bpf_dummy_ops {
	int (*test_1)(struct bpf_dummy_ops_state *);
	int (*test_2)(struct bpf_dummy_ops_state *, int, short unsigned int, char, long unsigned int);
};

enum bpf_struct_ops_state {
	BPF_STRUCT_OPS_STATE_INIT = 0,
	BPF_STRUCT_OPS_STATE_INUSE = 1,
	BPF_STRUCT_OPS_STATE_TOBEFREE = 2,
};

struct bpf_struct_ops_value {
	refcount_t refcnt;
	enum bpf_struct_ops_state state;
	char data[0];
};

struct bpf_struct_ops_map {
	struct bpf_map map;
	struct callback_head rcu;
	const struct bpf_struct_ops *st_ops;
	struct mutex lock;
	struct bpf_prog **progs;
	void *image;
	struct bpf_struct_ops_value *uvalue;
	struct bpf_struct_ops_value kvalue;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct bpf_struct_ops_bpf_dummy_ops {
	refcount_t refcnt;
	enum bpf_struct_ops_state state;
	struct bpf_dummy_ops data;
};

struct bpf_struct_ops_tcp_congestion_ops {
	refcount_t refcnt;
	enum bpf_struct_ops_state state;
	struct tcp_congestion_ops data;
};

enum {
	BPF_STRUCT_OPS_TYPE_bpf_dummy_ops = 0,
	BPF_STRUCT_OPS_TYPE_tcp_congestion_ops = 1,
	__NR_BPF_STRUCT_OPS_TYPE = 2,
};

struct perf_event_mmap_page {
	__u32 version;
	__u32 compat_version;
	__u32 lock;
	__u32 index;
	__s64 offset;
	__u64 time_enabled;
	__u64 time_running;
	union {
		__u64 capabilities;
		struct {
			__u64 cap_bit0: 1;
			__u64 cap_bit0_is_deprecated: 1;
			__u64 cap_user_rdpmc: 1;
			__u64 cap_user_time: 1;
			__u64 cap_user_time_zero: 1;
			__u64 cap_user_time_short: 1;
			__u64 cap_____res: 58;
		};
	};
	__u16 pmc_width;
	__u16 time_shift;
	__u32 time_mult;
	__u64 time_offset;
	__u64 time_zero;
	__u32 size;
	__u32 __reserved_1;
	__u64 time_cycles;
	__u64 time_mask;
	__u8 __reserved[928];
	__u64 data_head;
	__u64 data_tail;
	__u64 data_offset;
	__u64 data_size;
	__u64 aux_head;
	__u64 aux_tail;
	__u64 aux_offset;
	__u64 aux_size;
};

struct perf_event_header {
	__u32 type;
	__u16 misc;
	__u16 size;
};

enum perf_event_type {
	PERF_RECORD_MMAP = 1,
	PERF_RECORD_LOST = 2,
	PERF_RECORD_COMM = 3,
	PERF_RECORD_EXIT = 4,
	PERF_RECORD_THROTTLE = 5,
	PERF_RECORD_UNTHROTTLE = 6,
	PERF_RECORD_FORK = 7,
	PERF_RECORD_READ = 8,
	PERF_RECORD_SAMPLE = 9,
	PERF_RECORD_MMAP2 = 10,
	PERF_RECORD_AUX = 11,
	PERF_RECORD_ITRACE_START = 12,
	PERF_RECORD_LOST_SAMPLES = 13,
	PERF_RECORD_SWITCH = 14,
	PERF_RECORD_SWITCH_CPU_WIDE = 15,
	PERF_RECORD_NAMESPACES = 16,
	PERF_RECORD_KSYMBOL = 17,
	PERF_RECORD_BPF_EVENT = 18,
	PERF_RECORD_CGROUP = 19,
	PERF_RECORD_TEXT_POKE = 20,
	PERF_RECORD_AUX_OUTPUT_HW_ID = 21,
	PERF_RECORD_MAX = 22,
};

struct perf_buffer {
	refcount_t refcount;
	struct callback_head callback_head;
	struct work_struct work;
	int page_order;
	int nr_pages;
	int overwrite;
	int paused;
	atomic_t poll;
	local_t head;
	unsigned int nest;
	local_t events;
	local_t wakeup;
	local_t lost;
	long int watermark;
	long int aux_watermark;
	spinlock_t event_lock;
	struct list_head event_list;
	atomic_t mmap_count;
	long unsigned int mmap_locked;
	struct user_struct *mmap_user;
	long int aux_head;
	unsigned int aux_nest;
	long int aux_wakeup;
	long unsigned int aux_pgoff;
	int aux_nr_pages;
	int aux_overwrite;
	atomic_t aux_mmap_count;
	long unsigned int aux_mmap_locked;
	void (*free_aux)(void *);
	refcount_t aux_refcount;
	int aux_in_sampling;
	void **aux_pages;
	void *aux_priv;
	struct perf_event_mmap_page *user_page;
	void *data_pages[0];
};

struct callchain_cpus_entries {
	struct callback_head callback_head;
	struct perf_callchain_entry *cpu_entries[0];
};

enum perf_branch_sample_type {
	PERF_SAMPLE_BRANCH_USER = 1,
	PERF_SAMPLE_BRANCH_KERNEL = 2,
	PERF_SAMPLE_BRANCH_HV = 4,
	PERF_SAMPLE_BRANCH_ANY = 8,
	PERF_SAMPLE_BRANCH_ANY_CALL = 16,
	PERF_SAMPLE_BRANCH_ANY_RETURN = 32,
	PERF_SAMPLE_BRANCH_IND_CALL = 64,
	PERF_SAMPLE_BRANCH_ABORT_TX = 128,
	PERF_SAMPLE_BRANCH_IN_TX = 256,
	PERF_SAMPLE_BRANCH_NO_TX = 512,
	PERF_SAMPLE_BRANCH_COND = 1024,
	PERF_SAMPLE_BRANCH_CALL_STACK = 2048,
	PERF_SAMPLE_BRANCH_IND_JUMP = 4096,
	PERF_SAMPLE_BRANCH_CALL = 8192,
	PERF_SAMPLE_BRANCH_NO_FLAGS = 16384,
	PERF_SAMPLE_BRANCH_NO_CYCLES = 32768,
	PERF_SAMPLE_BRANCH_TYPE_SAVE = 65536,
	PERF_SAMPLE_BRANCH_HW_INDEX = 131072,
	PERF_SAMPLE_BRANCH_MAX = 262144,
};

enum perf_sample_regs_abi {
	PERF_SAMPLE_REGS_ABI_NONE = 0,
	PERF_SAMPLE_REGS_ABI_32 = 1,
	PERF_SAMPLE_REGS_ABI_64 = 2,
};

enum perf_event_read_format {
	PERF_FORMAT_TOTAL_TIME_ENABLED = 1,
	PERF_FORMAT_TOTAL_TIME_RUNNING = 2,
	PERF_FORMAT_ID = 4,
	PERF_FORMAT_GROUP = 8,
	PERF_FORMAT_MAX = 16,
};

enum perf_event_ioc_flags {
	PERF_IOC_FLAG_GROUP = 1,
};

struct perf_ns_link_info {
	__u64 dev;
	__u64 ino;
};

enum {
	NET_NS_INDEX = 0,
	UTS_NS_INDEX = 1,
	IPC_NS_INDEX = 2,
	PID_NS_INDEX = 3,
	USER_NS_INDEX = 4,
	MNT_NS_INDEX = 5,
	CGROUP_NS_INDEX = 6,
	NR_NAMESPACES = 7,
};

enum perf_addr_filter_action_t {
	PERF_ADDR_FILTER_ACTION_STOP = 0,
	PERF_ADDR_FILTER_ACTION_START = 1,
	PERF_ADDR_FILTER_ACTION_FILTER = 2,
};

struct perf_addr_filter {
	struct list_head entry;
	struct path path;
	long unsigned int offset;
	long unsigned int size;
	enum perf_addr_filter_action_t action;
};

struct swevent_hlist {
	struct hlist_head heads[256];
	struct callback_head callback_head;
};

struct pmu_event_list {
	raw_spinlock_t lock;
	struct list_head list;
};

struct match_token {
	int token;
	const char *pattern;
};

enum {
	MAX_OPT_ARGS = 3,
};

typedef struct {
	char *from;
	char *to;
} substring_t;

struct min_heap {
	void *data;
	int nr;
	int size;
};

struct min_heap_callbacks {
	int elem_size;
	bool (*less)(const void *, const void *);
	void (*swp)(void *, void *);
};

typedef int (*remote_function_f)(void *);

struct remote_function_call {
	struct task_struct *p;
	remote_function_f func;
	void *info;
	int ret;
};

typedef void (*event_f)(struct perf_event *, struct perf_cpu_context *, struct perf_event_context *, void *);

struct event_function_struct {
	struct perf_event *event;
	event_f func;
	void *data;
};

enum event_type_t {
	EVENT_FLEXIBLE = 1,
	EVENT_PINNED = 2,
	EVENT_TIME = 4,
	EVENT_CPU = 8,
	EVENT_ALL = 3,
};

struct __group_key {
	int cpu;
	struct cgroup *cgroup;
};

struct stop_event_data {
	struct perf_event *event;
	unsigned int restart;
};

struct perf_read_data {
	struct perf_event *event;
	bool group;
	int ret;
};

struct perf_read_event {
	struct perf_event_header header;
	u32 pid;
	u32 tid;
};

typedef void perf_iterate_f(struct perf_event *, void *);

struct remote_output {
	struct perf_buffer *rb;
	int err;
};

struct perf_task_event {
	struct task_struct *task;
	struct perf_event_context *task_ctx;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 ppid;
		u32 tid;
		u32 ptid;
		u64 time;
	} event_id;
};

struct perf_comm_event {
	struct task_struct *task;
	char *comm;
	int comm_size;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
	} event_id;
};

struct perf_namespaces_event {
	struct task_struct *task;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
		u64 nr_namespaces;
		struct perf_ns_link_info link_info[7];
	} event_id;
};

struct perf_mmap_event {
	struct vm_area_struct *vma;
	const char *file_name;
	int file_size;
	int maj;
	int min;
	u64 ino;
	u64 ino_generation;
	u32 prot;
	u32 flags;
	u8 build_id[20];
	u32 build_id_size;
	struct {
		struct perf_event_header header;
		u32 pid;
		u32 tid;
		u64 start;
		u64 len;
		u64 pgoff;
	} event_id;
};

struct perf_switch_event {
	struct task_struct *task;
	struct task_struct *next_prev;
	struct {
		struct perf_event_header header;
		u32 next_prev_pid;
		u32 next_prev_tid;
	} event_id;
};

struct perf_ksymbol_event {
	const char *name;
	int name_len;
	struct {
		struct perf_event_header header;
		u64 addr;
		u32 len;
		u16 ksym_type;
		u16 flags;
	} event_id;
};

struct perf_bpf_event {
	struct bpf_prog *prog;
	struct {
		struct perf_event_header header;
		u16 type;
		u16 flags;
		u32 id;
		u8 tag[8];
	} event_id;
};

struct perf_text_poke_event {
	const void *old_bytes;
	const void *new_bytes;
	size_t pad;
	u16 old_len;
	u16 new_len;
	struct {
		struct perf_event_header header;
		u64 addr;
	} event_id;
};

struct swevent_htable {
	struct swevent_hlist *swevent_hlist;
	struct mutex hlist_mutex;
	int hlist_refcount;
	int recursion[4];
};

enum perf_probe_config {
	PERF_PROBE_CONFIG_IS_RETPROBE = 1,
	PERF_UPROBE_REF_CTR_OFFSET_BITS = 32,
	PERF_UPROBE_REF_CTR_OFFSET_SHIFT = 32,
};

enum {
	IF_ACT_NONE = 4294967295,
	IF_ACT_FILTER = 0,
	IF_ACT_START = 1,
	IF_ACT_STOP = 2,
	IF_SRC_FILE = 3,
	IF_SRC_KERNEL = 4,
	IF_SRC_FILEADDR = 5,
	IF_SRC_KERNELADDR = 6,
};

enum {
	IF_STATE_ACTION = 0,
	IF_STATE_SOURCE = 1,
	IF_STATE_END = 2,
};

struct perf_aux_event {
	struct perf_event_header header;
	u64 hw_id;
};

struct perf_aux_event___2 {
	struct perf_event_header header;
	u32 pid;
	u32 tid;
};

struct perf_aux_event___3 {
	struct perf_event_header header;
	u64 offset;
	u64 size;
	u64 flags;
};

struct reciprocal_value {
	u32 m;
	u8 sh1;
	u8 sh2;
};

struct array_cache;

struct kmem_cache_node;

struct kmem_cache {
	struct array_cache *cpu_cache;
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;
	unsigned int size;
	struct reciprocal_value reciprocal_buffer_size;
	slab_flags_t flags;
	unsigned int num;
	unsigned int gfporder;
	gfp_t allocflags;
	size_t colour;
	unsigned int colour_off;
	struct kmem_cache *freelist_cache;
	unsigned int freelist_size;
	void (*ctor)(void *);
	const char *name;
	struct list_head list;
	int refcount;
	int object_size;
	int align;
	unsigned int useroffset;
	unsigned int usersize;
	struct kmem_cache_node *node[1];
};

struct alien_cache;

struct kmem_cache_node {
	spinlock_t list_lock;
	struct list_head slabs_partial;
	struct list_head slabs_full;
	struct list_head slabs_free;
	long unsigned int total_slabs;
	long unsigned int free_slabs;
	long unsigned int free_objects;
	unsigned int free_limit;
	unsigned int colour_next;
	struct array_cache *shared;
	struct alien_cache **alien;
	long unsigned int next_reap;
	int free_touched;
};

typedef void (*xa_update_node_t)(struct xa_node *);

struct xa_state {
	struct xarray *xa;
	long unsigned int xa_index;
	unsigned char xa_shift;
	unsigned char xa_sibs;
	unsigned char xa_offset;
	unsigned char xa_pad;
	struct xa_node *xa_node;
	struct xa_node *xa_alloc;
	xa_update_node_t xa_update;
	struct list_lru *xa_lru;
};

enum migrate_reason {
	MR_COMPACTION = 0,
	MR_MEMORY_FAILURE = 1,
	MR_MEMORY_HOTPLUG = 2,
	MR_SYSCALL = 3,
	MR_MEMPOLICY_MBIND = 4,
	MR_NUMA_MISPLACED = 5,
	MR_CONTIG_RANGE = 6,
	MR_LONGTERM_PIN = 7,
	MR_DEMOTION = 8,
	MR_TYPES = 9,
};

enum positive_aop_returns {
	AOP_WRITEPAGE_ACTIVATE = 524288,
	AOP_TRUNCATED_PAGE = 524289,
};

struct vm_event_state {
	long unsigned int event[47];
};

enum mapping_flags {
	AS_EIO = 0,
	AS_ENOSPC = 1,
	AS_MM_ALL_LOCKS = 2,
	AS_UNEVICTABLE = 3,
	AS_EXITING = 4,
	AS_NO_WRITEBACK_TAGS = 5,
	AS_LARGE_FOLIO_SUPPORT = 6,
};

typedef int filler_t(void *, struct page *);

struct wait_page_key {
	struct folio *folio;
	int bit_nr;
	int page_match;
};

enum iter_type {
	ITER_IOVEC = 0,
	ITER_KVEC = 1,
	ITER_BVEC = 2,
	ITER_PIPE = 3,
	ITER_XARRAY = 4,
	ITER_DISCARD = 5,
};

struct pagevec {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct page *pages[15];
};

struct folio_batch {
	unsigned char nr;
	bool percpu_pvec_drained;
	struct folio *folios[15];
};

struct trace_event_raw_mm_filemap_op_page_cache {
	struct trace_entry ent;
	long unsigned int pfn;
	long unsigned int i_ino;
	long unsigned int index;
	dev_t s_dev;
	unsigned char order;
	char __data[0];
};

struct trace_event_raw_filemap_set_wb_err {
	struct trace_entry ent;
	long unsigned int i_ino;
	dev_t s_dev;
	errseq_t errseq;
	char __data[0];
};

struct trace_event_raw_file_check_and_advance_wb_err {
	struct trace_entry ent;
	struct file *file;
	long unsigned int i_ino;
	dev_t s_dev;
	errseq_t old;
	errseq_t new;
	char __data[0];
};

struct trace_event_data_offsets_mm_filemap_op_page_cache {};

struct trace_event_data_offsets_filemap_set_wb_err {};

struct trace_event_data_offsets_file_check_and_advance_wb_err {};

typedef void (*btf_trace_mm_filemap_delete_from_page_cache)(void *, struct folio *);

typedef void (*btf_trace_mm_filemap_add_to_page_cache)(void *, struct folio *);

typedef void (*btf_trace_filemap_set_wb_err)(void *, struct address_space *, errseq_t);

typedef void (*btf_trace_file_check_and_advance_wb_err)(void *, struct file *, errseq_t);

enum behavior {
	EXCLUSIVE = 0,
	SHARED = 1,
	DROP = 2,
};

enum oom_constraint {
	CONSTRAINT_NONE = 0,
	CONSTRAINT_CPUSET = 1,
	CONSTRAINT_MEMORY_POLICY = 2,
	CONSTRAINT_MEMCG = 3,
};

struct oom_control {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct mem_cgroup *memcg;
	const gfp_t gfp_mask;
	const int order;
	long unsigned int totalpages;
	struct task_struct *chosen;
	long int chosen_points;
	enum oom_constraint constraint;
};

enum memcg_memory_event {
	MEMCG_LOW = 0,
	MEMCG_HIGH = 1,
	MEMCG_MAX = 2,
	MEMCG_OOM = 3,
	MEMCG_OOM_KILL = 4,
	MEMCG_OOM_GROUP_KILL = 5,
	MEMCG_SWAP_HIGH = 6,
	MEMCG_SWAP_MAX = 7,
	MEMCG_SWAP_FAIL = 8,
	MEMCG_NR_MEMORY_EVENTS = 9,
};

struct mmu_notifier_range {
	long unsigned int start;
	long unsigned int end;
};

struct mmu_gather_batch {
	struct mmu_gather_batch *next;
	unsigned int nr;
	unsigned int max;
	struct page *pages[0];
};

struct mmu_gather {
	struct mm_struct *mm;
	long unsigned int start;
	long unsigned int end;
	unsigned int fullmm: 1;
	unsigned int need_flush_all: 1;
	unsigned int freed_tables: 1;
	unsigned int cleared_ptes: 1;
	unsigned int cleared_pmds: 1;
	unsigned int cleared_puds: 1;
	unsigned int cleared_p4ds: 1;
	unsigned int vma_exec: 1;
	unsigned int vma_huge: 1;
	unsigned int batch_count;
	struct mmu_gather_batch *active;
	struct mmu_gather_batch local;
	struct page *__pages[8];
};

struct trace_event_raw_oom_score_adj_update {
	struct trace_entry ent;
	pid_t pid;
	char comm[16];
	short int oom_score_adj;
	char __data[0];
};

struct trace_event_raw_reclaim_retry_zone {
	struct trace_entry ent;
	int node;
	int zone_idx;
	int order;
	long unsigned int reclaimable;
	long unsigned int available;
	long unsigned int min_wmark;
	int no_progress_loops;
	bool wmark_check;
	char __data[0];
};

struct trace_event_raw_mark_victim {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_wake_reaper {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_start_task_reaping {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_finish_task_reaping {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_raw_skip_task_reaping {
	struct trace_entry ent;
	int pid;
	char __data[0];
};

struct trace_event_data_offsets_oom_score_adj_update {};

struct trace_event_data_offsets_reclaim_retry_zone {};

struct trace_event_data_offsets_mark_victim {};

struct trace_event_data_offsets_wake_reaper {};

struct trace_event_data_offsets_start_task_reaping {};

struct trace_event_data_offsets_finish_task_reaping {};

struct trace_event_data_offsets_skip_task_reaping {};

typedef void (*btf_trace_oom_score_adj_update)(void *, struct task_struct *);

typedef void (*btf_trace_reclaim_retry_zone)(void *, struct zoneref *, int, long unsigned int, long unsigned int, long unsigned int, int, bool);

typedef void (*btf_trace_mark_victim)(void *, int);

typedef void (*btf_trace_wake_reaper)(void *, int);

typedef void (*btf_trace_start_task_reaping)(void *, int);

typedef void (*btf_trace_finish_task_reaping)(void *, int);

typedef void (*btf_trace_skip_task_reaping)(void *, int);

struct zap_details;

enum {
	XA_CHECK_SCHED = 4096,
};

struct fprop_global {
	struct percpu_counter events;
	unsigned int period;
	seqcount_t sequence;
};

enum wb_state {
	WB_registered = 0,
	WB_writeback_running = 1,
	WB_has_dirty_io = 2,
	WB_start_all = 3,
};

struct wb_lock_cookie {
	bool locked;
	long unsigned int flags;
};

struct wb_domain {
	spinlock_t lock;
	struct fprop_global completions;
	struct timer_list period_timer;
	long unsigned int period_time;
	long unsigned int dirty_limit_tstamp;
	long unsigned int dirty_limit;
};

typedef int (*writepage_t)(struct page *, struct writeback_control *, void *);

struct dirty_throttle_control {
	struct bdi_writeback *wb;
	struct fprop_local_percpu *wb_completions;
	long unsigned int avail;
	long unsigned int dirty;
	long unsigned int thresh;
	long unsigned int bg_thresh;
	long unsigned int wb_dirty;
	long unsigned int wb_thresh;
	long unsigned int wb_bg_thresh;
	long unsigned int pos_ratio;
};

struct vmem_altmap {
	long unsigned int base_pfn;
	const long unsigned int end_pfn;
	const long unsigned int reserve;
	long unsigned int free;
	long unsigned int align;
	long unsigned int alloc;
};

enum memory_type {
	MEMORY_DEVICE_PRIVATE = 1,
	MEMORY_DEVICE_FS_DAX = 2,
	MEMORY_DEVICE_GENERIC = 3,
	MEMORY_DEVICE_PCI_P2PDMA = 4,
};

struct dev_pagemap_ops;

struct dev_pagemap {
	struct vmem_altmap altmap;
	struct percpu_ref ref;
	struct completion done;
	enum memory_type type;
	unsigned int flags;
	long unsigned int vmemmap_shift;
	const struct dev_pagemap_ops *ops;
	void *owner;
	int nr_range;
	union {
		struct range range;
		struct range ranges[0];
	};
};

typedef void compound_page_dtor(struct page *);

struct dev_pagemap_ops {
	void (*page_free)(struct page *);
	vm_fault_t (*migrate_to_ram)(struct vm_fault *);
};

struct trace_event_raw_mm_lru_insertion {
	struct trace_entry ent;
	struct folio *folio;
	long unsigned int pfn;
	enum lru_list lru;
	long unsigned int flags;
	char __data[0];
};

struct trace_event_raw_mm_lru_activate {
	struct trace_entry ent;
	struct folio *folio;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_data_offsets_mm_lru_insertion {};

struct trace_event_data_offsets_mm_lru_activate {};

typedef void (*btf_trace_mm_lru_insertion)(void *, struct folio *);

typedef void (*btf_trace_mm_lru_activate)(void *, struct folio *);

struct lru_rotate {
	local_lock_t lock;
	struct pagevec pvec;
};

struct lru_pvecs {
	local_lock_t lock;
	struct pagevec lru_add;
	struct pagevec lru_deactivate_file;
	struct pagevec lru_deactivate;
	struct pagevec lru_lazyfree;
};

typedef struct {
	long unsigned int val;
} swp_entry_t;

struct kstatfs {
	long int f_type;
	long int f_bsize;
	u64 f_blocks;
	u64 f_bfree;
	u64 f_bavail;
	u64 f_files;
	u64 f_ffree;
	__kernel_fsid_t f_fsid;
	long int f_namelen;
	long int f_frsize;
	long int f_flags;
	long int f_spare[4];
};

struct xattr;

typedef int (*initxattrs)(struct inode *, const struct xattr *, void *);

struct xattr {
	const char *name;
	void *value;
	size_t value_len;
};

struct constant_table {
	const char *name;
	int value;
};

struct shared_policy {};

struct simple_xattrs {
	struct list_head head;
	spinlock_t lock;
};

struct simple_xattr {
	struct list_head list;
	char *name;
	size_t size;
	char value[0];
};

struct shmem_inode_info {
	spinlock_t lock;
	unsigned int seals;
	long unsigned int flags;
	long unsigned int alloced;
	long unsigned int swapped;
	long unsigned int fallocend;
	struct list_head shrinklist;
	struct list_head swaplist;
	struct shared_policy policy;
	struct simple_xattrs xattrs;
	atomic_t stop_eviction;
	struct timespec64 i_crtime;
	int: 32;
	struct inode vfs_inode;
};

struct shmem_sb_info {
	long unsigned int max_blocks;
	struct percpu_counter used_blocks;
	long unsigned int max_inodes;
	long unsigned int free_inodes;
	raw_spinlock_t stat_lock;
	umode_t mode;
	unsigned char huge;
	kuid_t uid;
	kgid_t gid;
	bool full_inums;
	ino_t next_ino;
	ino_t *ino_batch;
	struct mempolicy *mpol;
	spinlock_t shrinklist_lock;
	struct list_head shrinklist;
	long unsigned int shrinklist_len;
};

enum sgp_type {
	SGP_READ = 0,
	SGP_NOALLOC = 1,
	SGP_CACHE = 2,
	SGP_WRITE = 3,
	SGP_FALLOC = 4,
};

enum fid_type {
	FILEID_ROOT = 0,
	FILEID_INO32_GEN = 1,
	FILEID_INO32_GEN_PARENT = 2,
	FILEID_BTRFS_WITHOUT_PARENT = 77,
	FILEID_BTRFS_WITH_PARENT = 78,
	FILEID_BTRFS_WITH_PARENT_ROOT = 79,
	FILEID_UDF_WITHOUT_PARENT = 81,
	FILEID_UDF_WITH_PARENT = 82,
	FILEID_NILFS_WITHOUT_PARENT = 97,
	FILEID_NILFS_WITH_PARENT = 98,
	FILEID_FAT_WITHOUT_PARENT = 113,
	FILEID_FAT_WITH_PARENT = 114,
	FILEID_LUSTRE = 151,
	FILEID_KERNFS = 254,
	FILEID_INVALID = 255,
};

struct fid {
	union {
		struct {
			u32 ino;
			u32 gen;
			u32 parent_ino;
			u32 parent_gen;
		} i32;
		struct {
			u32 block;
			u16 partref;
			u16 parent_partref;
			u32 generation;
			u32 parent_block;
			u32 parent_generation;
		} udf;
		__u32 raw[0];
	};
};

struct shmem_falloc {
	wait_queue_head_t *waitq;
	long unsigned int start;
	long unsigned int next;
	long unsigned int nr_falloced;
	long unsigned int nr_unswapped;
};

struct shmem_options {
	long long unsigned int blocks;
	long long unsigned int inodes;
	struct mempolicy *mpol;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	bool full_inums;
	int huge;
	int seen;
};

enum shmem_param {
	Opt_gid = 0,
	Opt_huge = 1,
	Opt_mode = 2,
	Opt_mpol = 3,
	Opt_nr_blocks = 4,
	Opt_nr_inodes = 5,
	Opt_size = 6,
	Opt_uid = 7,
	Opt_inode32 = 8,
	Opt_inode64 = 9,
};

enum lruvec_flags {
	LRUVEC_CONGESTED = 0,
};

enum pgdat_flags {
	PGDAT_DIRTY = 0,
	PGDAT_WRITEBACK = 1,
	PGDAT_RECLAIM_LOCKED = 2,
};

enum zone_flags {
	ZONE_BOOSTED_WATERMARK = 0,
	ZONE_RECLAIM_ACTIVE = 1,
};

struct reclaim_stat {
	unsigned int nr_dirty;
	unsigned int nr_unqueued_dirty;
	unsigned int nr_congested;
	unsigned int nr_writeback;
	unsigned int nr_immediate;
	unsigned int nr_pageout;
	unsigned int nr_activate[2];
	unsigned int nr_ref_keep;
	unsigned int nr_unmap_fail;
	unsigned int nr_lazyfree_fail;
};

struct mem_cgroup_reclaim_cookie {
	pg_data_t *pgdat;
	unsigned int generation;
};

enum ttu_flags {
	TTU_SPLIT_HUGE_PMD = 4,
	TTU_IGNORE_MLOCK = 8,
	TTU_SYNC = 16,
	TTU_IGNORE_HWPOISON = 32,
	TTU_BATCH_FLUSH = 64,
	TTU_RMAP_LOCKED = 128,
};

enum compact_result {
	COMPACT_NOT_SUITABLE_ZONE = 0,
	COMPACT_SKIPPED = 1,
	COMPACT_DEFERRED = 2,
	COMPACT_NO_SUITABLE_PAGE = 3,
	COMPACT_CONTINUE = 4,
	COMPACT_COMPLETE = 5,
	COMPACT_PARTIAL_SKIPPED = 6,
	COMPACT_CONTENDED = 7,
	COMPACT_SUCCESS = 8,
};

typedef struct page *new_page_t(struct page *, long unsigned int);

typedef void free_page_t(struct page *, long unsigned int);

struct migration_target_control {
	int nid;
	nodemask_t *nmask;
	gfp_t gfp_mask;
};

struct trace_event_raw_mm_vmscan_kswapd_sleep {
	struct trace_entry ent;
	int nid;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_kswapd_wake {
	struct trace_entry ent;
	int nid;
	int zid;
	int order;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_wakeup_kswapd {
	struct trace_entry ent;
	int nid;
	int zid;
	int order;
	gfp_t gfp_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_direct_reclaim_begin_template {
	struct trace_entry ent;
	int order;
	gfp_t gfp_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_direct_reclaim_end_template {
	struct trace_entry ent;
	long unsigned int nr_reclaimed;
	char __data[0];
};

struct trace_event_raw_mm_shrink_slab_start {
	struct trace_entry ent;
	struct shrinker *shr;
	void *shrink;
	int nid;
	long int nr_objects_to_shrink;
	gfp_t gfp_flags;
	long unsigned int cache_items;
	long long unsigned int delta;
	long unsigned int total_scan;
	int priority;
	char __data[0];
};

struct trace_event_raw_mm_shrink_slab_end {
	struct trace_entry ent;
	struct shrinker *shr;
	int nid;
	void *shrink;
	long int unused_scan;
	long int new_scan;
	int retval;
	long int total_scan;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_lru_isolate {
	struct trace_entry ent;
	int highest_zoneidx;
	int order;
	long unsigned int nr_requested;
	long unsigned int nr_scanned;
	long unsigned int nr_skipped;
	long unsigned int nr_taken;
	isolate_mode_t isolate_mode;
	int lru;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_write_folio {
	struct trace_entry ent;
	long unsigned int pfn;
	int reclaim_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_lru_shrink_inactive {
	struct trace_entry ent;
	int nid;
	long unsigned int nr_scanned;
	long unsigned int nr_reclaimed;
	long unsigned int nr_dirty;
	long unsigned int nr_writeback;
	long unsigned int nr_congested;
	long unsigned int nr_immediate;
	unsigned int nr_activate0;
	unsigned int nr_activate1;
	long unsigned int nr_ref_keep;
	long unsigned int nr_unmap_fail;
	int priority;
	int reclaim_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_lru_shrink_active {
	struct trace_entry ent;
	int nid;
	long unsigned int nr_taken;
	long unsigned int nr_active;
	long unsigned int nr_deactivated;
	long unsigned int nr_referenced;
	int priority;
	int reclaim_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_node_reclaim_begin {
	struct trace_entry ent;
	int nid;
	int order;
	gfp_t gfp_flags;
	char __data[0];
};

struct trace_event_raw_mm_vmscan_throttled {
	struct trace_entry ent;
	int nid;
	int usec_timeout;
	int usec_delayed;
	int reason;
	char __data[0];
};

struct trace_event_data_offsets_mm_vmscan_kswapd_sleep {};

struct trace_event_data_offsets_mm_vmscan_kswapd_wake {};

struct trace_event_data_offsets_mm_vmscan_wakeup_kswapd {};

struct trace_event_data_offsets_mm_vmscan_direct_reclaim_begin_template {};

struct trace_event_data_offsets_mm_vmscan_direct_reclaim_end_template {};

struct trace_event_data_offsets_mm_shrink_slab_start {};

struct trace_event_data_offsets_mm_shrink_slab_end {};

struct trace_event_data_offsets_mm_vmscan_lru_isolate {};

struct trace_event_data_offsets_mm_vmscan_write_folio {};

struct trace_event_data_offsets_mm_vmscan_lru_shrink_inactive {};

struct trace_event_data_offsets_mm_vmscan_lru_shrink_active {};

struct trace_event_data_offsets_mm_vmscan_node_reclaim_begin {};

struct trace_event_data_offsets_mm_vmscan_throttled {};

typedef void (*btf_trace_mm_vmscan_kswapd_sleep)(void *, int);

typedef void (*btf_trace_mm_vmscan_kswapd_wake)(void *, int, int, int);

typedef void (*btf_trace_mm_vmscan_wakeup_kswapd)(void *, int, int, int, gfp_t);

typedef void (*btf_trace_mm_vmscan_direct_reclaim_begin)(void *, int, gfp_t);

typedef void (*btf_trace_mm_vmscan_direct_reclaim_end)(void *, long unsigned int);

typedef void (*btf_trace_mm_shrink_slab_start)(void *, struct shrinker *, struct shrink_control *, long int, long unsigned int, long long unsigned int, long unsigned int, int);

typedef void (*btf_trace_mm_shrink_slab_end)(void *, struct shrinker *, int, int, long int, long int, long int);

typedef void (*btf_trace_mm_vmscan_lru_isolate)(void *, int, int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, isolate_mode_t, int);

typedef void (*btf_trace_mm_vmscan_write_folio)(void *, struct folio *);

typedef void (*btf_trace_mm_vmscan_lru_shrink_inactive)(void *, int, long unsigned int, long unsigned int, struct reclaim_stat *, int, int);

typedef void (*btf_trace_mm_vmscan_lru_shrink_active)(void *, int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, int, int);

typedef void (*btf_trace_mm_vmscan_node_reclaim_begin)(void *, int, int, gfp_t);

typedef void (*btf_trace_mm_vmscan_node_reclaim_end)(void *, long unsigned int);

typedef void (*btf_trace_mm_vmscan_throttled)(void *, int, int, int, int);

struct scan_control {
	long unsigned int nr_to_reclaim;
	nodemask_t *nodemask;
	struct mem_cgroup *target_mem_cgroup;
	long unsigned int anon_cost;
	long unsigned int file_cost;
	unsigned int may_deactivate: 2;
	unsigned int force_deactivate: 1;
	unsigned int skipped_deactivate: 1;
	unsigned int may_writepage: 1;
	unsigned int may_unmap: 1;
	unsigned int may_swap: 1;
	unsigned int memcg_low_reclaim: 1;
	unsigned int memcg_low_skipped: 1;
	unsigned int hibernation_mode: 1;
	unsigned int compaction_ready: 1;
	unsigned int cache_trim_mode: 1;
	unsigned int file_is_tiny: 1;
	unsigned int no_demotion: 1;
	s8 order;
	s8 priority;
	s8 reclaim_idx;
	gfp_t gfp_mask;
	long unsigned int nr_scanned;
	long unsigned int nr_reclaimed;
	struct {
		unsigned int dirty;
		unsigned int unqueued_dirty;
		unsigned int congested;
		unsigned int writeback;
		unsigned int immediate;
		unsigned int file_taken;
		unsigned int taken;
	} nr;
	struct reclaim_state reclaim_state;
};

typedef enum {
	PAGE_KEEP = 0,
	PAGE_ACTIVATE = 1,
	PAGE_SUCCESS = 2,
	PAGE_CLEAN = 3,
} pageout_t;

enum page_references {
	PAGEREF_RECLAIM = 0,
	PAGEREF_RECLAIM_CLEAN = 1,
	PAGEREF_KEEP = 2,
	PAGEREF_ACTIVATE = 3,
};

enum scan_balance {
	SCAN_EQUAL = 0,
	SCAN_FRACT = 1,
	SCAN_ANON = 2,
	SCAN_FILE = 3,
};

enum writeback_stat_item {
	NR_DIRTY_THRESHOLD = 0,
	NR_DIRTY_BG_THRESHOLD = 1,
	NR_VM_WRITEBACK_STAT_ITEMS = 2,
};

enum mminit_level {
	MMINIT_WARNING = 0,
	MMINIT_VERIFY = 1,
	MMINIT_TRACE = 2,
};

struct pcpu_group_info {
	int nr_units;
	long unsigned int base_offset;
	unsigned int *cpu_map;
};

struct pcpu_alloc_info {
	size_t static_size;
	size_t reserved_size;
	size_t dyn_size;
	size_t unit_size;
	size_t atom_size;
	size_t alloc_size;
	size_t __ai_size;
	int nr_groups;
	struct pcpu_group_info groups[0];
};

struct trace_event_raw_percpu_alloc_percpu {
	struct trace_entry ent;
	bool reserved;
	bool is_atomic;
	size_t size;
	size_t align;
	void *base_addr;
	int off;
	void *ptr;
	char __data[0];
};

struct trace_event_raw_percpu_free_percpu {
	struct trace_entry ent;
	void *base_addr;
	int off;
	void *ptr;
	char __data[0];
};

struct trace_event_raw_percpu_alloc_percpu_fail {
	struct trace_entry ent;
	bool reserved;
	bool is_atomic;
	size_t size;
	size_t align;
	char __data[0];
};

struct trace_event_raw_percpu_create_chunk {
	struct trace_entry ent;
	void *base_addr;
	char __data[0];
};

struct trace_event_raw_percpu_destroy_chunk {
	struct trace_entry ent;
	void *base_addr;
	char __data[0];
};

struct trace_event_data_offsets_percpu_alloc_percpu {};

struct trace_event_data_offsets_percpu_free_percpu {};

struct trace_event_data_offsets_percpu_alloc_percpu_fail {};

struct trace_event_data_offsets_percpu_create_chunk {};

struct trace_event_data_offsets_percpu_destroy_chunk {};

typedef void (*btf_trace_percpu_alloc_percpu)(void *, bool, bool, size_t, size_t, void *, int, void *);

typedef void (*btf_trace_percpu_free_percpu)(void *, void *, int, void *);

typedef void (*btf_trace_percpu_alloc_percpu_fail)(void *, bool, bool, size_t, size_t);

typedef void (*btf_trace_percpu_create_chunk)(void *, void *);

typedef void (*btf_trace_percpu_destroy_chunk)(void *, void *);

struct pcpu_block_md {
	int scan_hint;
	int scan_hint_start;
	int contig_hint;
	int contig_hint_start;
	int left_free;
	int right_free;
	int first_free;
	int nr_bits;
};

struct pcpu_chunk {
	struct list_head list;
	int free_bytes;
	struct pcpu_block_md chunk_md;
	void *base_addr;
	long unsigned int *alloc_map;
	long unsigned int *bound_map;
	struct pcpu_block_md *md_blocks;
	void *data;
	bool immutable;
	bool isolated;
	int start_offset;
	int end_offset;
	int nr_pages;
	int nr_populated;
	int nr_empty_pop_pages;
	long unsigned int populated[0];
};

struct obj_cgroup;

struct trace_event_raw_kmem_alloc {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	gfp_t gfp_flags;
	char __data[0];
};

struct trace_event_raw_kmem_alloc_node {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	size_t bytes_req;
	size_t bytes_alloc;
	gfp_t gfp_flags;
	int node;
	char __data[0];
};

struct trace_event_raw_kfree {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	char __data[0];
};

struct trace_event_raw_kmem_cache_free {
	struct trace_entry ent;
	long unsigned int call_site;
	const void *ptr;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_mm_page_free {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	char __data[0];
};

struct trace_event_raw_mm_page_free_batched {
	struct trace_entry ent;
	long unsigned int pfn;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	gfp_t gfp_flags;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page_pcpu_drain {
	struct trace_entry ent;
	long unsigned int pfn;
	unsigned int order;
	int migratetype;
	char __data[0];
};

struct trace_event_raw_mm_page_alloc_extfrag {
	struct trace_entry ent;
	long unsigned int pfn;
	int alloc_order;
	int fallback_order;
	int alloc_migratetype;
	int fallback_migratetype;
	int change_ownership;
	char __data[0];
};

struct trace_event_raw_rss_stat {
	struct trace_entry ent;
	unsigned int mm_id;
	unsigned int curr;
	int member;
	long int size;
	char __data[0];
};

struct trace_event_data_offsets_kmem_alloc {};

struct trace_event_data_offsets_kmem_alloc_node {};

struct trace_event_data_offsets_kfree {};

struct trace_event_data_offsets_kmem_cache_free {
	u32 name;
};

struct trace_event_data_offsets_mm_page_free {};

struct trace_event_data_offsets_mm_page_free_batched {};

struct trace_event_data_offsets_mm_page_alloc {};

struct trace_event_data_offsets_mm_page {};

struct trace_event_data_offsets_mm_page_pcpu_drain {};

struct trace_event_data_offsets_mm_page_alloc_extfrag {};

struct trace_event_data_offsets_rss_stat {};

typedef void (*btf_trace_kmalloc)(void *, long unsigned int, const void *, size_t, size_t, gfp_t);

typedef void (*btf_trace_kmem_cache_alloc)(void *, long unsigned int, const void *, size_t, size_t, gfp_t);

typedef void (*btf_trace_kmalloc_node)(void *, long unsigned int, const void *, size_t, size_t, gfp_t, int);

typedef void (*btf_trace_kmem_cache_alloc_node)(void *, long unsigned int, const void *, size_t, size_t, gfp_t, int);

typedef void (*btf_trace_kfree)(void *, long unsigned int, const void *);

typedef void (*btf_trace_kmem_cache_free)(void *, long unsigned int, const void *, const char *);

typedef void (*btf_trace_mm_page_free)(void *, struct page *, unsigned int);

typedef void (*btf_trace_mm_page_free_batched)(void *, struct page *);

typedef void (*btf_trace_mm_page_alloc)(void *, struct page *, unsigned int, gfp_t, int);

typedef void (*btf_trace_mm_page_alloc_zone_locked)(void *, struct page *, unsigned int, int);

typedef void (*btf_trace_mm_page_pcpu_drain)(void *, struct page *, unsigned int, int);

typedef void (*btf_trace_mm_page_alloc_extfrag)(void *, struct page *, int, int, int, int);

typedef void (*btf_trace_rss_stat)(void *, struct mm_struct *, int, long int);

struct slab {
	long unsigned int __page_flags;
	union {
		struct list_head slab_list;
		struct callback_head callback_head;
	};
	struct kmem_cache *slab_cache;
	void *freelist;
	void *s_mem;
	unsigned int active;
	atomic_t __page_refcount;
};

enum slab_state {
	DOWN = 0,
	PARTIAL = 1,
	PARTIAL_NODE = 2,
	UP = 3,
	FULL = 4,
};

struct kmalloc_info_struct {
	const char *name[2];
	unsigned int size;
};

struct slabinfo {
	long unsigned int active_objs;
	long unsigned int num_objs;
	long unsigned int active_slabs;
	long unsigned int num_slabs;
	long unsigned int shared_avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int shared;
	unsigned int objects_per_slab;
	unsigned int cache_order;
};

struct kmem_obj_info {
	void *kp_ptr;
	struct slab *kp_slab;
	void *kp_objp;
	long unsigned int kp_data_offset;
	struct kmem_cache *kp_slab_cache;
	void *kp_ret;
	void *kp_stack[16];
	void *kp_free_stack[16];
};

struct anon_vma_chain {
	struct vm_area_struct *vma;
	struct anon_vma *anon_vma;
	struct list_head same_vma;
	struct rb_node rb;
	long unsigned int rb_subtree_last;
};

struct rb_augment_callbacks {
	void (*propagate)(struct rb_node *, struct rb_node *);
	void (*copy)(struct rb_node *, struct rb_node *);
	void (*rotate)(struct rb_node *, struct rb_node *);
};

enum lru_status {
	LRU_REMOVED = 0,
	LRU_REMOVED_RETRY = 1,
	LRU_ROTATE = 2,
	LRU_SKIP = 3,
	LRU_RETRY = 4,
};

typedef enum lru_status (*list_lru_walk_cb)(struct list_head *, struct list_lru_one *, spinlock_t *, void *);

struct trace_event_raw_mmap_lock {
	struct trace_entry ent;
	struct mm_struct *mm;
	u32 __data_loc_memcg_path;
	bool write;
	char __data[0];
};

struct trace_event_raw_mmap_lock_acquire_returned {
	struct trace_entry ent;
	struct mm_struct *mm;
	u32 __data_loc_memcg_path;
	bool write;
	bool success;
	char __data[0];
};

struct trace_event_data_offsets_mmap_lock {
	u32 memcg_path;
};

struct trace_event_data_offsets_mmap_lock_acquire_returned {
	u32 memcg_path;
};

typedef void (*btf_trace_mmap_lock_start_locking)(void *, struct mm_struct *, const char *, bool);

typedef void (*btf_trace_mmap_lock_released)(void *, struct mm_struct *, const char *, bool);

typedef void (*btf_trace_mmap_lock_acquire_returned)(void *, struct mm_struct *, const char *, bool, bool);

typedef struct {
	long unsigned int pd;
} hugepd_t;

struct follow_page_context {
	struct dev_pagemap *pgmap;
	unsigned int page_mask;
};

struct mm_walk;

struct mm_walk_ops {
	int (*pgd_entry)(pgd_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*p4d_entry)(p4d_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pud_entry)(pud_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pmd_entry)(pmd_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pte_entry)(pte_t *, long unsigned int, long unsigned int, struct mm_walk *);
	int (*pte_hole)(long unsigned int, long unsigned int, int, struct mm_walk *);
	int (*hugetlb_entry)(pte_t *, long unsigned int, long unsigned int, long unsigned int, struct mm_walk *);
	int (*test_walk)(long unsigned int, long unsigned int, struct mm_walk *);
	int (*pre_vma)(long unsigned int, long unsigned int, struct mm_walk *);
	void (*post_vma)(struct mm_walk *);
};

enum page_walk_action {
	ACTION_SUBTREE = 0,
	ACTION_CONTINUE = 1,
	ACTION_AGAIN = 2,
};

struct mm_walk {
	const struct mm_walk_ops *ops;
	struct mm_struct *mm;
	pgd_t *pgd;
	struct vm_area_struct *vma;
	enum page_walk_action action;
	bool no_vma;
	void *private;
};

typedef struct {
	u64 val;
} pfn_t;

typedef unsigned int pgtbl_mod_mask;

typedef int (*pte_fn_t)(pte_t *, long unsigned int, void *);

enum {
	SWP_USED = 1,
	SWP_WRITEOK = 2,
	SWP_DISCARDABLE = 4,
	SWP_DISCARDING = 8,
	SWP_SOLIDSTATE = 16,
	SWP_CONTINUED = 32,
	SWP_BLKDEV = 64,
	SWP_ACTIVATED = 128,
	SWP_FS_OPS = 256,
	SWP_AREA_DISCARD = 512,
	SWP_PAGE_DISCARD = 1024,
	SWP_STABLE_WRITES = 2048,
	SWP_SYNCHRONOUS_IO = 4096,
	SWP_SCANNING = 16384,
};

struct zap_details {
	struct folio *single_folio;
	bool even_cows;
};

struct mlock_pvec {
	local_lock_t lock;
	struct pagevec vec;
};

struct vm_special_mapping {
	const char *name;
	struct page **pages;
	vm_fault_t (*fault)(const struct vm_special_mapping *, struct vm_area_struct *, struct vm_fault *);
	int (*mremap)(const struct vm_special_mapping *, struct vm_area_struct *);
};

enum {
	HUGETLB_SHMFS_INODE = 1,
	HUGETLB_ANONHUGE_INODE = 2,
};

struct hstate {};

struct trace_event_raw_vm_unmapped_area {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int total_vm;
	long unsigned int flags;
	long unsigned int length;
	long unsigned int low_limit;
	long unsigned int high_limit;
	long unsigned int align_mask;
	long unsigned int align_offset;
	char __data[0];
};

struct trace_event_data_offsets_vm_unmapped_area {};

typedef void (*btf_trace_vm_unmapped_area)(void *, long unsigned int, struct vm_unmapped_area_info *);

enum pgt_entry {
	NORMAL_PMD = 0,
	HPAGE_PMD = 1,
	NORMAL_PUD = 2,
	HPAGE_PUD = 3,
};

struct page_vma_mapped_walk {
	long unsigned int pfn;
	long unsigned int nr_pages;
	long unsigned int pgoff;
	struct vm_area_struct *vma;
	long unsigned int address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	unsigned int flags;
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH = 0,
	TLB_REMOTE_SHOOTDOWN = 1,
	TLB_LOCAL_SHOOTDOWN = 2,
	TLB_LOCAL_MM_SHOOTDOWN = 3,
	TLB_REMOTE_SEND_IPI = 4,
	NR_TLB_FLUSH_REASONS = 5,
};

struct rmap_walk_control {
	void *arg;
	bool (*rmap_one)(struct folio *, struct vm_area_struct *, long unsigned int, void *);
	int (*done)(struct folio *);
	struct anon_vma * (*anon_lock)(struct folio *);
	bool (*invalid_vma)(struct vm_area_struct *, void *);
};

struct trace_event_raw_tlb_flush {
	struct trace_entry ent;
	int reason;
	long unsigned int pages;
	char __data[0];
};

struct trace_event_data_offsets_tlb_flush {};

typedef void (*btf_trace_tlb_flush)(void *, int, long unsigned int);

struct trace_event_raw_mm_migrate_pages {
	struct trace_entry ent;
	long unsigned int succeeded;
	long unsigned int failed;
	long unsigned int thp_succeeded;
	long unsigned int thp_failed;
	long unsigned int thp_split;
	enum migrate_mode mode;
	int reason;
	char __data[0];
};

struct trace_event_raw_mm_migrate_pages_start {
	struct trace_entry ent;
	enum migrate_mode mode;
	int reason;
	char __data[0];
};

struct trace_event_raw_migration_pte {
	struct trace_entry ent;
	long unsigned int addr;
	long unsigned int pte;
	int order;
	char __data[0];
};

struct trace_event_data_offsets_mm_migrate_pages {};

struct trace_event_data_offsets_mm_migrate_pages_start {};

struct trace_event_data_offsets_migration_pte {};

typedef void (*btf_trace_mm_migrate_pages)(void *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, enum migrate_mode, int);

typedef void (*btf_trace_mm_migrate_pages_start)(void *, enum migrate_mode, int);

typedef void (*btf_trace_set_migration_pte)(void *, long unsigned int, long unsigned int, int);

typedef void (*btf_trace_remove_migration_pte)(void *, long unsigned int, long unsigned int, int);

struct folio_referenced_arg {
	int mapcount;
	int referenced;
	long unsigned int vm_flags;
	struct mem_cgroup *memcg;
};

struct vmap_area {
	long unsigned int va_start;
	long unsigned int va_end;
	struct rb_node rb_node;
	struct list_head list;
	union {
		long unsigned int subtree_max_size;
		struct vm_struct *vm;
	};
};

typedef unsigned int kasan_vmalloc_flags_t;

enum memcg_stat_item {
	MEMCG_SWAP = 39,
	MEMCG_SOCK = 40,
	MEMCG_PERCPU_B = 41,
	MEMCG_VMALLOC = 42,
	MEMCG_KMEM = 43,
	MEMCG_NR_STAT = 44,
};

struct vfree_deferred {
	struct llist_head list;
	struct work_struct wq;
};

enum fit_type {
	NOTHING_FIT = 0,
	FL_FIT_TYPE = 1,
	LE_FIT_TYPE = 2,
	RE_FIT_TYPE = 3,
	NE_FIT_TYPE = 4,
};

struct vmap_block_queue {
	spinlock_t lock;
	struct list_head free;
};

struct vmap_block {
	spinlock_t lock;
	struct vmap_area *va;
	long unsigned int free;
	long unsigned int dirty;
	long unsigned int dirty_min;
	long unsigned int dirty_max;
	struct list_head free_list;
	struct callback_head callback_head;
	struct list_head purge;
};

struct memblock_region {
	phys_addr_t base;
	phys_addr_t size;
	enum memblock_flags flags;
};

struct memblock_type {
	long unsigned int cnt;
	long unsigned int max;
	phys_addr_t total_size;
	struct memblock_region *regions;
	char *name;
};

struct memblock {
	bool bottom_up;
	phys_addr_t current_limit;
	struct memblock_type memory;
	struct memblock_type reserved;
};

struct va_format {
	const char *fmt;
	va_list *va;
};

enum pageblock_bits {
	PB_migrate = 0,
	PB_migrate_end = 2,
	PB_migrate_skip = 3,
	NR_PAGEBLOCK_BITS = 4,
};

struct page_frag_cache {
	void *va;
	__u16 offset;
	__u16 size;
	unsigned int pagecnt_bias;
	bool pfmemalloc;
};

enum meminit_context {
	MEMINIT_EARLY = 0,
	MEMINIT_HOTPLUG = 1,
};

enum compact_priority {
	COMPACT_PRIO_SYNC_FULL = 0,
	MIN_COMPACT_PRIORITY = 0,
	COMPACT_PRIO_SYNC_LIGHT = 1,
	MIN_COMPACT_COSTLY_PRIORITY = 1,
	DEF_COMPACT_PRIORITY = 1,
	COMPACT_PRIO_ASYNC = 2,
	INIT_COMPACT_PRIORITY = 2,
};

struct alloc_context {
	struct zonelist *zonelist;
	nodemask_t *nodemask;
	struct zoneref *preferred_zoneref;
	int migratetype;
	enum zone_type highest_zoneidx;
	bool spread_dirty_pages;
};

typedef int fpi_t;

struct pagesets {
	local_lock_t lock;
};

struct pcpu_drain {
	struct zone *zone;
	struct work_struct work;
};

struct capture_control;

struct madvise_walk_private {
	struct mmu_gather *tlb;
	bool pageout;
};

struct dma_pool {
	struct list_head page_list;
	spinlock_t lock;
	size_t size;
	struct device *dev;
	size_t allocation;
	size_t boundary;
	char name[32];
	struct list_head pools;
};

struct dma_page {
	struct list_head page_list;
	void *vaddr;
	dma_addr_t dma;
	unsigned int in_use;
	unsigned int offset;
};

struct array_cache {
	unsigned int avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int touched;
	void *entry[0];
};

struct alien_cache {
	spinlock_t lock;
	struct array_cache ac;
};

typedef short unsigned int freelist_idx_t;

enum hash_algo {
	HASH_ALGO_MD4 = 0,
	HASH_ALGO_MD5 = 1,
	HASH_ALGO_SHA1 = 2,
	HASH_ALGO_RIPE_MD_160 = 3,
	HASH_ALGO_SHA256 = 4,
	HASH_ALGO_SHA384 = 5,
	HASH_ALGO_SHA512 = 6,
	HASH_ALGO_SHA224 = 7,
	HASH_ALGO_RIPE_MD_128 = 8,
	HASH_ALGO_RIPE_MD_256 = 9,
	HASH_ALGO_RIPE_MD_320 = 10,
	HASH_ALGO_WP_256 = 11,
	HASH_ALGO_WP_384 = 12,
	HASH_ALGO_WP_512 = 13,
	HASH_ALGO_TGR_128 = 14,
	HASH_ALGO_TGR_160 = 15,
	HASH_ALGO_TGR_192 = 16,
	HASH_ALGO_SM3_256 = 17,
	HASH_ALGO_STREEBOG_256 = 18,
	HASH_ALGO_STREEBOG_512 = 19,
	HASH_ALGO__LAST = 20,
};

struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

typedef __kernel_long_t __kernel_off_t;

typedef __kernel_off_t off_t;

enum {
	IOPRIO_CLASS_NONE = 0,
	IOPRIO_CLASS_RT = 1,
	IOPRIO_CLASS_BE = 2,
	IOPRIO_CLASS_IDLE = 3,
};

struct files_stat_struct {
	long unsigned int nr_files;
	long unsigned int nr_free_files;
	long unsigned int max_files;
};

enum vfs_get_super_keying {
	vfs_get_single_super = 0,
	vfs_get_single_reconf_super = 1,
	vfs_get_keyed_super = 2,
	vfs_get_independent_super = 3,
};

typedef struct kobject *kobj_probe_t(dev_t, int *, void *);

struct kobj_map;

struct char_device_struct {
	struct char_device_struct *next;
	unsigned int major;
	unsigned int baseminor;
	int minorct;
	char name[64];
	struct cdev *cdev;
};

struct mount;

struct mnt_namespace {
	struct ns_common ns;
	struct mount *root;
	struct list_head list;
	spinlock_t ns_lock;
	struct user_namespace *user_ns;
	struct ucounts *ucounts;
	u64 seq;
	wait_queue_head_t poll;
	u64 event;
	unsigned int mounts;
	unsigned int pending_mounts;
};

struct mountpoint;

struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
	union {
		struct callback_head mnt_rcu;
		struct llist_node mnt_llist;
	};
	int mnt_count;
	int mnt_writers;
	struct list_head mnt_mounts;
	struct list_head mnt_child;
	struct list_head mnt_instance;
	const char *mnt_devname;
	struct list_head mnt_list;
	struct list_head mnt_expire;
	struct list_head mnt_share;
	struct list_head mnt_slave_list;
	struct list_head mnt_slave;
	struct mount *mnt_master;
	struct mnt_namespace *mnt_ns;
	struct mountpoint *mnt_mp;
	union {
		struct hlist_node mnt_mp_list;
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting;
	struct fsnotify_mark_connector *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
	int mnt_id;
	int mnt_group_id;
	int mnt_expiry_mark;
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
};

struct mountpoint {
	struct hlist_node m_hash;
	struct dentry *m_dentry;
	struct hlist_head m_list;
	int m_count;
};

typedef short unsigned int ushort;

struct user_arg_ptr {
	union {
		const char * const *native;
	} ptr;
};

enum inode_i_mutex_lock_class {
	I_MUTEX_NORMAL = 0,
	I_MUTEX_PARENT = 1,
	I_MUTEX_CHILD = 2,
	I_MUTEX_XATTR = 3,
	I_MUTEX_NONDIR2 = 4,
	I_MUTEX_PARENT2 = 5,
};

struct f_owner_ex {
	int type;
	__kernel_pid_t pid;
};

struct flock {
	short int l_type;
	short int l_whence;
	__kernel_off_t l_start;
	__kernel_off_t l_len;
	__kernel_pid_t l_pid;
};

struct flock64 {
	short int l_type;
	short int l_whence;
	__kernel_loff_t l_start;
	__kernel_loff_t l_len;
	__kernel_pid_t l_pid;
};

enum rw_hint {
	WRITE_LIFE_NOT_SET = 0,
	WRITE_LIFE_NONE = 1,
	WRITE_LIFE_SHORT = 2,
	WRITE_LIFE_MEDIUM = 3,
	WRITE_LIFE_LONG = 4,
	WRITE_LIFE_EXTREME = 5,
};

struct name_snapshot {
	struct qstr name;
	unsigned char inline_name[40];
};

struct saved {
	struct path link;
	struct delayed_call done;
	const char *name;
	unsigned int seq;
};

struct nameidata {
	struct path path;
	struct qstr last;
	struct path root;
	struct inode *inode;
	unsigned int flags;
	unsigned int state;
	unsigned int seq;
	unsigned int m_seq;
	unsigned int r_seq;
	int last_type;
	unsigned int depth;
	int total_link_count;
	struct saved *stack;
	struct saved internal[2];
	struct filename *name;
	struct nameidata *saved;
	unsigned int root_seq;
	int dfd;
	kuid_t dir_uid;
	umode_t dir_mode;
};

struct renamedata {
	struct user_namespace *old_mnt_userns;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct user_namespace *new_mnt_userns;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct inode **delegated_inode;
	unsigned int flags;
};

enum {
	LAST_NORM = 0,
	LAST_ROOT = 1,
	LAST_DOT = 2,
	LAST_DOTDOT = 3,
};

enum {
	WALK_TRAILING = 1,
	WALK_MORE = 2,
	WALK_NOFOLLOW = 4,
};

struct file_clone_range {
	__s64 src_fd;
	__u64 src_offset;
	__u64 src_length;
	__u64 dest_offset;
};

struct file_dedupe_range_info {
	__s64 dest_fd;
	__u64 dest_offset;
	__u64 bytes_deduped;
	__s32 status;
	__u32 reserved;
};

struct file_dedupe_range {
	__u64 src_offset;
	__u64 src_length;
	__u16 dest_count;
	__u16 reserved1;
	__u32 reserved2;
	struct file_dedupe_range_info info[0];
};

struct fsxattr {
	__u32 fsx_xflags;
	__u32 fsx_extsize;
	__u32 fsx_nextents;
	__u32 fsx_projid;
	__u32 fsx_cowextsize;
	unsigned char fsx_pad[8];
};

struct fiemap_extent;

struct fiemap_extent_info {
	unsigned int fi_flags;
	unsigned int fi_extents_mapped;
	unsigned int fi_extents_max;
	struct fiemap_extent *fi_extents_start;
};

struct fileattr {
	u32 flags;
	u32 fsx_xflags;
	u32 fsx_extsize;
	u32 fsx_nextents;
	u32 fsx_projid;
	u32 fsx_cowextsize;
	bool flags_valid: 1;
	bool fsx_valid: 1;
};

struct space_resv {
	__s16 l_type;
	__s16 l_whence;
	__s64 l_start;
	__s64 l_len;
	__s32 l_sysid;
	__u32 l_pid;
	__s32 l_pad[4];
};

struct fiemap_extent {
	__u64 fe_logical;
	__u64 fe_physical;
	__u64 fe_length;
	__u64 fe_reserved64[2];
	__u32 fe_flags;
	__u32 fe_reserved[3];
};

struct fiemap {
	__u64 fm_start;
	__u64 fm_length;
	__u32 fm_flags;
	__u32 fm_mapped_extents;
	__u32 fm_extent_count;
	__u32 fm_reserved;
	struct fiemap_extent fm_extents[0];
};

struct linux_dirent64 {
	u64 d_ino;
	s64 d_off;
	short unsigned int d_reclen;
	unsigned char d_type;
	char d_name[0];
};

struct linux_dirent {
	long unsigned int d_ino;
	long unsigned int d_off;
	short unsigned int d_reclen;
	char d_name[1];
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent *current_dir;
	int prev_reclen;
	int count;
	int error;
};

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 *current_dir;
	int prev_reclen;
	int count;
	int error;
};

struct poll_table_entry {
	struct file *filp;
	__poll_t key;
	wait_queue_entry_t wait;
	wait_queue_head_t *wait_address;
};

struct poll_table_page;

struct poll_wqueues {
	poll_table pt;
	struct poll_table_page *table;
	struct task_struct *polling_task;
	int triggered;
	int error;
	int inline_index;
	struct poll_table_entry inline_entries[18];
};

struct poll_table_page {
	struct poll_table_page *next;
	struct poll_table_entry *entry;
	struct poll_table_entry entries[0];
};

enum poll_time_type {
	PT_TIMEVAL = 0,
	PT_OLD_TIMEVAL = 1,
	PT_TIMESPEC = 2,
	PT_OLD_TIMESPEC = 3,
};

typedef struct {
	long unsigned int *in;
	long unsigned int *out;
	long unsigned int *ex;
	long unsigned int *res_in;
	long unsigned int *res_out;
	long unsigned int *res_ex;
} fd_set_bits;

struct sigset_argpack {
	sigset_t *p;
	size_t size;
};

struct poll_list {
	struct poll_list *next;
	int len;
	struct pollfd entries[0];
};

enum dentry_d_lock_class {
	DENTRY_D_LOCK_NORMAL = 0,
	DENTRY_D_LOCK_NESTED = 1,
};

struct dentry_stat_t {
	long int nr_dentry;
	long int nr_unused;
	long int age_limit;
	long int want_pages;
	long int nr_negative;
	long int dummy;
};

struct external_name {
	union {
		atomic_t count;
		struct callback_head head;
	} u;
	unsigned char name[0];
};

enum d_walk_ret {
	D_WALK_CONTINUE = 0,
	D_WALK_QUIT = 1,
	D_WALK_NORETRY = 2,
	D_WALK_SKIP = 3,
};

struct check_mount {
	struct vfsmount *mnt;
	unsigned int mounted;
};

struct select_data {
	struct dentry *start;
	union {
		long int found;
		struct dentry *victim;
	};
	struct list_head dispose;
};

struct inodes_stat_t {
	long int nr_inodes;
	long int nr_unused;
	long int dummy[5];
};

enum file_time_flags {
	S_ATIME = 1,
	S_MTIME = 2,
	S_CTIME = 4,
	S_VERSION = 8,
};

struct mount_attr {
	__u64 attr_set;
	__u64 attr_clr;
	__u64 propagation;
	__u64 userns_fd;
};

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
	struct mount cursor;
};

struct mount_kattr {
	unsigned int attr_set;
	unsigned int attr_clr;
	unsigned int propagation;
	unsigned int lookup_flags;
	bool recurse;
	struct user_namespace *mnt_userns;
};

enum umount_tree_flags {
	UMOUNT_SYNC = 1,
	UMOUNT_PROPAGATE = 2,
	UMOUNT_CONNECTED = 4,
};

struct simple_transaction_argresp {
	ssize_t size;
	char data[0];
};

enum utf8_normalization {
	UTF8_NFDI = 0,
	UTF8_NFDICF = 1,
	UTF8_NMAX = 2,
};

struct simple_attr {
	int (*get)(void *, u64 *);
	int (*set)(void *, u64);
	char get_buf[24];
	char set_buf[24];
	void *data;
	const char *fmt;
	struct mutex mutex;
};

struct wb_completion {
	atomic_t cnt;
	wait_queue_head_t *waitq;
};

struct wb_writeback_work {
	long int nr_pages;
	struct super_block *sb;
	enum writeback_sync_modes sync_mode;
	unsigned int tagged_writepages: 1;
	unsigned int for_kupdate: 1;
	unsigned int range_cyclic: 1;
	unsigned int for_background: 1;
	unsigned int for_sync: 1;
	unsigned int auto_free: 1;
	enum wb_reason reason;
	struct list_head list;
	struct wb_completion *done;
};

struct trace_event_raw_writeback_folio_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int index;
	char __data[0];
};

struct trace_event_raw_writeback_dirty_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int flags;
	char __data[0];
};

struct trace_event_raw_writeback_write_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	int sync_mode;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_work_class {
	struct trace_entry ent;
	char name[32];
	long int nr_pages;
	dev_t sb_dev;
	int sync_mode;
	int for_kupdate;
	int range_cyclic;
	int for_background;
	int reason;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_pages_written {
	struct trace_entry ent;
	long int pages;
	char __data[0];
};

struct trace_event_raw_writeback_class {
	struct trace_entry ent;
	char name[32];
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_bdi_register {
	struct trace_entry ent;
	char name[32];
	char __data[0];
};

struct trace_event_raw_wbc_class {
	struct trace_entry ent;
	char name[32];
	long int nr_to_write;
	long int pages_skipped;
	int sync_mode;
	int for_kupdate;
	int for_background;
	int for_reclaim;
	int range_cyclic;
	long int range_start;
	long int range_end;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_queue_io {
	struct trace_entry ent;
	char name[32];
	long unsigned int older;
	long int age;
	int moved;
	int reason;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_global_dirty_state {
	struct trace_entry ent;
	long unsigned int nr_dirty;
	long unsigned int nr_writeback;
	long unsigned int background_thresh;
	long unsigned int dirty_thresh;
	long unsigned int dirty_limit;
	long unsigned int nr_dirtied;
	long unsigned int nr_written;
	char __data[0];
};

struct trace_event_raw_bdi_dirty_ratelimit {
	struct trace_entry ent;
	char bdi[32];
	long unsigned int write_bw;
	long unsigned int avg_write_bw;
	long unsigned int dirty_rate;
	long unsigned int dirty_ratelimit;
	long unsigned int task_ratelimit;
	long unsigned int balanced_dirty_ratelimit;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_balance_dirty_pages {
	struct trace_entry ent;
	char bdi[32];
	long unsigned int limit;
	long unsigned int setpoint;
	long unsigned int dirty;
	long unsigned int bdi_setpoint;
	long unsigned int bdi_dirty;
	long unsigned int dirty_ratelimit;
	long unsigned int task_ratelimit;
	unsigned int dirtied;
	unsigned int dirtied_pause;
	long unsigned int paused;
	long int pause;
	long unsigned int period;
	long int think;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_sb_inodes_requeue {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int dirtied_when;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_single_inode_template {
	struct trace_entry ent;
	char name[32];
	ino_t ino;
	long unsigned int state;
	long unsigned int dirtied_when;
	long unsigned int writeback_index;
	long int nr_to_write;
	long unsigned int wrote;
	ino_t cgroup_ino;
	char __data[0];
};

struct trace_event_raw_writeback_inode_template {
	struct trace_entry ent;
	dev_t dev;
	ino_t ino;
	long unsigned int state;
	__u16 mode;
	long unsigned int dirtied_when;
	char __data[0];
};

struct trace_event_data_offsets_writeback_folio_template {};

struct trace_event_data_offsets_writeback_dirty_inode_template {};

struct trace_event_data_offsets_writeback_write_inode_template {};

struct trace_event_data_offsets_writeback_work_class {};

struct trace_event_data_offsets_writeback_pages_written {};

struct trace_event_data_offsets_writeback_class {};

struct trace_event_data_offsets_writeback_bdi_register {};

struct trace_event_data_offsets_wbc_class {};

struct trace_event_data_offsets_writeback_queue_io {};

struct trace_event_data_offsets_global_dirty_state {};

struct trace_event_data_offsets_bdi_dirty_ratelimit {};

struct trace_event_data_offsets_balance_dirty_pages {};

struct trace_event_data_offsets_writeback_sb_inodes_requeue {};

struct trace_event_data_offsets_writeback_single_inode_template {};

struct trace_event_data_offsets_writeback_inode_template {};

typedef void (*btf_trace_writeback_dirty_folio)(void *, struct folio *, struct address_space *);

typedef void (*btf_trace_folio_wait_writeback)(void *, struct folio *, struct address_space *);

typedef void (*btf_trace_writeback_mark_inode_dirty)(void *, struct inode *, int);

typedef void (*btf_trace_writeback_dirty_inode_start)(void *, struct inode *, int);

typedef void (*btf_trace_writeback_dirty_inode)(void *, struct inode *, int);

typedef void (*btf_trace_writeback_write_inode_start)(void *, struct inode *, struct writeback_control *);

typedef void (*btf_trace_writeback_write_inode)(void *, struct inode *, struct writeback_control *);

typedef void (*btf_trace_writeback_queue)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_exec)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_start)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_written)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_wait)(void *, struct bdi_writeback *, struct wb_writeback_work *);

typedef void (*btf_trace_writeback_pages_written)(void *, long int);

typedef void (*btf_trace_writeback_wake_background)(void *, struct bdi_writeback *);

typedef void (*btf_trace_writeback_bdi_register)(void *, struct backing_dev_info *);

typedef void (*btf_trace_wbc_writepage)(void *, struct writeback_control *, struct backing_dev_info *);

typedef void (*btf_trace_writeback_queue_io)(void *, struct bdi_writeback *, struct wb_writeback_work *, long unsigned int, int);

typedef void (*btf_trace_global_dirty_state)(void *, long unsigned int, long unsigned int);

typedef void (*btf_trace_bdi_dirty_ratelimit)(void *, struct bdi_writeback *, long unsigned int, long unsigned int);

typedef void (*btf_trace_balance_dirty_pages)(void *, struct bdi_writeback *, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long unsigned int, long int, long unsigned int);

typedef void (*btf_trace_writeback_sb_inodes_requeue)(void *, struct inode *);

typedef void (*btf_trace_writeback_single_inode_start)(void *, struct inode *, struct writeback_control *, long unsigned int);

typedef void (*btf_trace_writeback_single_inode)(void *, struct inode *, struct writeback_control *, long unsigned int);

typedef void (*btf_trace_writeback_lazytime)(void *, struct inode *);

typedef void (*btf_trace_writeback_lazytime_iput)(void *, struct inode *);

typedef void (*btf_trace_writeback_dirty_inode_enqueue)(void *, struct inode *);

typedef void (*btf_trace_sb_mark_inode_writeback)(void *, struct inode *);

typedef void (*btf_trace_sb_clear_inode_writeback)(void *, struct inode *);

struct splice_desc {
	size_t total_len;
	unsigned int len;
	unsigned int flags;
	union {
		void *userptr;
		struct file *file;
		void *data;
	} u;
	loff_t pos;
	loff_t *opos;
	size_t num_spliced;
	bool need_wakeup;
};

typedef int splice_actor(struct pipe_inode_info *, struct pipe_buffer *, struct splice_desc *);

typedef int splice_direct_actor(struct pipe_inode_info *, struct splice_desc *);

struct prepend_buffer {
	char *buf;
	int len;
};

struct fs_pin {
	wait_queue_head_t wait;
	int done;
	struct hlist_node s_list;
	struct hlist_node m_list;
	void (*kill)(struct fs_pin *);
};

typedef int __kernel_daddr_t;

struct ustat {
	__kernel_daddr_t f_tfree;
	long unsigned int f_tinode;
	char f_fname[6];
	char f_fpack[6];
};

struct statfs {
	__u32 f_type;
	__u32 f_bsize;
	__u32 f_blocks;
	__u32 f_bfree;
	__u32 f_bavail;
	__u32 f_files;
	__u32 f_ffree;
	__kernel_fsid_t f_fsid;
	__u32 f_namelen;
	__u32 f_frsize;
	__u32 f_flags;
	__u32 f_spare[4];
};

struct statfs64 {
	__u32 f_type;
	__u32 f_bsize;
	__u64 f_blocks;
	__u64 f_bfree;
	__u64 f_bavail;
	__u64 f_files;
	__u64 f_ffree;
	__kernel_fsid_t f_fsid;
	__u32 f_namelen;
	__u32 f_frsize;
	__u32 f_flags;
	__u32 f_spare[4];
};

struct ns_get_path_task_args {
	const struct proc_ns_operations *ns_ops;
	struct task_struct *task;
};

enum legacy_fs_param {
	LEGACY_FS_UNSET_PARAMS = 0,
	LEGACY_FS_MONOLITHIC_PARAMS = 1,
	LEGACY_FS_INDIVIDUAL_PARAMS = 2,
};

struct legacy_fs_context {
	char *legacy_data;
	size_t data_size;
	enum legacy_fs_param param_type;
};

enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0,
	FSCONFIG_SET_STRING = 1,
	FSCONFIG_SET_BINARY = 2,
	FSCONFIG_SET_PATH = 3,
	FSCONFIG_SET_PATH_EMPTY = 4,
	FSCONFIG_SET_FD = 5,
	FSCONFIG_CMD_CREATE = 6,
	FSCONFIG_CMD_RECONFIGURE = 7,
};

struct buffer_head;

typedef int get_block_t(struct inode *, sector_t, struct buffer_head *, int);

typedef void bh_end_io_t(struct buffer_head *, int);

struct buffer_head {
	long unsigned int b_state;
	struct buffer_head *b_this_page;
	struct page *b_page;
	sector_t b_blocknr;
	size_t b_size;
	char *b_data;
	struct block_device *b_bdev;
	bh_end_io_t *b_end_io;
	void *b_private;
	struct list_head b_assoc_buffers;
	struct address_space *b_assoc_map;
	atomic_t b_count;
	spinlock_t b_uptodate_lock;
};

typedef int dio_iodone_t(struct kiocb *, loff_t, ssize_t, void *);

typedef void dio_submit_t(struct bio *, struct inode *, loff_t);

enum {
	DIO_LOCKING = 1,
	DIO_SKIP_HOLES = 2,
};

enum {
	BIO_NO_PAGE_REF = 0,
	BIO_CLONED = 1,
	BIO_BOUNCED = 2,
	BIO_WORKINGSET = 3,
	BIO_QUIET = 4,
	BIO_CHAIN = 5,
	BIO_REFFED = 6,
	BIO_THROTTLED = 7,
	BIO_TRACE_COMPLETION = 8,
	BIO_CGROUP_ACCT = 9,
	BIO_QOS_THROTTLED = 10,
	BIO_QOS_MERGED = 11,
	BIO_REMAPPED = 12,
	BIO_ZONE_WRITE_LOCKED = 13,
	BIO_PERCPU_CACHE = 14,
	BIO_FLAG_LAST = 15,
};

enum bh_state_bits {
	BH_Uptodate = 0,
	BH_Dirty = 1,
	BH_Lock = 2,
	BH_Req = 3,
	BH_Mapped = 4,
	BH_New = 5,
	BH_Async_Read = 6,
	BH_Async_Write = 7,
	BH_Delay = 8,
	BH_Boundary = 9,
	BH_Write_EIO = 10,
	BH_Unwritten = 11,
	BH_Quiet = 12,
	BH_Meta = 13,
	BH_Prio = 14,
	BH_Defer_Completion = 15,
	BH_PrivateStart = 16,
};

struct dio_submit {
	struct bio *bio;
	unsigned int blkbits;
	unsigned int blkfactor;
	unsigned int start_zero_done;
	int pages_in_io;
	sector_t block_in_file;
	unsigned int blocks_available;
	int reap_counter;
	sector_t final_block_in_request;
	int boundary;
	get_block_t *get_block;
	dio_submit_t *submit_io;
	loff_t logical_offset_in_bio;
	sector_t final_block_in_bio;
	sector_t next_block_for_io;
	struct page *cur_page;
	unsigned int cur_page_offset;
	unsigned int cur_page_len;
	sector_t cur_page_block;
	loff_t cur_page_fs_offset;
	struct iov_iter *iter;
	unsigned int head;
	unsigned int tail;
	size_t from;
	size_t to;
};

struct dio {
	int flags;
	int op;
	int op_flags;
	struct gendisk *bio_disk;
	struct inode *inode;
	loff_t i_size;
	dio_iodone_t *end_io;
	void *private;
	spinlock_t bio_lock;
	int page_errors;
	int is_async;
	bool defer_completion;
	bool should_dirty;
	int io_error;
	long unsigned int refcount;
	struct bio *bio_list;
	struct task_struct *waiter;
	struct kiocb *iocb;
	ssize_t result;
	union {
		struct page *pages[64];
		struct work_struct complete_work;
	};
};

typedef __u32 blk_mq_req_flags_t;

struct dax_device;

struct iomap_page_ops;

struct iomap {
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	struct block_device *bdev;
	struct dax_device *dax_dev;
	void *inline_data;
	void *private;
	const struct iomap_page_ops *page_ops;
};

struct iomap_page_ops {
	int (*page_prepare)(struct inode *, loff_t, unsigned int);
	void (*page_done)(struct inode *, loff_t, unsigned int, struct page *);
};

enum hctx_type {
	HCTX_TYPE_DEFAULT = 0,
	HCTX_TYPE_READ = 1,
	HCTX_TYPE_POLL = 2,
	HCTX_MAX_TYPES = 3,
};

enum blktrace_act {
	__BLK_TA_QUEUE = 1,
	__BLK_TA_BACKMERGE = 2,
	__BLK_TA_FRONTMERGE = 3,
	__BLK_TA_GETRQ = 4,
	__BLK_TA_SLEEPRQ = 5,
	__BLK_TA_REQUEUE = 6,
	__BLK_TA_ISSUE = 7,
	__BLK_TA_COMPLETE = 8,
	__BLK_TA_PLUG = 9,
	__BLK_TA_UNPLUG_IO = 10,
	__BLK_TA_UNPLUG_TIMER = 11,
	__BLK_TA_INSERT = 12,
	__BLK_TA_SPLIT = 13,
	__BLK_TA_BOUNCE = 14,
	__BLK_TA_REMAP = 15,
	__BLK_TA_ABORT = 16,
	__BLK_TA_DRV_DATA = 17,
	__BLK_TA_CGROUP = 256,
};

struct decrypt_bh_ctx {
	struct work_struct work;
	struct buffer_head *bh;
};

struct bh_lru {
	struct buffer_head *bhs[16];
};

struct bh_accounting {
	int nr;
	int ratelimit;
};

struct bvec_iter_all {
	struct bio_vec bv;
	int idx;
	unsigned int done;
};

struct mpage_readpage_args {
	struct bio *bio;
	struct page *page;
	unsigned int nr_pages;
	bool is_readahead;
	sector_t last_block_in_bio;
	struct buffer_head map_bh;
	long unsigned int first_logical_block;
	get_block_t *get_block;
};

struct mpage_data {
	struct bio *bio;
	sector_t last_block_in_bio;
	get_block_t *get_block;
	unsigned int use_writepage;
};

typedef u32 nlink_t;

typedef int (*proc_write_t)(struct file *, char *, size_t);

struct proc_dir_entry {
	atomic_t in_use;
	refcount_t refcnt;
	struct list_head pde_openers;
	spinlock_t pde_unload_lock;
	struct completion *pde_unload_completion;
	const struct inode_operations *proc_iops;
	union {
		const struct proc_ops *proc_ops;
		const struct file_operations *proc_dir_ops;
	};
	const struct dentry_operations *proc_dops;
	union {
		const struct seq_operations *seq_ops;
		int (*single_show)(struct seq_file *, void *);
	};
	proc_write_t write;
	void *data;
	unsigned int state_size;
	unsigned int low_ino;
	nlink_t nlink;
	kuid_t uid;
	kgid_t gid;
	loff_t size;
	struct proc_dir_entry *parent;
	struct rb_root subdir;
	struct rb_node subdir_node;
	char *name;
	umode_t mode;
	u8 flags;
	u8 namelen;
	char inline_name[0];
};

union proc_op {
	int (*proc_get_link)(struct dentry *, struct path *);
	int (*proc_show)(struct seq_file *, struct pid_namespace *, struct pid *, struct task_struct *);
	const char *lsm;
};

struct proc_inode {
	struct pid *pid;
	unsigned int fd;
	union proc_op op;
	struct proc_dir_entry *pde;
	struct ctl_table_header *sysctl;
	struct ctl_table *sysctl_entry;
	struct hlist_node sibling_inodes;
	const struct proc_ns_operations *ns_ops;
	int: 32;
	struct inode vfs_inode;
};

struct proc_fs_opts {
	int flag;
	const char *str;
};

struct fsnotify_group;

struct fsnotify_iter_info;

struct fsnotify_mark;

struct fsnotify_event;

struct fsnotify_ops {
	int (*handle_event)(struct fsnotify_group *, u32, const void *, int, struct inode *, const struct qstr *, u32, struct fsnotify_iter_info *);
	int (*handle_inode_event)(struct fsnotify_mark *, u32, struct inode *, struct inode *, const struct qstr *, u32);
	void (*free_group_priv)(struct fsnotify_group *);
	void (*freeing_mark)(struct fsnotify_mark *, struct fsnotify_group *);
	void (*free_event)(struct fsnotify_group *, struct fsnotify_event *);
	void (*free_mark)(struct fsnotify_mark *);
};

struct inotify_group_private_data {
	spinlock_t idr_lock;
	struct idr idr;
	struct ucounts *ucounts;
};

struct fsnotify_group {
	const struct fsnotify_ops *ops;
	refcount_t refcnt;
	spinlock_t notification_lock;
	struct list_head notification_list;
	wait_queue_head_t notification_waitq;
	unsigned int q_len;
	unsigned int max_events;
	unsigned int priority;
	bool shutdown;
	struct mutex mark_mutex;
	atomic_t user_waits;
	struct list_head marks_list;
	struct fasync_struct *fsn_fa;
	struct fsnotify_event *overflow_event;
	struct mem_cgroup *memcg;
	union {
		void *private;
		struct inotify_group_private_data inotify_data;
	};
};

struct fsnotify_iter_info {
	struct fsnotify_mark *marks[5];
	unsigned int report_mask;
	int srcu_idx;
};

struct fsnotify_mark {
	__u32 mask;
	refcount_t refcnt;
	struct fsnotify_group *group;
	struct list_head g_list;
	spinlock_t lock;
	struct hlist_node obj_list;
	struct fsnotify_mark_connector *connector;
	__u32 ignored_mask;
	unsigned int flags;
};

struct fsnotify_event {
	struct list_head list;
};

struct fs_error_report {
	int error;
	struct inode *inode;
	struct super_block *sb;
};

enum fsnotify_obj_type {
	FSNOTIFY_OBJ_TYPE_ANY = 4294967295,
	FSNOTIFY_OBJ_TYPE_INODE = 0,
	FSNOTIFY_OBJ_TYPE_VFSMOUNT = 1,
	FSNOTIFY_OBJ_TYPE_SB = 2,
	FSNOTIFY_OBJ_TYPE_COUNT = 3,
	FSNOTIFY_OBJ_TYPE_DETACHED = 3,
};

struct inotify_inode_mark {
	struct fsnotify_mark fsn_mark;
	int wd;
};

struct dnotify_struct {
	struct dnotify_struct *dn_next;
	__u32 dn_mask;
	int dn_fd;
	struct file *dn_filp;
	fl_owner_t dn_owner;
};

struct dnotify_mark {
	struct fsnotify_mark fsn_mark;
	struct dnotify_struct *dn;
};

struct inotify_event_info {
	struct fsnotify_event fse;
	u32 mask;
	int wd;
	u32 sync_cookie;
	int name_len;
	char name[0];
};

struct inotify_event {
	__s32 wd;
	__u32 mask;
	__u32 cookie;
	__u32 len;
	char name[0];
};

struct wake_irq;

struct wakeup_source {
	const char *name;
	int id;
	struct list_head entry;
	spinlock_t lock;
	struct wake_irq *wakeirq;
	struct timer_list timer;
	long unsigned int timer_expires;
	ktime_t total_time;
	ktime_t max_time;
	ktime_t last_time;
	ktime_t start_prevent_time;
	ktime_t prevent_sleep_time;
	long unsigned int event_count;
	long unsigned int active_count;
	long unsigned int relax_count;
	long unsigned int expire_count;
	long unsigned int wakeup_count;
	struct device *dev;
	bool active: 1;
	bool autosleep_enabled: 1;
};

struct epoll_filefd {
	struct file *file;
	int fd;
};

struct epitem;

struct eppoll_entry {
	struct eppoll_entry *next;
	struct epitem *base;
	wait_queue_entry_t wait;
	wait_queue_head_t *whead;
};

struct eventpoll;

struct epitem {
	union {
		struct rb_node rbn;
		struct callback_head rcu;
	};
	struct list_head rdllink;
	struct epitem *next;
	struct epoll_filefd ffd;
	struct eppoll_entry *pwqlist;
	struct eventpoll *ep;
	struct hlist_node fllink;
	struct wakeup_source *ws;
	struct epoll_event event;
};

struct eventpoll {
	struct mutex mtx;
	wait_queue_head_t wq;
	wait_queue_head_t poll_wait;
	struct list_head rdllist;
	rwlock_t lock;
	struct rb_root_cached rbr;
	struct epitem *ovflist;
	struct wakeup_source *ws;
	struct user_struct *user;
	struct file *file;
	u64 gen;
	struct hlist_head refs;
	unsigned int napi_id;
};

struct ep_pqueue {
	poll_table pt;
	struct epitem *epi;
};

struct epitems_head {
	struct hlist_head epitems;
	struct epitems_head *next;
};

struct signalfd_siginfo {
	__u32 ssi_signo;
	__s32 ssi_errno;
	__s32 ssi_code;
	__u32 ssi_pid;
	__u32 ssi_uid;
	__s32 ssi_fd;
	__u32 ssi_tid;
	__u32 ssi_band;
	__u32 ssi_overrun;
	__u32 ssi_trapno;
	__s32 ssi_status;
	__s32 ssi_int;
	__u64 ssi_ptr;
	__u64 ssi_utime;
	__u64 ssi_stime;
	__u64 ssi_addr;
	__u16 ssi_addr_lsb;
	__u16 __pad2;
	__s32 ssi_syscall;
	__u64 ssi_call_addr;
	__u32 ssi_arch;
	__u8 __pad[28];
};

struct signalfd_ctx {
	sigset_t sigmask;
};

struct timerfd_ctx {
	union {
		struct hrtimer tmr;
		struct alarm alarm;
	} t;
	ktime_t tintv;
	ktime_t moffs;
	wait_queue_head_t wqh;
	u64 ticks;
	int clockid;
	short unsigned int expired;
	short unsigned int settime_flags;
	struct callback_head rcu;
	struct list_head clist;
	spinlock_t cancel_lock;
	bool might_cancel;
};

struct eventfd_ctx {
	struct kref kref;
	wait_queue_head_t wqh;
	__u64 count;
	unsigned int flags;
	int id;
};

struct kioctx;

struct kioctx_table {
	struct callback_head rcu;
	unsigned int nr;
	struct kioctx *table[0];
};

enum {
	IOCB_CMD_PREAD = 0,
	IOCB_CMD_PWRITE = 1,
	IOCB_CMD_FSYNC = 2,
	IOCB_CMD_FDSYNC = 3,
	IOCB_CMD_POLL = 5,
	IOCB_CMD_NOOP = 6,
	IOCB_CMD_PREADV = 7,
	IOCB_CMD_PWRITEV = 8,
};

typedef int kiocb_cancel_fn(struct kiocb *);

struct aio_ring {
	unsigned int id;
	unsigned int nr;
	unsigned int head;
	unsigned int tail;
	unsigned int magic;
	unsigned int compat_features;
	unsigned int incompat_features;
	unsigned int header_length;
	struct io_event io_events[0];
};

struct kioctx_cpu;

struct ctx_rq_wait;

struct kioctx {
	struct percpu_ref users;
	atomic_t dead;
	struct percpu_ref reqs;
	long unsigned int user_id;
	struct kioctx_cpu *cpu;
	unsigned int req_batch;
	unsigned int max_reqs;
	unsigned int nr_events;
	long unsigned int mmap_base;
	long unsigned int mmap_size;
	struct page **ring_pages;
	long int nr_pages;
	struct rcu_work free_rwork;
	struct ctx_rq_wait *rq_wait;
	struct {
		atomic_t reqs_available;
	};
	struct {
		spinlock_t ctx_lock;
		struct list_head active_reqs;
	};
	struct {
		struct mutex ring_lock;
		wait_queue_head_t wait;
	};
	struct {
		unsigned int tail;
		unsigned int completed_events;
		spinlock_t completion_lock;
	};
	struct page *internal_pages[8];
	struct file *aio_ring_file;
	unsigned int id;
};

struct kioctx_cpu {
	unsigned int reqs_available;
};

struct ctx_rq_wait {
	struct completion comp;
	atomic_t count;
};

struct fsync_iocb {
	struct file *file;
	struct work_struct work;
	bool datasync;
	struct cred *creds;
};

struct poll_iocb {
	struct file *file;
	struct wait_queue_head *head;
	__poll_t events;
	bool cancelled;
	bool work_scheduled;
	bool work_need_resched;
	struct wait_queue_entry wait;
	struct work_struct work;
};

struct eventfd_ctx;

struct aio_kiocb {
	union {
		struct file *ki_filp;
		struct kiocb rw;
		struct fsync_iocb fsync;
		struct poll_iocb poll;
	};
	struct kioctx *ki_ctx;
	kiocb_cancel_fn *ki_cancel;
	struct io_event ki_res;
	struct list_head ki_list;
	refcount_t ki_refcnt;
	struct eventfd_ctx *ki_eventfd;
};

struct aio_poll_table {
	struct poll_table_struct pt;
	struct aio_kiocb *iocb;
	bool queued;
	int error;
};

struct __aio_sigset {
	const sigset_t *sigmask;
	size_t sigsetsize;
};

enum {
	IO_WQ_BOUND = 0,
	IO_WQ_UNBOUND = 1,
};

enum {
	IO_WQ_WORK_CANCEL = 1,
	IO_WQ_WORK_HASHED = 2,
	IO_WQ_WORK_UNBOUND = 4,
	IO_WQ_WORK_CONCURRENT = 16,
	IO_WQ_HASH_SHIFT = 24,
};

enum io_wq_cancel {
	IO_WQ_CANCEL_OK = 0,
	IO_WQ_CANCEL_RUNNING = 1,
	IO_WQ_CANCEL_NOTFOUND = 2,
};

struct io_wq_work_node {
	struct io_wq_work_node *next;
};

struct io_wq_work_list {
	struct io_wq_work_node *first;
	struct io_wq_work_node *last;
};

struct io_wq_work {
	struct io_wq_work_node list;
	unsigned int flags;
};

typedef struct io_wq_work *free_work_fn(struct io_wq_work *);

typedef void io_wq_work_fn(struct io_wq_work *);

struct io_wq_hash {
	refcount_t refs;
	long unsigned int map;
	struct wait_queue_head wait;
};

struct io_wq_data {
	struct io_wq_hash *hash;
	struct task_struct *task;
	io_wq_work_fn *do_work;
	free_work_fn *free_work;
};

typedef bool work_cancel_fn(struct io_wq_work *, void *);

enum {
	IO_WORKER_F_UP = 1,
	IO_WORKER_F_RUNNING = 2,
	IO_WORKER_F_FREE = 4,
	IO_WORKER_F_BOUND = 8,
};

enum {
	IO_WQ_BIT_EXIT = 0,
};

enum {
	IO_ACCT_STALLED_BIT = 0,
};

struct io_wqe;

struct io_worker {
	refcount_t ref;
	unsigned int flags;
	struct hlist_nulls_node nulls_node;
	struct list_head all_list;
	struct task_struct *task;
	struct io_wqe *wqe;
	struct io_wq_work *cur_work;
	struct io_wq_work *next_work;
	raw_spinlock_t lock;
	struct completion ref_done;
	long unsigned int create_state;
	struct callback_head create_work;
	int create_index;
	union {
		struct callback_head rcu;
		struct work_struct work;
	};
};

struct io_wqe_acct {
	unsigned int nr_workers;
	unsigned int max_workers;
	int index;
	atomic_t nr_running;
	raw_spinlock_t lock;
	struct io_wq_work_list work_list;
	long unsigned int flags;
};

struct io_wq;

struct io_wqe {
	raw_spinlock_t lock;
	struct io_wqe_acct acct[2];
	int node;
	struct hlist_nulls_head free_list;
	struct list_head all_list;
	struct wait_queue_entry wait;
	struct io_wq *wq;
	struct io_wq_work *hash_tail[32];
	cpumask_var_t cpu_mask;
};

enum {
	IO_WQ_ACCT_BOUND = 0,
	IO_WQ_ACCT_UNBOUND = 1,
	IO_WQ_ACCT_NR = 2,
};

struct io_wq {
	long unsigned int state;
	free_work_fn *free_work;
	io_wq_work_fn *do_work;
	struct io_wq_hash *hash;
	atomic_t worker_refs;
	struct completion worker_done;
	struct hlist_node cpuhp_node;
	struct task_struct *task;
	struct io_wqe *wqes[0];
};

struct io_cb_cancel_data {
	work_cancel_fn *fn;
	void *data;
	int nr_running;
	int nr_pending;
	bool cancel_all;
};

struct online_data {
	unsigned int cpu;
	bool online;
};

struct xa_limit {
	u32 max;
	u32 min;
};

struct io_wq;

struct io_ring_ctx;

struct io_uring_task {
	int cached_refs;
	struct xarray xa;
	struct wait_queue_head wait;
	const struct io_ring_ctx *last;
	struct io_wq *io_wq;
	struct percpu_counter inflight;
	atomic_t in_idle;
	spinlock_t task_lock;
	struct io_wq_work_list task_list;
	struct io_wq_work_list prior_task_list;
	struct callback_head task_work;
	struct file **registered_rings;
	bool task_running;
};

enum {
	PERCPU_REF_INIT_ATOMIC = 1,
	PERCPU_REF_INIT_DEAD = 2,
	PERCPU_REF_ALLOW_REINIT = 4,
};

struct iov_iter_state {
	size_t iov_offset;
	size_t count;
	long unsigned int nr_segs;
};

struct __kernel_sockaddr_storage {
	union {
		struct {
			__kernel_sa_family_t ss_family;
			char __data[126];
		};
		void *__align;
	};
};

struct user_msghdr {
	void *msg_name;
	int msg_namelen;
	struct iovec *msg_iov;
	__kernel_size_t msg_iovlen;
	void *msg_control;
	__kernel_size_t msg_controllen;
	unsigned int msg_flags;
};

typedef u32 compat_size_t;

typedef s32 compat_int_t;

typedef u32 compat_uint_t;

typedef u32 compat_ulong_t;

typedef u32 compat_uptr_t;

struct compat_msghdr {
	compat_uptr_t msg_name;
	compat_int_t msg_namelen;
	compat_uptr_t msg_iov;
	compat_size_t msg_iovlen;
	compat_uptr_t msg_control;
	compat_size_t msg_controllen;
	compat_uint_t msg_flags;
};

struct scm_fp_list {
	short int count;
	short int max;
	struct user_struct *user;
	struct file *fp[253];
};

struct unix_skb_parms {
	struct pid *pid;
	kuid_t uid;
	kgid_t gid;
	struct scm_fp_list *fp;
	u32 consumed;
};

struct io_uring_sqe {
	__u8 opcode;
	__u8 flags;
	__u16 ioprio;
	__s32 fd;
	union {
		__u64 off;
		__u64 addr2;
	};
	union {
		__u64 addr;
		__u64 splice_off_in;
	};
	__u32 len;
	union {
		__kernel_rwf_t rw_flags;
		__u32 fsync_flags;
		__u16 poll_events;
		__u32 poll32_events;
		__u32 sync_range_flags;
		__u32 msg_flags;
		__u32 timeout_flags;
		__u32 accept_flags;
		__u32 cancel_flags;
		__u32 open_flags;
		__u32 statx_flags;
		__u32 fadvise_advice;
		__u32 splice_flags;
		__u32 rename_flags;
		__u32 unlink_flags;
		__u32 hardlink_flags;
	};
	__u64 user_data;
	union {
		__u16 buf_index;
		__u16 buf_group;
	};
	__u16 personality;
	union {
		__s32 splice_fd_in;
		__u32 file_index;
	};
	__u64 __pad2[2];
};

enum {
	IOSQE_FIXED_FILE_BIT = 0,
	IOSQE_IO_DRAIN_BIT = 1,
	IOSQE_IO_LINK_BIT = 2,
	IOSQE_IO_HARDLINK_BIT = 3,
	IOSQE_ASYNC_BIT = 4,
	IOSQE_BUFFER_SELECT_BIT = 5,
	IOSQE_CQE_SKIP_SUCCESS_BIT = 6,
};

enum {
	IORING_OP_NOP = 0,
	IORING_OP_READV = 1,
	IORING_OP_WRITEV = 2,
	IORING_OP_FSYNC = 3,
	IORING_OP_READ_FIXED = 4,
	IORING_OP_WRITE_FIXED = 5,
	IORING_OP_POLL_ADD = 6,
	IORING_OP_POLL_REMOVE = 7,
	IORING_OP_SYNC_FILE_RANGE = 8,
	IORING_OP_SENDMSG = 9,
	IORING_OP_RECVMSG = 10,
	IORING_OP_TIMEOUT = 11,
	IORING_OP_TIMEOUT_REMOVE = 12,
	IORING_OP_ACCEPT = 13,
	IORING_OP_ASYNC_CANCEL = 14,
	IORING_OP_LINK_TIMEOUT = 15,
	IORING_OP_CONNECT = 16,
	IORING_OP_FALLOCATE = 17,
	IORING_OP_OPENAT = 18,
	IORING_OP_CLOSE = 19,
	IORING_OP_FILES_UPDATE = 20,
	IORING_OP_STATX = 21,
	IORING_OP_READ = 22,
	IORING_OP_WRITE = 23,
	IORING_OP_FADVISE = 24,
	IORING_OP_MADVISE = 25,
	IORING_OP_SEND = 26,
	IORING_OP_RECV = 27,
	IORING_OP_OPENAT2 = 28,
	IORING_OP_EPOLL_CTL = 29,
	IORING_OP_SPLICE = 30,
	IORING_OP_PROVIDE_BUFFERS = 31,
	IORING_OP_REMOVE_BUFFERS = 32,
	IORING_OP_TEE = 33,
	IORING_OP_SHUTDOWN = 34,
	IORING_OP_RENAMEAT = 35,
	IORING_OP_UNLINKAT = 36,
	IORING_OP_MKDIRAT = 37,
	IORING_OP_SYMLINKAT = 38,
	IORING_OP_LINKAT = 39,
	IORING_OP_MSG_RING = 40,
	IORING_OP_LAST = 41,
};

struct io_uring_cqe {
	__u64 user_data;
	__s32 res;
	__u32 flags;
};

enum {
	IORING_CQE_BUFFER_SHIFT = 16,
};

struct io_sqring_offsets {
	__u32 head;
	__u32 tail;
	__u32 ring_mask;
	__u32 ring_entries;
	__u32 flags;
	__u32 dropped;
	__u32 array;
	__u32 resv1;
	__u64 resv2;
};

struct io_cqring_offsets {
	__u32 head;
	__u32 tail;
	__u32 ring_mask;
	__u32 ring_entries;
	__u32 overflow;
	__u32 cqes;
	__u32 flags;
	__u32 resv1;
	__u64 resv2;
};

struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 features;
	__u32 wq_fd;
	__u32 resv[3];
	struct io_sqring_offsets sq_off;
	struct io_cqring_offsets cq_off;
};

enum {
	IORING_REGISTER_BUFFERS = 0,
	IORING_UNREGISTER_BUFFERS = 1,
	IORING_REGISTER_FILES = 2,
	IORING_UNREGISTER_FILES = 3,
	IORING_REGISTER_EVENTFD = 4,
	IORING_UNREGISTER_EVENTFD = 5,
	IORING_REGISTER_FILES_UPDATE = 6,
	IORING_REGISTER_EVENTFD_ASYNC = 7,
	IORING_REGISTER_PROBE = 8,
	IORING_REGISTER_PERSONALITY = 9,
	IORING_UNREGISTER_PERSONALITY = 10,
	IORING_REGISTER_RESTRICTIONS = 11,
	IORING_REGISTER_ENABLE_RINGS = 12,
	IORING_REGISTER_FILES2 = 13,
	IORING_REGISTER_FILES_UPDATE2 = 14,
	IORING_REGISTER_BUFFERS2 = 15,
	IORING_REGISTER_BUFFERS_UPDATE = 16,
	IORING_REGISTER_IOWQ_AFF = 17,
	IORING_UNREGISTER_IOWQ_AFF = 18,
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19,
	IORING_REGISTER_RING_FDS = 20,
	IORING_UNREGISTER_RING_FDS = 21,
	IORING_REGISTER_LAST = 22,
};

struct io_uring_rsrc_register {
	__u32 nr;
	__u32 resv;
	__u64 resv2;
	__u64 data;
	__u64 tags;
};

struct io_uring_rsrc_update {
	__u32 offset;
	__u32 resv;
	__u64 data;
};

struct io_uring_rsrc_update2 {
	__u32 offset;
	__u32 resv;
	__u64 data;
	__u64 tags;
	__u32 nr;
	__u32 resv2;
};

struct io_uring_probe_op {
	__u8 op;
	__u8 resv;
	__u16 flags;
	__u32 resv2;
};

struct io_uring_probe {
	__u8 last_op;
	__u8 ops_len;
	__u16 resv;
	__u32 resv2[3];
	struct io_uring_probe_op ops[0];
};

struct io_uring_restriction {
	__u16 opcode;
	union {
		__u8 register_op;
		__u8 sqe_op;
		__u8 sqe_flags;
	};
	__u8 resv;
	__u32 resv2[3];
};

enum {
	IORING_RESTRICTION_REGISTER_OP = 0,
	IORING_RESTRICTION_SQE_OP = 1,
	IORING_RESTRICTION_SQE_FLAGS_ALLOWED = 2,
	IORING_RESTRICTION_SQE_FLAGS_REQUIRED = 3,
	IORING_RESTRICTION_LAST = 4,
};

struct io_uring_getevents_arg {
	__u64 sigmask;
	__u32 sigmask_sz;
	__u32 pad;
	__u64 ts;
};

struct trace_event_raw_io_uring_create {
	struct trace_entry ent;
	int fd;
	void *ctx;
	u32 sq_entries;
	u32 cq_entries;
	u32 flags;
	char __data[0];
};

struct trace_event_raw_io_uring_register {
	struct trace_entry ent;
	void *ctx;
	unsigned int opcode;
	unsigned int nr_files;
	unsigned int nr_bufs;
	long int ret;
	char __data[0];
};

struct trace_event_raw_io_uring_file_get {
	struct trace_entry ent;
	void *ctx;
	void *req;
	u64 user_data;
	int fd;
	char __data[0];
};

struct trace_event_raw_io_uring_queue_async_work {
	struct trace_entry ent;
	void *ctx;
	void *req;
	u64 user_data;
	u8 opcode;
	unsigned int flags;
	struct io_wq_work *work;
	int rw;
	char __data[0];
};

struct trace_event_raw_io_uring_defer {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int data;
	u8 opcode;
	char __data[0];
};

struct trace_event_raw_io_uring_link {
	struct trace_entry ent;
	void *ctx;
	void *req;
	void *target_req;
	char __data[0];
};

struct trace_event_raw_io_uring_cqring_wait {
	struct trace_entry ent;
	void *ctx;
	int min_events;
	char __data[0];
};

struct trace_event_raw_io_uring_fail_link {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int user_data;
	u8 opcode;
	void *link;
	char __data[0];
};

struct trace_event_raw_io_uring_complete {
	struct trace_entry ent;
	void *ctx;
	void *req;
	u64 user_data;
	int res;
	unsigned int cflags;
	char __data[0];
};

struct trace_event_raw_io_uring_submit_sqe {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int user_data;
	u8 opcode;
	u32 flags;
	bool force_nonblock;
	bool sq_thread;
	char __data[0];
};

struct trace_event_raw_io_uring_poll_arm {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int user_data;
	u8 opcode;
	int mask;
	int events;
	char __data[0];
};

struct trace_event_raw_io_uring_task_add {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int user_data;
	u8 opcode;
	int mask;
	char __data[0];
};

struct trace_event_raw_io_uring_req_failed {
	struct trace_entry ent;
	void *ctx;
	void *req;
	long long unsigned int user_data;
	u8 opcode;
	u8 flags;
	u8 ioprio;
	u64 off;
	u64 addr;
	u32 len;
	u32 op_flags;
	u16 buf_index;
	u16 personality;
	u32 file_index;
	u64 pad1;
	u64 pad2;
	int error;
	char __data[0];
};

struct trace_event_data_offsets_io_uring_create {};

struct trace_event_data_offsets_io_uring_register {};

struct trace_event_data_offsets_io_uring_file_get {};

struct trace_event_data_offsets_io_uring_queue_async_work {};

struct trace_event_data_offsets_io_uring_defer {};

struct trace_event_data_offsets_io_uring_link {};

struct trace_event_data_offsets_io_uring_cqring_wait {};

struct trace_event_data_offsets_io_uring_fail_link {};

struct trace_event_data_offsets_io_uring_complete {};

struct trace_event_data_offsets_io_uring_submit_sqe {};

struct trace_event_data_offsets_io_uring_poll_arm {};

struct trace_event_data_offsets_io_uring_task_add {};

struct trace_event_data_offsets_io_uring_req_failed {};

typedef void (*btf_trace_io_uring_create)(void *, int, void *, u32, u32, u32);

typedef void (*btf_trace_io_uring_register)(void *, void *, unsigned int, unsigned int, unsigned int, long int);

typedef void (*btf_trace_io_uring_file_get)(void *, void *, void *, long long unsigned int, int);

typedef void (*btf_trace_io_uring_queue_async_work)(void *, void *, void *, long long unsigned int, u8, unsigned int, struct io_wq_work *, int);

typedef void (*btf_trace_io_uring_defer)(void *, void *, void *, long long unsigned int, u8);

typedef void (*btf_trace_io_uring_link)(void *, void *, void *, void *);

typedef void (*btf_trace_io_uring_cqring_wait)(void *, void *, int);

typedef void (*btf_trace_io_uring_fail_link)(void *, void *, void *, long long unsigned int, u8, void *);

typedef void (*btf_trace_io_uring_complete)(void *, void *, void *, u64, int, unsigned int);

typedef void (*btf_trace_io_uring_submit_sqe)(void *, void *, void *, long long unsigned int, u8, u32, bool, bool);

typedef void (*btf_trace_io_uring_poll_arm)(void *, void *, void *, u64, u8, int, int);

typedef void (*btf_trace_io_uring_task_add)(void *, void *, void *, long long unsigned int, u8, int);

typedef void (*btf_trace_io_uring_req_failed)(void *, const struct io_uring_sqe *, void *, void *, int);

struct io_uring {
	u32 head;
	u32 tail;
};

struct io_rings {
	struct io_uring sq;
	struct io_uring cq;
	u32 sq_ring_mask;
	u32 cq_ring_mask;
	u32 sq_ring_entries;
	u32 cq_ring_entries;
	u32 sq_dropped;
	u32 sq_flags;
	u32 cq_flags;
	u32 cq_overflow;
	struct io_uring_cqe cqes[0];
};

enum io_uring_cmd_flags {
	IO_URING_F_COMPLETE_DEFER = 1,
	IO_URING_F_UNLOCKED = 2,
	IO_URING_F_NONBLOCK = 2147483648,
};

struct io_mapped_ubuf {
	u64 ubuf;
	u64 ubuf_end;
	unsigned int nr_bvecs;
	long unsigned int acct_pages;
	struct bio_vec bvec[0];
};

struct io_overflow_cqe {
	struct io_uring_cqe cqe;
	struct list_head list;
};

struct io_fixed_file {
	long unsigned int file_ptr;
};

struct io_rsrc_put {
	struct list_head list;
	u64 tag;
	union {
		void *rsrc;
		struct file *file;
		struct io_mapped_ubuf *buf;
	};
};

struct io_file_table {
	struct io_fixed_file *files;
};

struct io_rsrc_data;

struct io_rsrc_node {
	struct percpu_ref refs;
	struct list_head node;
	struct list_head rsrc_list;
	struct io_rsrc_data *rsrc_data;
	struct llist_node llist;
	bool done;
};

typedef void rsrc_put_fn(struct io_ring_ctx *, struct io_rsrc_put *);

struct io_rsrc_data {
	struct io_ring_ctx *ctx;
	u64 **tags;
	unsigned int nr;
	rsrc_put_fn *do_put;
	atomic_t refs;
	struct completion done;
	bool quiesce;
};

struct io_kiocb;

struct io_submit_link {
	struct io_kiocb *head;
	struct io_kiocb *last;
};

struct io_submit_state {
	struct io_wq_work_node free_list;
	struct io_wq_work_list compl_reqs;
	struct io_submit_link link;
	bool plug_started;
	bool need_plug;
	bool flush_cqes;
	short unsigned int submit_nr;
	struct blk_plug plug;
};

struct io_restriction {
	long unsigned int register_op[1];
	long unsigned int sqe_op[2];
	u8 sqe_flags_allowed;
	u8 sqe_flags_required;
	bool registered;
};

struct io_sq_data;

struct io_ev_fd;

struct io_ring_ctx {
	struct {
		struct percpu_ref refs;
		struct io_rings *rings;
		unsigned int flags;
		unsigned int compat: 1;
		unsigned int drain_next: 1;
		unsigned int restricted: 1;
		unsigned int off_timeout_used: 1;
		unsigned int drain_active: 1;
		unsigned int drain_disabled: 1;
		unsigned int has_evfd: 1;
	};
	struct {
		struct mutex uring_lock;
		u32 *sq_array;
		struct io_uring_sqe *sq_sqes;
		unsigned int cached_sq_head;
		unsigned int sq_entries;
		struct list_head defer_list;
		struct io_rsrc_node *rsrc_node;
		int rsrc_cached_refs;
		struct io_file_table file_table;
		unsigned int nr_user_files;
		unsigned int nr_user_bufs;
		struct io_mapped_ubuf **user_bufs;
		struct io_submit_state submit_state;
		struct list_head timeout_list;
		struct list_head ltimeout_list;
		struct list_head cq_overflow_list;
		struct list_head *io_buffers;
		struct list_head io_buffers_cache;
		struct list_head apoll_cache;
		struct xarray personalities;
		u32 pers_next;
		unsigned int sq_thread_idle;
	};
	struct io_wq_work_list locked_free_list;
	unsigned int locked_free_nr;
	const struct cred *sq_creds;
	struct io_sq_data *sq_data;
	struct wait_queue_head sqo_sq_wait;
	struct list_head sqd_list;
	long unsigned int check_cq_overflow;
	struct {
		unsigned int cached_cq_tail;
		unsigned int cq_entries;
		struct io_ev_fd *io_ev_fd;
		struct wait_queue_head cq_wait;
		unsigned int cq_extra;
		atomic_t cq_timeouts;
		unsigned int cq_last_tm_flush;
	};
	struct {
		spinlock_t completion_lock;
		spinlock_t timeout_lock;
		struct io_wq_work_list iopoll_list;
		struct hlist_head *cancel_hash;
		unsigned int cancel_hash_bits;
		bool poll_multi_queue;
		struct list_head io_buffers_comp;
	};
	struct io_restriction restrictions;
	struct {
		struct io_rsrc_node *rsrc_backup_node;
		struct io_mapped_ubuf *dummy_ubuf;
		struct io_rsrc_data *file_data;
		struct io_rsrc_data *buf_data;
		struct delayed_work rsrc_put_work;
		struct llist_head rsrc_put_llist;
		struct list_head rsrc_ref_list;
		spinlock_t rsrc_ref_lock;
		struct list_head io_buffers_pages;
	};
	struct {
		struct socket *ring_sock;
		struct io_wq_hash *hash_map;
		struct user_struct *user;
		struct mm_struct *mm_account;
		struct llist_head fallback_llist;
		struct delayed_work fallback_work;
		struct work_struct exit_work;
		struct list_head tctx_list;
		struct completion ref_comp;
		u32 iowq_limits[2];
		bool iowq_limits_set;
	};
};

struct io_buffer_list {
	struct list_head list;
	struct list_head buf_list;
	__u16 bgid;
};

struct io_buffer {
	struct list_head list;
	__u64 addr;
	__u32 len;
	__u16 bid;
	__u16 bgid;
};

enum {
	IO_SQ_THREAD_SHOULD_STOP = 0,
	IO_SQ_THREAD_SHOULD_PARK = 1,
};

struct io_sq_data {
	refcount_t refs;
	atomic_t park_pending;
	struct mutex lock;
	struct list_head ctx_list;
	struct task_struct *thread;
	struct wait_queue_head wait;
	unsigned int sq_thread_idle;
	int sq_cpu;
	pid_t task_pid;
	pid_t task_tgid;
	long unsigned int state;
	struct completion exited;
};

struct io_rw {
	struct kiocb kiocb;
	u64 addr;
	u32 len;
	u32 flags;
};

struct io_poll_iocb {
	struct file *file;
	struct wait_queue_head *head;
	__poll_t events;
	struct wait_queue_entry wait;
};

struct io_poll_update {
	struct file *file;
	u64 old_user_data;
	u64 new_user_data;
	__poll_t events;
	bool update_events;
	bool update_user_data;
};

struct io_accept {
	struct file *file;
	struct sockaddr *addr;
	int *addr_len;
	int flags;
	u32 file_slot;
	long unsigned int nofile;
};

struct io_sync {
	struct file *file;
	loff_t len;
	loff_t off;
	int flags;
	int mode;
};

struct io_cancel {
	struct file *file;
	u64 addr;
};

struct io_timeout {
	struct file *file;
	u32 off;
	u32 target_seq;
	struct list_head list;
	struct io_kiocb *head;
	struct io_kiocb *prev;
};

struct io_timeout_rem {
	struct file *file;
	u64 addr;
	struct timespec64 ts;
	u32 flags;
	bool ltimeout;
};

struct io_connect {
	struct file *file;
	struct sockaddr *addr;
	int addr_len;
};

struct io_sr_msg {
	struct file *file;
	union {
		struct compat_msghdr *umsg_compat;
		struct user_msghdr *umsg;
		void *buf;
	};
	int msg_flags;
	int bgid;
	size_t len;
	size_t done_io;
};

struct io_open {
	struct file *file;
	int dfd;
	u32 file_slot;
	struct filename *filename;
	struct open_how how;
	long unsigned int nofile;
};

struct io_close {
	struct file *file;
	int fd;
	u32 file_slot;
};

struct io_rsrc_update {
	struct file *file;
	u64 arg;
	u32 nr_args;
	u32 offset;
};

struct io_fadvise {
	struct file *file;
	u64 offset;
	u32 len;
	u32 advice;
};

struct io_madvise {
	struct file *file;
	u64 addr;
	u32 len;
	u32 advice;
};

struct io_epoll {
	struct file *file;
	int epfd;
	int op;
	int fd;
	struct epoll_event event;
};

struct io_splice {
	struct file *file_out;
	loff_t off_out;
	loff_t off_in;
	u64 len;
	int splice_fd_in;
	unsigned int flags;
};

struct io_provide_buf {
	struct file *file;
	__u64 addr;
	__u32 len;
	__u32 bgid;
	__u16 nbufs;
	__u16 bid;
};

struct io_statx {
	struct file *file;
	int dfd;
	unsigned int mask;
	unsigned int flags;
	struct filename *filename;
	struct statx *buffer;
};

struct io_shutdown {
	struct file *file;
	int how;
};

struct io_rename {
	struct file *file;
	int old_dfd;
	int new_dfd;
	struct filename *oldpath;
	struct filename *newpath;
	int flags;
};

struct io_unlink {
	struct file *file;
	int dfd;
	int flags;
	struct filename *filename;
};

struct io_mkdir {
	struct file *file;
	int dfd;
	umode_t mode;
	struct filename *filename;
};

struct io_symlink {
	struct file *file;
	int new_dfd;
	struct filename *oldpath;
	struct filename *newpath;
};

struct io_hardlink {
	struct file *file;
	int old_dfd;
	int new_dfd;
	struct filename *oldpath;
	struct filename *newpath;
	int flags;
};

struct io_msg {
	struct file *file;
	u64 user_data;
	u32 len;
};

typedef void (*io_req_tw_func_t)(struct io_kiocb *, bool *);

struct io_task_work {
	union {
		struct io_wq_work_node node;
		struct llist_node fallback_node;
	};
	io_req_tw_func_t func;
};

struct async_poll;

struct io_kiocb {
	union {
		struct file *file;
		struct io_rw rw;
		struct io_poll_iocb poll;
		struct io_poll_update poll_update;
		struct io_accept accept;
		struct io_sync sync;
		struct io_cancel cancel;
		struct io_timeout timeout;
		struct io_timeout_rem timeout_rem;
		struct io_connect connect;
		struct io_sr_msg sr_msg;
		struct io_open open;
		struct io_close close;
		struct io_rsrc_update rsrc_update;
		struct io_fadvise fadvise;
		struct io_madvise madvise;
		struct io_epoll epoll;
		struct io_splice splice;
		struct io_provide_buf pbuf;
		struct io_statx statx;
		struct io_shutdown shutdown;
		struct io_rename rename;
		struct io_unlink unlink;
		struct io_mkdir mkdir;
		struct io_symlink symlink;
		struct io_hardlink hardlink;
		struct io_msg msg;
	};
	u8 opcode;
	u8 iopoll_completed;
	u16 buf_index;
	unsigned int flags;
	u64 user_data;
	u32 result;
	union {
		u32 cflags;
		int fd;
	};
	struct io_ring_ctx *ctx;
	struct task_struct *task;
	struct percpu_ref *fixed_rsrc_refs;
	struct io_mapped_ubuf *imu;
	union {
		struct io_wq_work_node comp_list;
		int apoll_events;
	};
	atomic_t refs;
	atomic_t poll_refs;
	struct io_task_work io_task_work;
	struct hlist_node hash_node;
	struct async_poll *apoll;
	void *async_data;
	struct io_buffer *kbuf;
	struct io_kiocb *link;
	const struct cred *creds;
	struct io_wq_work work;
};

struct io_ev_fd {
	struct eventfd_ctx *cq_ev_fd;
	unsigned int eventfd_async: 1;
	struct callback_head rcu;
};

struct io_timeout_data {
	struct io_kiocb *req;
	struct hrtimer timer;
	struct timespec64 ts;
	enum hrtimer_mode mode;
	u32 flags;
};

struct io_async_connect {
	struct __kernel_sockaddr_storage address;
};

struct io_async_msghdr {
	struct iovec fast_iov[8];
	struct iovec *free_iov;
	struct sockaddr *uaddr;
	struct msghdr msg;
	struct __kernel_sockaddr_storage addr;
};

struct io_rw_state {
	struct iov_iter iter;
	struct iov_iter_state iter_state;
	struct iovec fast_iov[8];
};

struct io_async_rw {
	struct io_rw_state s;
	const struct iovec *free_iovec;
	size_t bytes_done;
	struct wait_page_queue wpq;
};

enum {
	REQ_F_FIXED_FILE_BIT = 0,
	REQ_F_IO_DRAIN_BIT = 1,
	REQ_F_LINK_BIT = 2,
	REQ_F_HARDLINK_BIT = 3,
	REQ_F_FORCE_ASYNC_BIT = 4,
	REQ_F_BUFFER_SELECT_BIT = 5,
	REQ_F_CQE_SKIP_BIT = 6,
	REQ_F_FAIL_BIT = 8,
	REQ_F_INFLIGHT_BIT = 9,
	REQ_F_CUR_POS_BIT = 10,
	REQ_F_NOWAIT_BIT = 11,
	REQ_F_LINK_TIMEOUT_BIT = 12,
	REQ_F_NEED_CLEANUP_BIT = 13,
	REQ_F_POLLED_BIT = 14,
	REQ_F_BUFFER_SELECTED_BIT = 15,
	REQ_F_COMPLETE_INLINE_BIT = 16,
	REQ_F_REISSUE_BIT = 17,
	REQ_F_CREDS_BIT = 18,
	REQ_F_REFCOUNT_BIT = 19,
	REQ_F_ARM_LTIMEOUT_BIT = 20,
	REQ_F_ASYNC_DATA_BIT = 21,
	REQ_F_SKIP_LINK_CQES_BIT = 22,
	REQ_F_SINGLE_POLL_BIT = 23,
	REQ_F_DOUBLE_POLL_BIT = 24,
	REQ_F_PARTIAL_IO_BIT = 25,
	REQ_F_SUPPORT_NOWAIT_BIT = 26,
	REQ_F_ISREG_BIT = 27,
	__REQ_F_LAST_BIT = 28,
};

enum {
	REQ_F_FIXED_FILE = 1,
	REQ_F_IO_DRAIN = 2,
	REQ_F_LINK = 4,
	REQ_F_HARDLINK = 8,
	REQ_F_FORCE_ASYNC = 16,
	REQ_F_BUFFER_SELECT = 32,
	REQ_F_CQE_SKIP = 64,
	REQ_F_FAIL = 256,
	REQ_F_INFLIGHT = 512,
	REQ_F_CUR_POS = 1024,
	REQ_F_NOWAIT = 2048,
	REQ_F_LINK_TIMEOUT = 4096,
	REQ_F_NEED_CLEANUP = 8192,
	REQ_F_POLLED = 16384,
	REQ_F_BUFFER_SELECTED = 32768,
	REQ_F_COMPLETE_INLINE = 65536,
	REQ_F_REISSUE = 131072,
	REQ_F_SUPPORT_NOWAIT = 67108864,
	REQ_F_ISREG = 134217728,
	REQ_F_CREDS = 262144,
	REQ_F_REFCOUNT = 524288,
	REQ_F_ARM_LTIMEOUT = 1048576,
	REQ_F_ASYNC_DATA = 2097152,
	REQ_F_SKIP_LINK_CQES = 4194304,
	REQ_F_SINGLE_POLL = 8388608,
	REQ_F_DOUBLE_POLL = 16777216,
	REQ_F_PARTIAL_IO = 33554432,
};

struct async_poll {
	struct io_poll_iocb poll;
	struct io_poll_iocb *double_poll;
};

enum {
	IORING_RSRC_FILE = 0,
	IORING_RSRC_BUFFER = 1,
};

struct io_tctx_node {
	struct list_head ctx_node;
	struct task_struct *task;
	struct io_ring_ctx *ctx;
};

struct io_defer_entry {
	struct list_head list;
	struct io_kiocb *req;
	u32 seq;
};

struct io_op_def {
	unsigned int needs_file: 1;
	unsigned int plug: 1;
	unsigned int hash_reg_file: 1;
	unsigned int unbound_nonreg_file: 1;
	unsigned int pollin: 1;
	unsigned int pollout: 1;
	unsigned int poll_exclusive: 1;
	unsigned int buffer_select: 1;
	unsigned int needs_async_setup: 1;
	unsigned int not_supported: 1;
	unsigned int audit_skip: 1;
	short unsigned int async_size;
};

struct io_poll_table {
	struct poll_table_struct pt;
	struct io_kiocb *req;
	int nr_entries;
	int error;
};

enum {
	IO_APOLL_OK = 0,
	IO_APOLL_ABORTED = 1,
	IO_APOLL_READY = 2,
};

struct io_cancel_data {
	struct io_ring_ctx *ctx;
	u64 user_data;
};

struct io_wait_queue {
	struct wait_queue_entry wq;
	struct io_ring_ctx *ctx;
	unsigned int cq_tail;
	unsigned int nr_timeouts;
};

struct io_tctx_exit {
	struct callback_head task_work;
	struct completion completion;
	struct io_ring_ctx *ctx;
};

struct io_task_cancel {
	struct task_struct *task;
	bool all;
};

struct creds;

struct trace_event_raw_locks_get_lock_context {
	struct trace_entry ent;
	long unsigned int i_ino;
	dev_t s_dev;
	unsigned char type;
	struct file_lock_context *ctx;
	char __data[0];
};

struct trace_event_raw_filelock_lock {
	struct trace_entry ent;
	struct file_lock *fl;
	long unsigned int i_ino;
	dev_t s_dev;
	struct file_lock *fl_blocker;
	fl_owner_t fl_owner;
	unsigned int fl_pid;
	unsigned int fl_flags;
	unsigned char fl_type;
	loff_t fl_start;
	loff_t fl_end;
	int ret;
	char __data[0];
};

struct trace_event_raw_filelock_lease {
	struct trace_entry ent;
	struct file_lock *fl;
	long unsigned int i_ino;
	dev_t s_dev;
	struct file_lock *fl_blocker;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	long unsigned int fl_break_time;
	long unsigned int fl_downgrade_time;
	char __data[0];
};

struct trace_event_raw_generic_add_lease {
	struct trace_entry ent;
	long unsigned int i_ino;
	int wcount;
	int rcount;
	int icount;
	dev_t s_dev;
	fl_owner_t fl_owner;
	unsigned int fl_flags;
	unsigned char fl_type;
	char __data[0];
};

struct trace_event_raw_leases_conflict {
	struct trace_entry ent;
	void *lease;
	void *breaker;
	unsigned int l_fl_flags;
	unsigned int b_fl_flags;
	unsigned char l_fl_type;
	unsigned char b_fl_type;
	bool conflict;
	char __data[0];
};

struct trace_event_data_offsets_locks_get_lock_context {};

struct trace_event_data_offsets_filelock_lock {};

struct trace_event_data_offsets_filelock_lease {};

struct trace_event_data_offsets_generic_add_lease {};

struct trace_event_data_offsets_leases_conflict {};

typedef void (*btf_trace_locks_get_lock_context)(void *, struct inode *, int, struct file_lock_context *);

typedef void (*btf_trace_posix_lock_inode)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_fcntl_setlk)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_locks_remove_posix)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_flock_lock_inode)(void *, struct inode *, struct file_lock *, int);

typedef void (*btf_trace_break_lease_noblock)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_break_lease_block)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_break_lease_unblock)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_generic_delete_lease)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_time_out_leases)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_generic_add_lease)(void *, struct inode *, struct file_lock *);

typedef void (*btf_trace_leases_conflict)(void *, bool, struct file_lock *, struct file_lock *);

struct file_lock_list_struct {
	spinlock_t lock;
	struct hlist_head hlist;
};

struct locks_iterator {
	int li_cpu;
	loff_t li_pos;
};

typedef long unsigned int elf_greg_t;

typedef elf_greg_t elf_gregset_t[40];

struct elf32_phdr {
	Elf32_Word p_type;
	Elf32_Off p_offset;
	Elf32_Addr p_vaddr;
	Elf32_Addr p_paddr;
	Elf32_Word p_filesz;
	Elf32_Word p_memsz;
	Elf32_Word p_flags;
	Elf32_Word p_align;
};

enum {
	PER_LINUX = 0,
	PER_LINUX_32BIT = 8388608,
	PER_LINUX_FDPIC = 524288,
	PER_SVR4 = 68157441,
	PER_SVR3 = 83886082,
	PER_SCOSVR3 = 117440515,
	PER_OSR5 = 100663299,
	PER_WYSEV386 = 83886084,
	PER_ISCR4 = 67108869,
	PER_BSD = 6,
	PER_SUNOS = 67108870,
	PER_XENIX = 83886087,
	PER_LINUX32 = 8,
	PER_LINUX32_3GB = 134217736,
	PER_IRIX32 = 67108873,
	PER_IRIXN32 = 67108874,
	PER_IRIX64 = 67108875,
	PER_RISCOS = 12,
	PER_SOLARIS = 67108877,
	PER_UW7 = 68157454,
	PER_OSF4 = 15,
	PER_HPUX = 16,
	PER_MASK = 255,
};

struct elf_siginfo {
	int si_signo;
	int si_code;
	int si_errno;
};

struct elf_prstatus_common {
	struct elf_siginfo pr_info;
	short int pr_cursig;
	long unsigned int pr_sigpend;
	long unsigned int pr_sighold;
	pid_t pr_pid;
	pid_t pr_ppid;
	pid_t pr_pgrp;
	pid_t pr_sid;
	struct __kernel_old_timeval pr_utime;
	struct __kernel_old_timeval pr_stime;
	struct __kernel_old_timeval pr_cutime;
	struct __kernel_old_timeval pr_cstime;
};

struct elf_prstatus {
	struct elf_prstatus_common common;
	elf_gregset_t pr_reg;
	int pr_fpvalid;
};

struct elf_prpsinfo {
	char pr_state;
	char pr_sname;
	char pr_zomb;
	char pr_nice;
	long unsigned int pr_flag;
	__kernel_uid_t pr_uid;
	__kernel_gid_t pr_gid;
	pid_t pr_pid;
	pid_t pr_ppid;
	pid_t pr_pgrp;
	pid_t pr_sid;
	char pr_fname[16];
	char pr_psargs[80];
};

struct arch_elf_state {};

struct memelfnote {
	const char *name;
	int type;
	unsigned int datasz;
	void *data;
};

struct elf_thread_core_info {
	struct elf_thread_core_info *next;
	struct task_struct *task;
	struct elf_prstatus prstatus;
	struct memelfnote notes[0];
};

struct elf_note_info {
	struct elf_thread_core_info *thread;
	struct memelfnote psinfo;
	struct memelfnote signote;
	struct memelfnote auxv;
	struct memelfnote files;
	siginfo_t csigdata;
	size_t size;
	int thread_notes;
};

struct mb_cache_entry {
	struct list_head e_list;
	struct hlist_bl_node e_hash_list;
	atomic_t e_refcnt;
	u32 e_key;
	u32 e_referenced: 1;
	u32 e_reusable: 1;
	u64 e_value;
};

struct mb_cache {
	struct hlist_bl_head *c_hash;
	int c_bucket_bits;
	long unsigned int c_max_entries;
	spinlock_t c_list_lock;
	struct list_head c_list;
	long unsigned int c_entry_count;
	struct shrinker c_shrink;
	struct work_struct c_shrink_work;
};

struct lock_manager {
	struct list_head list;
	bool block_opens;
};

struct net_generic {
	union {
		struct {
			unsigned int len;
			struct callback_head rcu;
		} s;
		void *ptr[0];
	};
};

struct core_name {
	char *corename;
	int used;
	int size;
};

struct iomap_iter {
	struct inode *inode;
	loff_t pos;
	u64 len;
	s64 processed;
	unsigned int flags;
	struct iomap iomap;
	struct iomap srcmap;
};

struct trace_event_raw_iomap_readpage_class {
	struct trace_entry ent;
	dev_t dev;
	u64 ino;
	int nr_pages;
	char __data[0];
};

struct trace_event_raw_iomap_range_class {
	struct trace_entry ent;
	dev_t dev;
	u64 ino;
	loff_t size;
	loff_t offset;
	u64 length;
	char __data[0];
};

struct trace_event_raw_iomap_class {
	struct trace_entry ent;
	dev_t dev;
	u64 ino;
	u64 addr;
	loff_t offset;
	u64 length;
	u16 type;
	u16 flags;
	dev_t bdev;
	char __data[0];
};

struct trace_event_raw_iomap_iter {
	struct trace_entry ent;
	dev_t dev;
	u64 ino;
	loff_t pos;
	u64 length;
	unsigned int flags;
	const void *ops;
	long unsigned int caller;
	char __data[0];
};

struct trace_event_data_offsets_iomap_readpage_class {};

struct trace_event_data_offsets_iomap_range_class {};

struct trace_event_data_offsets_iomap_class {};

struct trace_event_data_offsets_iomap_iter {};

typedef void (*btf_trace_iomap_readpage)(void *, struct inode *, int);

typedef void (*btf_trace_iomap_readahead)(void *, struct inode *, int);

typedef void (*btf_trace_iomap_writepage)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_releasepage)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_invalidate_folio)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_dio_invalidate_fail)(void *, struct inode *, loff_t, u64);

typedef void (*btf_trace_iomap_iter_dstmap)(void *, struct inode *, struct iomap *);

typedef void (*btf_trace_iomap_iter_srcmap)(void *, struct inode *, struct iomap *);

typedef void (*btf_trace_iomap_iter)(void *, struct iomap_iter *, const void *, long unsigned int);

struct iomap_ops {
	int (*iomap_begin)(struct inode *, loff_t, loff_t, unsigned int, struct iomap *, struct iomap *);
	int (*iomap_end)(struct inode *, loff_t, loff_t, ssize_t, unsigned int, struct iomap *);
};

struct iomap_dio_ops {
	int (*end_io)(struct kiocb *, ssize_t, int, unsigned int);
	void (*submit_io)(const struct iomap_iter *, struct bio *, loff_t);
};

struct iomap_dio {
	struct kiocb *iocb;
	const struct iomap_dio_ops *dops;
	loff_t i_size;
	loff_t size;
	atomic_t ref;
	unsigned int flags;
	int error;
	size_t done_before;
	bool wait_for_completion;
	union {
		struct {
			struct iov_iter *iter;
			struct task_struct *waiter;
			struct bio *poll_bio;
		} submit;
		struct {
			struct work_struct work;
		} aio;
	};
};

struct folio_iter {
	struct folio *folio;
	size_t offset;
	size_t length;
	size_t _seg_count;
	int _i;
};

enum {
	BIOSET_NEED_BVECS = 1,
	BIOSET_NEED_RESCUER = 2,
	BIOSET_PERCPU_CACHE = 4,
};

struct iomap_ioend {
	struct list_head io_list;
	u16 io_type;
	u16 io_flags;
	u32 io_folios;
	struct inode *io_inode;
	size_t io_size;
	loff_t io_offset;
	sector_t io_sector;
	struct bio *io_bio;
	struct bio io_inline_bio;
};

struct iomap_writepage_ctx;

struct iomap_writeback_ops {
	int (*map_blocks)(struct iomap_writepage_ctx *, struct inode *, loff_t);
	int (*prepare_ioend)(struct iomap_ioend *, int);
	void (*discard_folio)(struct folio *, loff_t);
};

struct iomap_writepage_ctx {
	struct iomap iomap;
	struct iomap_ioend *ioend;
	const struct iomap_writeback_ops *ops;
};

typedef int (*list_cmp_func_t)(void *, const struct list_head *, const struct list_head *);

struct iomap_page {
	atomic_t read_bytes_pending;
	atomic_t write_bytes_pending;
	spinlock_t uptodate_lock;
	long unsigned int uptodate[0];
};

struct iomap_readpage_ctx {
	struct folio *cur_folio;
	bool cur_folio_in_bio;
	struct bio *bio;
	struct readahead_control *rac;
};

struct proc_maps_private {
	struct inode *inode;
	struct task_struct *task;
	struct mm_struct *mm;
	struct vm_area_struct *tail_vma;
};

struct mem_size_stats {
	long unsigned int resident;
	long unsigned int shared_clean;
	long unsigned int shared_dirty;
	long unsigned int private_clean;
	long unsigned int private_dirty;
	long unsigned int referenced;
	long unsigned int anonymous;
	long unsigned int lazyfree;
	long unsigned int anonymous_thp;
	long unsigned int shmem_thp;
	long unsigned int file_thp;
	long unsigned int swap;
	long unsigned int shared_hugetlb;
	long unsigned int private_hugetlb;
	u64 pss;
	u64 pss_anon;
	u64 pss_file;
	u64 pss_shmem;
	u64 pss_locked;
	u64 swap_pss;
};

enum clear_refs_types {
	CLEAR_REFS_ALL = 1,
	CLEAR_REFS_ANON = 2,
	CLEAR_REFS_MAPPED = 3,
	CLEAR_REFS_SOFT_DIRTY = 4,
	CLEAR_REFS_MM_HIWATER_RSS = 5,
	CLEAR_REFS_LAST = 6,
};

struct clear_refs_private {
	enum clear_refs_types type;
};

typedef struct {
	u64 pme;
} pagemap_entry_t;

struct pagemapread {
	int pos;
	int len;
	pagemap_entry_t *buffer;
	bool show_pfn;
};

struct pde_opener {
	struct list_head lh;
	struct file *file;
	bool closing;
	struct completion *c;
};

enum {
	BIAS = 2147483648,
};

struct proc_fs_context {
	struct pid_namespace *pid_ns;
	unsigned int mask;
	enum proc_hidepid hidepid;
	int gid;
	enum proc_pidonly pidonly;
};

enum proc_param {
	Opt_gid___2 = 0,
	Opt_hidepid = 1,
	Opt_subset = 2,
};

struct seccomp_data {
	int nr;
	__u32 arch;
	__u64 instruction_pointer;
	__u64 args[6];
};

struct genradix_root;

struct __genradix {
	struct genradix_root *root;
};

struct syscall_info {
	__u64 sp;
	struct seccomp_data data;
};

enum resctrl_conf_type {
	CDP_NONE = 0,
	CDP_CODE = 1,
	CDP_DATA = 2,
};

typedef struct dentry *instantiate_t(struct dentry *, struct task_struct *, const void *);

struct pid_entry {
	const char *name;
	unsigned int len;
	umode_t mode;
	const struct inode_operations *iop;
	const struct file_operations *fop;
	union proc_op op;
};

struct limit_names {
	const char *name;
	const char *unit;
};

struct map_files_info {
	long unsigned int start;
	long unsigned int end;
	fmode_t mode;
};

struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};

struct fd_data {
	fmode_t mode;
	unsigned int fd;
};

struct seq_net_private {
	struct net *net;
	netns_tracker ns_tracker;
};

struct bpf_iter_aux_info;

struct ctl_path {
	const char *procname;
};

struct sysctl_alias {
	const char *kernel_param;
	const char *sysctl_param;
};

enum kernfs_root_flag {
	KERNFS_ROOT_CREATE_DEACTIVATED = 1,
	KERNFS_ROOT_EXTRA_OPEN_PERM_CHECK = 2,
	KERNFS_ROOT_SUPPORT_EXPORTOP = 4,
	KERNFS_ROOT_SUPPORT_USER_XATTR = 8,
};

struct kernfs_syscall_ops;

struct kernfs_root {
	struct kernfs_node *kn;
	unsigned int flags;
	struct idr ino_idr;
	u32 last_id_lowbits;
	u32 id_highbits;
	struct kernfs_syscall_ops *syscall_ops;
	struct list_head supers;
	wait_queue_head_t deactivate_waitq;
	struct rw_semaphore kernfs_rwsem;
};

struct kernfs_iattrs {
	kuid_t ia_uid;
	kgid_t ia_gid;
	struct timespec64 ia_atime;
	struct timespec64 ia_mtime;
	struct timespec64 ia_ctime;
	struct simple_xattrs xattrs;
	atomic_t nr_user_xattrs;
	atomic_t user_xattr_size;
};

struct kernfs_syscall_ops {
	int (*show_options)(struct seq_file *, struct kernfs_root *);
	int (*mkdir)(struct kernfs_node *, const char *, umode_t);
	int (*rmdir)(struct kernfs_node *);
	int (*rename)(struct kernfs_node *, struct kernfs_node *, const char *);
	int (*show_path)(struct seq_file *, struct kernfs_node *, struct kernfs_root *);
};

struct kernfs_fs_context {
	struct kernfs_root *root;
	void *ns_tag;
	long unsigned int magic;
	bool new_sb_created;
};

struct kernfs_super_info {
	struct super_block *sb;
	struct kernfs_root *root;
	const void *ns;
	struct list_head node;
};

enum kernfs_node_type {
	KERNFS_DIR = 1,
	KERNFS_FILE = 2,
	KERNFS_LINK = 4,
};

enum kernfs_node_flag {
	KERNFS_ACTIVATED = 16,
	KERNFS_NS = 32,
	KERNFS_HAS_SEQ_SHOW = 64,
	KERNFS_HAS_MMAP = 128,
	KERNFS_LOCKDEP = 256,
	KERNFS_SUICIDAL = 1024,
	KERNFS_SUICIDED = 2048,
	KERNFS_EMPTY_DIR = 4096,
	KERNFS_HAS_RELEASE = 8192,
};

struct kernfs_open_node {
	atomic_t refcnt;
	atomic_t event;
	wait_queue_head_t poll;
	struct list_head files;
};

struct pts_mount_opts {
	int setuid;
	int setgid;
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
	umode_t ptmxmode;
	int reserve;
	int max;
};

enum {
	Opt_uid___2 = 0,
	Opt_gid___3 = 1,
	Opt_mode___2 = 2,
	Opt_ptmxmode = 3,
	Opt_newinstance = 4,
	Opt_max = 5,
	Opt_err = 6,
};

struct pts_fs_info {
	struct ida allocated_ptys;
	struct pts_mount_opts mount_opts;
	struct super_block *sb;
	struct dentry *ptmx_dentry;
};

struct bgl_lock {
	spinlock_t lock;
};

struct blockgroup_lock {
	struct bgl_lock locks[1];
};

typedef int ext2_grpblk_t;

typedef long unsigned int ext2_fsblk_t;

struct ext2_reserve_window {
	ext2_fsblk_t _rsv_start;
	ext2_fsblk_t _rsv_end;
};

struct ext2_reserve_window_node {
	struct rb_node rsv_node;
	__u32 rsv_goal_size;
	__u32 rsv_alloc_hit;
	struct ext2_reserve_window rsv_window;
};

struct ext2_block_alloc_info {
	struct ext2_reserve_window_node rsv_window_node;
	__u32 last_alloc_logical_block;
	ext2_fsblk_t last_alloc_physical_block;
};

struct mb_cache;

struct ext2_super_block;

struct ext2_sb_info {
	long unsigned int s_frag_size;
	long unsigned int s_frags_per_block;
	long unsigned int s_inodes_per_block;
	long unsigned int s_frags_per_group;
	long unsigned int s_blocks_per_group;
	long unsigned int s_inodes_per_group;
	long unsigned int s_itb_per_group;
	long unsigned int s_gdb_count;
	long unsigned int s_desc_per_block;
	long unsigned int s_groups_count;
	long unsigned int s_overhead_last;
	long unsigned int s_blocks_last;
	struct buffer_head *s_sbh;
	struct ext2_super_block *s_es;
	struct buffer_head **s_group_desc;
	long unsigned int s_mount_opt;
	long unsigned int s_sb_block;
	kuid_t s_resuid;
	kgid_t s_resgid;
	short unsigned int s_mount_state;
	short unsigned int s_pad;
	int s_addr_per_block_bits;
	int s_desc_per_block_bits;
	int s_inode_size;
	int s_first_ino;
	spinlock_t s_next_gen_lock;
	u32 s_next_generation;
	long unsigned int s_dir_count;
	u8 *s_debts;
	struct percpu_counter s_freeblocks_counter;
	struct percpu_counter s_freeinodes_counter;
	struct percpu_counter s_dirs_counter;
	struct blockgroup_lock *s_blockgroup_lock;
	spinlock_t s_rsv_window_lock;
	struct rb_root s_rsv_window_root;
	struct ext2_reserve_window_node s_rsv_window_head;
	spinlock_t s_lock;
	struct mb_cache *s_ea_block_cache;
	struct dax_device *s_daxdev;
	u64 s_dax_part_off;
};

struct ext2_super_block {
	__le32 s_inodes_count;
	__le32 s_blocks_count;
	__le32 s_r_blocks_count;
	__le32 s_free_blocks_count;
	__le32 s_free_inodes_count;
	__le32 s_first_data_block;
	__le32 s_log_block_size;
	__le32 s_log_frag_size;
	__le32 s_blocks_per_group;
	__le32 s_frags_per_group;
	__le32 s_inodes_per_group;
	__le32 s_mtime;
	__le32 s_wtime;
	__le16 s_mnt_count;
	__le16 s_max_mnt_count;
	__le16 s_magic;
	__le16 s_state;
	__le16 s_errors;
	__le16 s_minor_rev_level;
	__le32 s_lastcheck;
	__le32 s_checkinterval;
	__le32 s_creator_os;
	__le32 s_rev_level;
	__le16 s_def_resuid;
	__le16 s_def_resgid;
	__le32 s_first_ino;
	__le16 s_inode_size;
	__le16 s_block_group_nr;
	__le32 s_feature_compat;
	__le32 s_feature_incompat;
	__le32 s_feature_ro_compat;
	__u8 s_uuid[16];
	char s_volume_name[16];
	char s_last_mounted[64];
	__le32 s_algorithm_usage_bitmap;
	__u8 s_prealloc_blocks;
	__u8 s_prealloc_dir_blocks;
	__u16 s_padding1;
	__u8 s_journal_uuid[16];
	__u32 s_journal_inum;
	__u32 s_journal_dev;
	__u32 s_last_orphan;
	__u32 s_hash_seed[4];
	__u8 s_def_hash_version;
	__u8 s_reserved_char_pad;
	__u16 s_reserved_word_pad;
	__le32 s_default_mount_opts;
	__le32 s_first_meta_bg;
	__u32 s_reserved[190];
};

struct ext2_group_desc {
	__le32 bg_block_bitmap;
	__le32 bg_inode_bitmap;
	__le32 bg_inode_table;
	__le16 bg_free_blocks_count;
	__le16 bg_free_inodes_count;
	__le16 bg_used_dirs_count;
	__le16 bg_pad;
	__le32 bg_reserved[3];
};

struct ext2_inode_info {
	__le32 i_data[15];
	__u32 i_flags;
	__u32 i_faddr;
	__u8 i_frag_no;
	__u8 i_frag_size;
	__u16 i_state;
	__u32 i_file_acl;
	__u32 i_dir_acl;
	__u32 i_dtime;
	__u32 i_block_group;
	struct ext2_block_alloc_info *i_block_alloc_info;
	__u32 i_dir_start_lookup;
	struct rw_semaphore xattr_sem;
	rwlock_t i_meta_lock;
	struct mutex truncate_mutex;
	int: 32;
	struct inode vfs_inode;
	struct list_head i_orphan;
};

struct ext2_dir_entry_2 {
	__le32 inode;
	__le16 rec_len;
	__u8 name_len;
	__u8 file_type;
	char name[0];
};

typedef struct ext2_dir_entry_2 ext2_dirent;

typedef short unsigned int __kernel_uid16_t;

typedef short unsigned int __kernel_gid16_t;

typedef __kernel_uid16_t uid16_t;

typedef __kernel_gid16_t gid16_t;

struct ext2_inode {
	__le16 i_mode;
	__le16 i_uid;
	__le32 i_size;
	__le32 i_atime;
	__le32 i_ctime;
	__le32 i_mtime;
	__le32 i_dtime;
	__le16 i_gid;
	__le16 i_links_count;
	__le32 i_blocks;
	__le32 i_flags;
	union {
		struct {
			__le32 l_i_reserved1;
		} linux1;
		struct {
			__le32 h_i_translator;
		} hurd1;
		struct {
			__le32 m_i_reserved1;
		} masix1;
	} osd1;
	__le32 i_block[15];
	__le32 i_generation;
	__le32 i_file_acl;
	__le32 i_dir_acl;
	__le32 i_faddr;
	union {
		struct {
			__u8 l_i_frag;
			__u8 l_i_fsize;
			__u16 i_pad1;
			__le16 l_i_uid_high;
			__le16 l_i_gid_high;
			__u32 l_i_reserved2;
		} linux2;
		struct {
			__u8 h_i_frag;
			__u8 h_i_fsize;
			__le16 h_i_mode_high;
			__le16 h_i_uid_high;
			__le16 h_i_gid_high;
			__le32 h_i_author;
		} hurd2;
		struct {
			__u8 m_i_frag;
			__u8 m_i_fsize;
			__u16 m_pad1;
			__u32 m_i_reserved2[2];
		} masix2;
	} osd2;
};

typedef struct {
	__le32 *p;
	__le32 key;
	struct buffer_head *bh;
} Indirect;

struct ext2_mount_options {
	long unsigned int s_mount_opt;
	kuid_t s_resuid;
	kgid_t s_resgid;
};

enum {
	Opt_bsd_df = 0,
	Opt_minix_df = 1,
	Opt_grpid = 2,
	Opt_nogrpid = 3,
	Opt_resgid = 4,
	Opt_resuid = 5,
	Opt_sb = 6,
	Opt_err_cont = 7,
	Opt_err_panic = 8,
	Opt_err_ro = 9,
	Opt_nouid32 = 10,
	Opt_debug = 11,
	Opt_oldalloc = 12,
	Opt_orlov = 13,
	Opt_nobh = 14,
	Opt_user_xattr = 15,
	Opt_nouser_xattr = 16,
	Opt_acl = 17,
	Opt_noacl = 18,
	Opt_xip = 19,
	Opt_dax = 20,
	Opt_ignore = 21,
	Opt_err___2 = 22,
	Opt_quota = 23,
	Opt_usrquota = 24,
	Opt_grpquota = 25,
	Opt_reservation = 26,
	Opt_noreservation = 27,
};

struct ext2_xattr_header {
	__le32 h_magic;
	__le32 h_refcount;
	__le32 h_blocks;
	__le32 h_hash;
	__u32 h_reserved[4];
};

struct ext2_xattr_entry {
	__u8 e_name_len;
	__u8 e_name_index;
	__le16 e_value_offs;
	__le32 e_value_block;
	__le32 e_value_size;
	__le32 e_hash;
	char e_name[0];
};

struct ramfs_mount_opts {
	umode_t mode;
};

struct ramfs_fs_info {
	struct ramfs_mount_opts mount_opts;
};

enum ramfs_param {
	Opt_mode___3 = 0,
};

struct in_addr {
	__be32 s_addr;
};

struct sockaddr_in {
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr sin_addr;
	unsigned char __pad[8];
};

struct sockaddr_in6 {
	short unsigned int sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

typedef u32 rpc_authflavor_t;

enum rpc_auth_flavors {
	RPC_AUTH_NULL = 0,
	RPC_AUTH_UNIX = 1,
	RPC_AUTH_SHORT = 2,
	RPC_AUTH_DES = 3,
	RPC_AUTH_KRB = 4,
	RPC_AUTH_GSS = 6,
	RPC_AUTH_TLS = 7,
	RPC_AUTH_MAXFLAVOR = 8,
	RPC_AUTH_GSS_KRB5 = 390003,
	RPC_AUTH_GSS_KRB5I = 390004,
	RPC_AUTH_GSS_KRB5P = 390005,
	RPC_AUTH_GSS_LKEY = 390006,
	RPC_AUTH_GSS_LKEYI = 390007,
	RPC_AUTH_GSS_LKEYP = 390008,
	RPC_AUTH_GSS_SPKM = 390009,
	RPC_AUTH_GSS_SPKMI = 390010,
	RPC_AUTH_GSS_SPKMP = 390011,
};

struct xdr_netobj {
	unsigned int len;
	u8 *data;
};

struct xdr_buf {
	struct kvec head[1];
	struct kvec tail[1];
	struct bio_vec *bvec;
	struct page **pages;
	unsigned int page_base;
	unsigned int page_len;
	unsigned int flags;
	unsigned int buflen;
	unsigned int len;
};

struct rpc_rqst;

struct xdr_stream {
	__be32 *p;
	struct xdr_buf *buf;
	__be32 *end;
	struct kvec *iov;
	struct kvec scratch;
	struct page **page_ptr;
	unsigned int nwords;
	struct rpc_rqst *rqst;
};

struct rpc_xprt;

struct rpc_task;

struct rpc_cred;

struct rpc_rqst {
	struct rpc_xprt *rq_xprt;
	struct xdr_buf rq_snd_buf;
	struct xdr_buf rq_rcv_buf;
	struct rpc_task *rq_task;
	struct rpc_cred *rq_cred;
	__be32 rq_xid;
	int rq_cong;
	u32 rq_seqno;
	int rq_enc_pages_num;
	struct page **rq_enc_pages;
	void (*rq_release_snd_buf)(struct rpc_rqst *);
	union {
		struct list_head rq_list;
		struct rb_node rq_recv;
	};
	struct list_head rq_xmit;
	struct list_head rq_xmit2;
	void *rq_buffer;
	size_t rq_callsize;
	void *rq_rbuffer;
	size_t rq_rcvsize;
	size_t rq_xmit_bytes_sent;
	size_t rq_reply_bytes_recvd;
	struct xdr_buf rq_private_buf;
	long unsigned int rq_majortimeo;
	long unsigned int rq_minortimeo;
	long unsigned int rq_timeout;
	ktime_t rq_rtt;
	unsigned int rq_retries;
	unsigned int rq_connect_cookie;
	atomic_t rq_pin;
	u32 rq_bytes_sent;
	ktime_t rq_xtime;
	int rq_ntrans;
};

typedef void (*kxdreproc_t)(struct rpc_rqst *, struct xdr_stream *, const void *);

typedef int (*kxdrdproc_t)(struct rpc_rqst *, struct xdr_stream *, void *);

struct rpc_procinfo;

struct rpc_message {
	const struct rpc_procinfo *rpc_proc;
	void *rpc_argp;
	void *rpc_resp;
	const struct cred *rpc_cred;
};

struct rpc_procinfo {
	u32 p_proc;
	kxdreproc_t p_encode;
	kxdrdproc_t p_decode;
	unsigned int p_arglen;
	unsigned int p_replen;
	unsigned int p_timer;
	u32 p_statidx;
	const char *p_name;
};

struct rpc_wait {
	struct list_head list;
	struct list_head links;
	struct list_head timer_list;
};

struct rpc_wait_queue;

struct rpc_call_ops;

struct rpc_clnt;

struct rpc_task {
	atomic_t tk_count;
	int tk_status;
	struct list_head tk_task;
	void (*tk_callback)(struct rpc_task *);
	void (*tk_action)(struct rpc_task *);
	long unsigned int tk_timeout;
	long unsigned int tk_runstate;
	struct rpc_wait_queue *tk_waitqueue;
	union {
		struct work_struct tk_work;
		struct rpc_wait tk_wait;
	} u;
	int tk_rpc_status;
	struct rpc_message tk_msg;
	void *tk_calldata;
	const struct rpc_call_ops *tk_ops;
	struct rpc_clnt *tk_client;
	struct rpc_xprt *tk_xprt;
	struct rpc_cred *tk_op_cred;
	struct rpc_rqst *tk_rqstp;
	struct workqueue_struct *tk_workqueue;
	ktime_t tk_start;
	pid_t tk_owner;
	short unsigned int tk_flags;
	short unsigned int tk_timeouts;
	short unsigned int tk_pid;
	unsigned char tk_priority: 2;
	unsigned char tk_garb_retry: 2;
	unsigned char tk_cred_retry: 2;
	unsigned char tk_rebind_retry: 2;
};

struct rpc_timer {
	struct list_head list;
	long unsigned int expires;
	struct delayed_work dwork;
};

struct rpc_wait_queue {
	spinlock_t lock;
	struct list_head tasks[4];
	unsigned char maxpriority;
	unsigned char priority;
	unsigned char nr;
	short unsigned int qlen;
	struct rpc_timer timer_list;
	const char *name;
};

struct rpc_call_ops {
	void (*rpc_call_prepare)(struct rpc_task *, void *);
	void (*rpc_call_done)(struct rpc_task *, void *);
	void (*rpc_count_stats)(struct rpc_task *, void *);
	void (*rpc_release)(void *);
};

struct rpc_pipe_dir_head {
	struct list_head pdh_entries;
	struct dentry *pdh_dentry;
};

struct rpc_rtt {
	long unsigned int timeo;
	long unsigned int srtt[5];
	long unsigned int sdrtt[5];
	int ntimeouts[5];
};

struct rpc_timeout {
	long unsigned int to_initval;
	long unsigned int to_maxval;
	long unsigned int to_increment;
	unsigned int to_retries;
	unsigned char to_exponential;
};

struct rpc_xprt_switch;

struct rpc_xprt_iter_ops;

struct rpc_xprt_iter {
	struct rpc_xprt_switch *xpi_xpswitch;
	struct rpc_xprt *xpi_cursor;
	const struct rpc_xprt_iter_ops *xpi_ops;
};

struct rpc_auth;

struct rpc_stat;

struct rpc_iostats;

struct rpc_program;

struct rpc_sysfs_client;

struct rpc_clnt {
	refcount_t cl_count;
	unsigned int cl_clid;
	struct list_head cl_clients;
	struct list_head cl_tasks;
	atomic_t cl_pid;
	spinlock_t cl_lock;
	struct rpc_xprt *cl_xprt;
	const struct rpc_procinfo *cl_procinfo;
	u32 cl_prog;
	u32 cl_vers;
	u32 cl_maxproc;
	struct rpc_auth *cl_auth;
	struct rpc_stat *cl_stats;
	struct rpc_iostats *cl_metrics;
	unsigned int cl_softrtry: 1;
	unsigned int cl_softerr: 1;
	unsigned int cl_discrtry: 1;
	unsigned int cl_noretranstimeo: 1;
	unsigned int cl_autobind: 1;
	unsigned int cl_chatty: 1;
	struct rpc_rtt *cl_rtt;
	const struct rpc_timeout *cl_timeout;
	atomic_t cl_swapper;
	int cl_nodelen;
	char cl_nodename[65];
	struct rpc_pipe_dir_head cl_pipedir_objects;
	struct rpc_clnt *cl_parent;
	struct rpc_rtt cl_rtt_default;
	struct rpc_timeout cl_timeout_default;
	const struct rpc_program *cl_program;
	const char *cl_principal;
	struct rpc_sysfs_client *cl_sysfs;
	union {
		struct rpc_xprt_iter cl_xpi;
		struct work_struct cl_work;
	};
	const struct cred *cl_cred;
	unsigned int cl_max_connect;
};

struct rpc_xprt_ops;

struct svc_xprt;

struct xprt_class;

struct rpc_sysfs_xprt;

struct rpc_xprt {
	struct kref kref;
	const struct rpc_xprt_ops *ops;
	unsigned int id;
	const struct rpc_timeout *timeout;
	struct __kernel_sockaddr_storage addr;
	size_t addrlen;
	int prot;
	long unsigned int cong;
	long unsigned int cwnd;
	size_t max_payload;
	struct rpc_wait_queue binding;
	struct rpc_wait_queue sending;
	struct rpc_wait_queue pending;
	struct rpc_wait_queue backlog;
	struct list_head free;
	unsigned int max_reqs;
	unsigned int min_reqs;
	unsigned int num_reqs;
	long unsigned int state;
	unsigned char resvport: 1;
	unsigned char reuseport: 1;
	atomic_t swapper;
	unsigned int bind_index;
	struct list_head xprt_switch;
	long unsigned int bind_timeout;
	long unsigned int reestablish_timeout;
	unsigned int connect_cookie;
	struct work_struct task_cleanup;
	struct timer_list timer;
	long unsigned int last_used;
	long unsigned int idle_timeout;
	long unsigned int connect_timeout;
	long unsigned int max_reconnect_timeout;
	atomic_long_t queuelen;
	spinlock_t transport_lock;
	spinlock_t reserve_lock;
	spinlock_t queue_lock;
	u32 xid;
	struct rpc_task *snd_task;
	struct list_head xmit_queue;
	atomic_long_t xmit_queuelen;
	struct svc_xprt *bc_xprt;
	struct rb_root recv_queue;
	struct {
		long unsigned int bind_count;
		long unsigned int connect_count;
		long unsigned int connect_start;
		long unsigned int connect_time;
		long unsigned int sends;
		long unsigned int recvs;
		long unsigned int bad_xids;
		long unsigned int max_slots;
		long long unsigned int req_u;
		long long unsigned int bklog_u;
		long long unsigned int sending_u;
		long long unsigned int pending_u;
	} stat;
	struct net *xprt_net;
	netns_tracker ns_tracker;
	const char *servername;
	const char *address_strings[6];
	struct callback_head rcu;
	const struct xprt_class *xprt_class;
	struct rpc_sysfs_xprt *xprt_sysfs;
	bool main;
};

struct rpc_credops;

struct rpc_cred {
	struct hlist_node cr_hash;
	struct list_head cr_lru;
	struct callback_head cr_rcu;
	struct rpc_auth *cr_auth;
	const struct rpc_credops *cr_ops;
	long unsigned int cr_expire;
	long unsigned int cr_flags;
	refcount_t cr_count;
	const struct cred *cr_cred;
};

struct rpc_task_setup {
	struct rpc_task *task;
	struct rpc_clnt *rpc_client;
	struct rpc_xprt *rpc_xprt;
	struct rpc_cred *rpc_op_cred;
	const struct rpc_message *rpc_message;
	const struct rpc_call_ops *callback_ops;
	void *callback_data;
	struct workqueue_struct *workqueue;
	short unsigned int flags;
	signed char priority;
};

struct rpc_xprt_ops {
	void (*set_buffer_size)(struct rpc_xprt *, size_t, size_t);
	int (*reserve_xprt)(struct rpc_xprt *, struct rpc_task *);
	void (*release_xprt)(struct rpc_xprt *, struct rpc_task *);
	void (*alloc_slot)(struct rpc_xprt *, struct rpc_task *);
	void (*free_slot)(struct rpc_xprt *, struct rpc_rqst *);
	void (*rpcbind)(struct rpc_task *);
	void (*set_port)(struct rpc_xprt *, short unsigned int);
	void (*connect)(struct rpc_xprt *, struct rpc_task *);
	int (*get_srcaddr)(struct rpc_xprt *, char *, size_t);
	short unsigned int (*get_srcport)(struct rpc_xprt *);
	int (*buf_alloc)(struct rpc_task *);
	void (*buf_free)(struct rpc_task *);
	int (*prepare_request)(struct rpc_rqst *);
	int (*send_request)(struct rpc_rqst *);
	void (*wait_for_reply_request)(struct rpc_task *);
	void (*timer)(struct rpc_xprt *, struct rpc_task *);
	void (*release_request)(struct rpc_task *);
	void (*close)(struct rpc_xprt *);
	void (*destroy)(struct rpc_xprt *);
	void (*set_connect_timeout)(struct rpc_xprt *, long unsigned int, long unsigned int);
	void (*print_stats)(struct rpc_xprt *, struct seq_file *);
	int (*enable_swap)(struct rpc_xprt *);
	void (*disable_swap)(struct rpc_xprt *);
	void (*inject_disconnect)(struct rpc_xprt *);
	int (*bc_setup)(struct rpc_xprt *, unsigned int);
	size_t (*bc_maxpayload)(struct rpc_xprt *);
	unsigned int (*bc_num_slots)(struct rpc_xprt *);
	void (*bc_free_rqst)(struct rpc_rqst *);
	void (*bc_destroy)(struct rpc_xprt *, unsigned int);
};

enum xprt_transports {
	XPRT_TRANSPORT_UDP = 17,
	XPRT_TRANSPORT_TCP = 6,
	XPRT_TRANSPORT_BC_TCP = 2147483654,
	XPRT_TRANSPORT_RDMA = 256,
	XPRT_TRANSPORT_BC_RDMA = 2147483904,
	XPRT_TRANSPORT_LOCAL = 257,
};

struct svc_xprt_class;

struct svc_xprt_ops;

struct svc_serv;

struct svc_xprt {
	struct svc_xprt_class *xpt_class;
	const struct svc_xprt_ops *xpt_ops;
	struct kref xpt_ref;
	struct list_head xpt_list;
	struct list_head xpt_ready;
	long unsigned int xpt_flags;
	struct svc_serv *xpt_server;
	atomic_t xpt_reserved;
	atomic_t xpt_nr_rqsts;
	struct mutex xpt_mutex;
	spinlock_t xpt_lock;
	void *xpt_auth_cache;
	struct list_head xpt_deferred;
	struct __kernel_sockaddr_storage xpt_local;
	size_t xpt_locallen;
	struct __kernel_sockaddr_storage xpt_remote;
	size_t xpt_remotelen;
	char xpt_remotebuf[58];
	struct list_head xpt_users;
	struct net *xpt_net;
	netns_tracker ns_tracker;
	const struct cred *xpt_cred;
	struct rpc_xprt *xpt_bc_xprt;
	struct rpc_xprt_switch *xpt_bc_xps;
};

struct xprt_create;

struct xprt_class {
	struct list_head list;
	int ident;
	struct rpc_xprt * (*setup)(struct xprt_create *);
	struct module *owner;
	char name[32];
	const char *netid[0];
};

struct xprt_create {
	int ident;
	struct net *net;
	struct sockaddr *srcaddr;
	struct sockaddr *dstaddr;
	size_t addrlen;
	const char *servername;
	struct svc_xprt *bc_xprt;
	struct rpc_xprt_switch *bc_xps;
	unsigned int flags;
};

struct rpc_sysfs_xprt_switch;

struct rpc_xprt_switch {
	spinlock_t xps_lock;
	struct kref xps_kref;
	unsigned int xps_id;
	unsigned int xps_nxprts;
	unsigned int xps_nactive;
	unsigned int xps_nunique_destaddr_xprts;
	atomic_long_t xps_queuelen;
	struct list_head xps_xprt_list;
	struct net *xps_net;
	const struct rpc_xprt_iter_ops *xps_iter_ops;
	struct rpc_sysfs_xprt_switch *xps_sysfs;
	struct callback_head xps_rcu;
};

struct auth_cred {
	const struct cred *cred;
	const char *principal;
};

struct rpc_authops;

struct rpc_cred_cache;

struct rpc_auth {
	unsigned int au_cslack;
	unsigned int au_rslack;
	unsigned int au_verfsize;
	unsigned int au_ralign;
	long unsigned int au_flags;
	const struct rpc_authops *au_ops;
	rpc_authflavor_t au_flavor;
	refcount_t au_count;
	struct rpc_cred_cache *au_credcache;
};

struct rpc_credops {
	const char *cr_name;
	int (*cr_init)(struct rpc_auth *, struct rpc_cred *);
	void (*crdestroy)(struct rpc_cred *);
	int (*crmatch)(struct auth_cred *, struct rpc_cred *, int);
	int (*crmarshal)(struct rpc_task *, struct xdr_stream *);
	int (*crrefresh)(struct rpc_task *);
	int (*crvalidate)(struct rpc_task *, struct xdr_stream *);
	int (*crwrap_req)(struct rpc_task *, struct xdr_stream *);
	int (*crunwrap_resp)(struct rpc_task *, struct xdr_stream *);
	int (*crkey_timeout)(struct rpc_cred *);
	char * (*crstringify_acceptor)(struct rpc_cred *);
	bool (*crneed_reencode)(struct rpc_task *);
};

struct rpc_auth_create_args;

struct rpcsec_gss_info;

struct rpc_authops {
	struct module *owner;
	rpc_authflavor_t au_flavor;
	char *au_name;
	struct rpc_auth * (*create)(const struct rpc_auth_create_args *, struct rpc_clnt *);
	void (*destroy)(struct rpc_auth *);
	int (*hash_cred)(struct auth_cred *, unsigned int);
	struct rpc_cred * (*lookup_cred)(struct rpc_auth *, struct auth_cred *, int);
	struct rpc_cred * (*crcreate)(struct rpc_auth *, struct auth_cred *, int, gfp_t);
	rpc_authflavor_t (*info2flavor)(struct rpcsec_gss_info *);
	int (*flavor2info)(rpc_authflavor_t, struct rpcsec_gss_info *);
	int (*key_timeout)(struct rpc_auth *, struct rpc_cred *);
};

struct rpc_auth_create_args {
	rpc_authflavor_t pseudoflavor;
	const char *target_name;
};

struct rpcsec_gss_oid {
	unsigned int len;
	u8 data[32];
};

struct rpcsec_gss_info {
	struct rpcsec_gss_oid oid;
	u32 qop;
	u32 service;
};

struct rpc_stat {
	const struct rpc_program *program;
	unsigned int netcnt;
	unsigned int netudpcnt;
	unsigned int nettcpcnt;
	unsigned int nettcpconn;
	unsigned int netreconn;
	unsigned int rpccnt;
	unsigned int rpcretrans;
	unsigned int rpcauthrefresh;
	unsigned int rpcgarbage;
};

struct rpc_version;

struct rpc_program {
	const char *name;
	u32 number;
	unsigned int nrvers;
	const struct rpc_version **version;
	struct rpc_stat *stats;
	const char *pipe_dir_name;
};

struct svc_program;

struct svc_stat {
	struct svc_program *program;
	unsigned int netcnt;
	unsigned int netudpcnt;
	unsigned int nettcpcnt;
	unsigned int nettcpconn;
	unsigned int rpccnt;
	unsigned int rpcbadfmt;
	unsigned int rpcbadauth;
	unsigned int rpcbadclnt;
};

struct svc_version;

struct svc_rqst;

struct svc_process_info;

struct svc_program {
	struct svc_program *pg_next;
	u32 pg_prog;
	unsigned int pg_lovers;
	unsigned int pg_hivers;
	unsigned int pg_nvers;
	const struct svc_version **pg_vers;
	char *pg_name;
	char *pg_class;
	struct svc_stat *pg_stats;
	int (*pg_authenticate)(struct svc_rqst *);
	__be32 (*pg_init_request)(struct svc_rqst *, const struct svc_program *, struct svc_process_info *);
	int (*pg_rpcbind_set)(struct net *, const struct svc_program *, u32, int, short unsigned int, short unsigned int);
};

struct rpc_pipe_msg {
	struct list_head list;
	void *data;
	size_t len;
	size_t copied;
	int errno;
};

struct rpc_pipe_ops {
	ssize_t (*upcall)(struct file *, struct rpc_pipe_msg *, char *, size_t);
	ssize_t (*downcall)(struct file *, const char *, size_t);
	void (*release_pipe)(struct inode *);
	int (*open_pipe)(struct inode *);
	void (*destroy_msg)(struct rpc_pipe_msg *);
};

struct rpc_pipe {
	struct list_head pipe;
	struct list_head in_upcall;
	struct list_head in_downcall;
	int pipelen;
	int nreaders;
	int nwriters;
	int flags;
	struct delayed_work queue_timeout;
	const struct rpc_pipe_ops *ops;
	spinlock_t lock;
	struct dentry *dentry;
};

struct rpc_xprt_iter_ops {
	void (*xpi_rewind)(struct rpc_xprt_iter *);
	struct rpc_xprt * (*xpi_xprt)(struct rpc_xprt_iter *);
	struct rpc_xprt * (*xpi_next)(struct rpc_xprt_iter *);
};

struct rpc_iostats {
	spinlock_t om_lock;
	long unsigned int om_ops;
	long unsigned int om_ntrans;
	long unsigned int om_timeouts;
	long long unsigned int om_bytes_sent;
	long long unsigned int om_bytes_recv;
	ktime_t om_queue;
	ktime_t om_rtt;
	ktime_t om_execute;
	long unsigned int om_error_status;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct rpc_version {
	u32 number;
	unsigned int nrprocs;
	const struct rpc_procinfo *procs;
	unsigned int *counts;
};

struct rpc_create_args {
	struct net *net;
	int protocol;
	struct sockaddr *address;
	size_t addrsize;
	struct sockaddr *saddress;
	const struct rpc_timeout *timeout;
	const char *servername;
	const char *nodename;
	const struct rpc_program *program;
	u32 prognumber;
	u32 version;
	rpc_authflavor_t authflavor;
	u32 nconnect;
	long unsigned int flags;
	char *client_name;
	struct svc_xprt *bc_xprt;
	const struct cred *cred;
	unsigned int max_connect;
};

struct nfs_fh {
	short unsigned int size;
	unsigned char data[128];
};

enum nfs3_stable_how {
	NFS_UNSTABLE = 0,
	NFS_DATA_SYNC = 1,
	NFS_FILE_SYNC = 2,
	NFS_INVALID_STABLE_HOW = 4294967295,
};

struct nfs4_label {
	uint32_t lfs;
	uint32_t pi;
	u32 len;
	char *label;
};

struct nfs4_stateid_struct {
	union {
		char data[16];
		struct {
			__be32 seqid;
			char other[12];
		};
	};
	enum {
		NFS4_INVALID_STATEID_TYPE = 0,
		NFS4_SPECIAL_STATEID_TYPE = 1,
		NFS4_OPEN_STATEID_TYPE = 2,
		NFS4_LOCK_STATEID_TYPE = 3,
		NFS4_DELEGATION_STATEID_TYPE = 4,
		NFS4_LAYOUT_STATEID_TYPE = 5,
		NFS4_PNFS_DS_STATEID_TYPE = 6,
		NFS4_REVOKED_STATEID_TYPE = 7,
	} type;
};

typedef struct nfs4_stateid_struct nfs4_stateid;

enum nfs4_change_attr_type {
	NFS4_CHANGE_TYPE_IS_MONOTONIC_INCR = 0,
	NFS4_CHANGE_TYPE_IS_VERSION_COUNTER = 1,
	NFS4_CHANGE_TYPE_IS_VERSION_COUNTER_NOPNFS = 2,
	NFS4_CHANGE_TYPE_IS_TIME_METADATA = 3,
	NFS4_CHANGE_TYPE_IS_UNDEFINED = 4,
};

struct gss_api_mech;

struct gss_ctx {
	struct gss_api_mech *mech_type;
	void *internal_ctx_id;
	unsigned int slack;
	unsigned int align;
};

struct gss_api_ops;

struct pf_desc;

struct gss_api_mech {
	struct list_head gm_list;
	struct module *gm_owner;
	struct rpcsec_gss_oid gm_oid;
	char *gm_name;
	const struct gss_api_ops *gm_ops;
	int gm_pf_num;
	struct pf_desc *gm_pfs;
	const char *gm_upcall_enctypes;
};

struct auth_domain;

struct pf_desc {
	u32 pseudoflavor;
	u32 qop;
	u32 service;
	char *name;
	char *auth_domain_name;
	struct auth_domain *domain;
	bool datatouch;
};

struct auth_ops;

struct auth_domain {
	struct kref ref;
	struct hlist_node hash;
	char *name;
	struct auth_ops *flavour;
	struct callback_head callback_head;
};

struct gss_api_ops {
	int (*gss_import_sec_context)(const void *, size_t, struct gss_ctx *, time64_t *, gfp_t);
	u32 (*gss_get_mic)(struct gss_ctx *, struct xdr_buf *, struct xdr_netobj *);
	u32 (*gss_verify_mic)(struct gss_ctx *, struct xdr_buf *, struct xdr_netobj *);
	u32 (*gss_wrap)(struct gss_ctx *, int, struct xdr_buf *, struct page **);
	u32 (*gss_unwrap)(struct gss_ctx *, int, int, struct xdr_buf *);
	void (*gss_delete_sec_context)(void *);
};

struct nfs4_string {
	unsigned int len;
	char *data;
};

struct nfs_fsid {
	uint64_t major;
	uint64_t minor;
};

struct nfs4_threshold {
	__u32 bm;
	__u32 l_type;
	__u64 rd_sz;
	__u64 wr_sz;
	__u64 rd_io_sz;
	__u64 wr_io_sz;
};

struct nfs_fattr {
	unsigned int valid;
	umode_t mode;
	__u32 nlink;
	kuid_t uid;
	kgid_t gid;
	dev_t rdev;
	__u64 size;
	union {
		struct {
			__u32 blocksize;
			__u32 blocks;
		} nfs2;
		struct {
			__u64 used;
		} nfs3;
	} du;
	struct nfs_fsid fsid;
	__u64 fileid;
	__u64 mounted_on_fileid;
	struct timespec64 atime;
	struct timespec64 mtime;
	struct timespec64 ctime;
	__u64 change_attr;
	__u64 pre_change_attr;
	__u64 pre_size;
	struct timespec64 pre_mtime;
	struct timespec64 pre_ctime;
	long unsigned int time_start;
	long unsigned int gencount;
	struct nfs4_string *owner_name;
	struct nfs4_string *group_name;
	struct nfs4_threshold *mdsthreshold;
	struct nfs4_label *label;
};

struct nfs_fsinfo {
	struct nfs_fattr *fattr;
	__u32 rtmax;
	__u32 rtpref;
	__u32 rtmult;
	__u32 wtmax;
	__u32 wtpref;
	__u32 wtmult;
	__u32 dtpref;
	__u64 maxfilesize;
	struct timespec64 time_delta;
	__u32 lease_time;
	__u32 nlayouttypes;
	__u32 layouttype[8];
	__u32 blksize;
	__u32 clone_blksize;
	enum nfs4_change_attr_type change_attr_type;
	__u32 xattr_support;
};

struct nfs_fsstat {
	struct nfs_fattr *fattr;
	__u64 tbytes;
	__u64 fbytes;
	__u64 abytes;
	__u64 tfiles;
	__u64 ffiles;
	__u64 afiles;
};

struct nfs_pathconf {
	struct nfs_fattr *fattr;
	__u32 max_link;
	__u32 max_namelen;
};

struct nfs4_change_info {
	u32 atomic;
	u64 before;
	u64 after;
};

struct nfs4_slot;

struct nfs4_sequence_args {
	struct nfs4_slot *sa_slot;
	u8 sa_cache_this: 1;
	u8 sa_privileged: 1;
};

struct nfs4_sequence_res {
	struct nfs4_slot *sr_slot;
	long unsigned int sr_timestamp;
	int sr_status;
	u32 sr_status_flags;
	u32 sr_highest_slotid;
	u32 sr_target_highest_slotid;
};

struct pnfs_layout_range {
	u32 iomode;
	u64 offset;
	u64 length;
};

struct nfs_open_context;

struct nfs_lock_context {
	refcount_t count;
	struct list_head list;
	struct nfs_open_context *open_context;
	fl_owner_t lockowner;
	atomic_t io_count;
	struct callback_head callback_head;
};

struct nfs4_state;

struct nfs_open_context {
	struct nfs_lock_context lock_context;
	fl_owner_t flock_owner;
	struct dentry *dentry;
	const struct cred *cred;
	struct rpc_cred *ll_cred;
	struct nfs4_state *state;
	fmode_t mode;
	long unsigned int flags;
	int error;
	struct list_head list;
	struct nfs4_threshold *mdsthreshold;
	struct callback_head callback_head;
};

struct pnfs_layout_hdr;

struct nlm_host;

struct nfs_auth_info {
	unsigned int flavor_len;
	rpc_authflavor_t flavors[12];
};

struct nfs_client;

struct nfs_iostats;

struct nfs_server {
	struct nfs_client *nfs_client;
	struct list_head client_link;
	struct list_head master_link;
	struct rpc_clnt *client;
	struct rpc_clnt *client_acl;
	struct nlm_host *nlm_host;
	struct nfs_iostats *io_stats;
	atomic_long_t writeback;
	unsigned int write_congested;
	unsigned int flags;
	unsigned int fattr_valid;
	unsigned int caps;
	unsigned int rsize;
	unsigned int rpages;
	unsigned int wsize;
	unsigned int wpages;
	unsigned int wtmult;
	unsigned int dtsize;
	short unsigned int port;
	unsigned int bsize;
	unsigned int acregmin;
	unsigned int acregmax;
	unsigned int acdirmin;
	unsigned int acdirmax;
	unsigned int namelen;
	unsigned int options;
	unsigned int clone_blksize;
	enum nfs4_change_attr_type change_attr_type;
	struct nfs_fsid fsid;
	__u64 maxfilesize;
	struct timespec64 time_delta;
	long unsigned int mount_time;
	struct super_block *super;
	dev_t s_dev;
	struct nfs_auth_info auth_info;
	u32 pnfs_blksize;
	struct ida openowner_id;
	struct ida lockowner_id;
	struct list_head state_owners_lru;
	struct list_head layouts;
	struct list_head delegations;
	struct list_head ss_copies;
	long unsigned int mig_gen;
	long unsigned int mig_status;
	void (*destroy)(struct nfs_server *);
	atomic_t active;
	struct __kernel_sockaddr_storage mountd_address;
	size_t mountd_addrlen;
	u32 mountd_version;
	short unsigned int mountd_port;
	short unsigned int mountd_protocol;
	struct rpc_wait_queue uoc_rpcwaitq;
	unsigned int read_hdrsize;
	const struct cred *cred;
	bool has_sec_mnt_opts;
};

struct nfs_rpc_ops;

struct nfs_subversion;

struct nfs_client {
	refcount_t cl_count;
	atomic_t cl_mds_count;
	int cl_cons_state;
	long unsigned int cl_res_state;
	long unsigned int cl_flags;
	struct __kernel_sockaddr_storage cl_addr;
	size_t cl_addrlen;
	char *cl_hostname;
	char *cl_acceptor;
	struct list_head cl_share_link;
	struct list_head cl_superblocks;
	struct rpc_clnt *cl_rpcclient;
	const struct nfs_rpc_ops *rpc_ops;
	int cl_proto;
	struct nfs_subversion *cl_nfs_mod;
	u32 cl_minorversion;
	unsigned int cl_nconnect;
	unsigned int cl_max_connect;
	const char *cl_principal;
	char cl_ipaddr[48];
	struct net *cl_net;
	struct list_head pending_cb_stateids;
};

struct pnfs_layout_segment {
	struct list_head pls_list;
	struct list_head pls_lc_list;
	struct list_head pls_commits;
	struct pnfs_layout_range pls_range;
	refcount_t pls_refcount;
	u32 pls_seq;
	long unsigned int pls_flags;
	struct pnfs_layout_hdr *pls_layout;
};

struct nfs_write_verifier {
	char data[8];
};

struct nfs_writeverf {
	struct nfs_write_verifier verifier;
	enum nfs3_stable_how committed;
};

struct nfs_pgio_args {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	struct nfs_open_context *context;
	struct nfs_lock_context *lock_context;
	nfs4_stateid stateid;
	__u64 offset;
	__u32 count;
	unsigned int pgbase;
	struct page **pages;
	union {
		unsigned int replen;
		struct {
			const u32 *bitmask;
			u32 bitmask_store[3];
			enum nfs3_stable_how stable;
		};
	};
};

struct nfs_pgio_res {
	struct nfs4_sequence_res seq_res;
	struct nfs_fattr *fattr;
	__u64 count;
	__u32 op_status;
	union {
		struct {
			unsigned int replen;
			int eof;
		};
		struct {
			struct nfs_writeverf *verf;
			const struct nfs_server *server;
		};
	};
};

struct nfs_commitargs {
	struct nfs4_sequence_args seq_args;
	struct nfs_fh *fh;
	__u64 offset;
	__u32 count;
	const u32 *bitmask;
};

struct nfs_commitres {
	struct nfs4_sequence_res seq_res;
	__u32 op_status;
	struct nfs_fattr *fattr;
	struct nfs_writeverf *verf;
	const struct nfs_server *server;
};

struct nfs_removeargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *fh;
	struct qstr name;
};

struct nfs_removeres {
	struct nfs4_sequence_res seq_res;
	struct nfs_server *server;
	struct nfs_fattr *dir_attr;
	struct nfs4_change_info cinfo;
};

struct nfs_renameargs {
	struct nfs4_sequence_args seq_args;
	const struct nfs_fh *old_dir;
	const struct nfs_fh *new_dir;
	const struct qstr *old_name;
	const struct qstr *new_name;
};

struct nfs_renameres {
	struct nfs4_sequence_res seq_res;
	struct nfs_server *server;
	struct nfs4_change_info old_cinfo;
	struct nfs_fattr *old_fattr;
	struct nfs4_change_info new_cinfo;
	struct nfs_fattr *new_fattr;
};

struct nfs_entry {
	__u64 ino;
	__u64 cookie;
	const char *name;
	unsigned int len;
	int eof;
	struct nfs_fh *fh;
	struct nfs_fattr *fattr;
	unsigned char d_type;
	struct nfs_server *server;
};

struct nfs_readdir_arg {
	struct dentry *dentry;
	const struct cred *cred;
	__be32 *verf;
	u64 cookie;
	struct page **pages;
	unsigned int page_len;
	bool plus;
};

struct nfs_readdir_res {
	__be32 *verf;
};

struct pnfs_ds_commit_info {};

struct nfs_page_array {
	struct page **pagevec;
	unsigned int npages;
	struct page *page_array[8];
};

struct nfs_page;

struct nfs_pgio_completion_ops;

struct nfs_rw_ops;

struct nfs_io_completion;

struct nfs_direct_req;

struct nfs_pgio_header {
	struct inode *inode;
	const struct cred *cred;
	struct list_head pages;
	struct nfs_page *req;
	struct nfs_writeverf verf;
	fmode_t rw_mode;
	struct pnfs_layout_segment *lseg;
	loff_t io_start;
	const struct rpc_call_ops *mds_ops;
	void (*release)(struct nfs_pgio_header *);
	const struct nfs_pgio_completion_ops *completion_ops;
	const struct nfs_rw_ops *rw_ops;
	struct nfs_io_completion *io_completion;
	struct nfs_direct_req *dreq;
	int pnfs_error;
	int error;
	unsigned int good_bytes;
	long unsigned int flags;
	struct rpc_task task;
	struct nfs_fattr fattr;
	struct nfs_pgio_args args;
	struct nfs_pgio_res res;
	long unsigned int timestamp;
	int (*pgio_done_cb)(struct rpc_task *, struct nfs_pgio_header *);
	__u64 mds_offset;
	struct nfs_page_array page_array;
	struct nfs_client *ds_clp;
	u32 ds_commit_idx;
	u32 pgio_mirror_idx;
};

struct nfs_page {
	struct list_head wb_list;
	struct page *wb_page;
	struct nfs_lock_context *wb_lock_context;
	long unsigned int wb_index;
	unsigned int wb_offset;
	unsigned int wb_pgbase;
	unsigned int wb_bytes;
	struct kref wb_kref;
	long unsigned int wb_flags;
	struct nfs_write_verifier wb_verf;
	struct nfs_page *wb_this_page;
	struct nfs_page *wb_head;
	short unsigned int wb_nio;
};

struct nfs_pgio_completion_ops {
	void (*error_cleanup)(struct list_head *, int);
	void (*init_hdr)(struct nfs_pgio_header *);
	void (*completion)(struct nfs_pgio_header *);
	void (*reschedule_io)(struct nfs_pgio_header *);
};

struct nfs_rw_ops {
	struct nfs_pgio_header * (*rw_alloc_header)();
	void (*rw_free_header)(struct nfs_pgio_header *);
	int (*rw_done)(struct rpc_task *, struct nfs_pgio_header *, struct inode *);
	void (*rw_result)(struct rpc_task *, struct nfs_pgio_header *);
	void (*rw_initiate)(struct nfs_pgio_header *, struct rpc_message *, const struct nfs_rpc_ops *, struct rpc_task_setup *, int);
};

struct nfs_mds_commit_info {
	atomic_t rpcs_out;
	atomic_long_t ncommit;
	struct list_head list;
};

struct nfs_commit_data;

struct nfs_commit_info;

struct nfs_commit_completion_ops {
	void (*completion)(struct nfs_commit_data *);
	void (*resched_write)(struct nfs_commit_info *, struct nfs_page *);
};

struct nfs_commit_data {
	struct rpc_task task;
	struct inode *inode;
	const struct cred *cred;
	struct nfs_fattr fattr;
	struct nfs_writeverf verf;
	struct list_head pages;
	struct list_head list;
	struct nfs_direct_req *dreq;
	struct nfs_commitargs args;
	struct nfs_commitres res;
	struct nfs_open_context *context;
	struct pnfs_layout_segment *lseg;
	struct nfs_client *ds_clp;
	int ds_commit_index;
	loff_t lwb;
	const struct rpc_call_ops *mds_ops;
	const struct nfs_commit_completion_ops *completion_ops;
	int (*commit_done_cb)(struct rpc_task *, struct nfs_commit_data *);
	long unsigned int flags;
};

struct nfs_commit_info {
	struct inode *inode;
	struct nfs_mds_commit_info *mds;
	struct pnfs_ds_commit_info *ds;
	struct nfs_direct_req *dreq;
	const struct nfs_commit_completion_ops *completion_ops;
};

struct nfs_unlinkdata {
	struct nfs_removeargs args;
	struct nfs_removeres res;
	struct dentry *dentry;
	wait_queue_head_t wq;
	const struct cred *cred;
	struct nfs_fattr dir_attr;
	long int timeout;
};

struct nfs_renamedata {
	struct nfs_renameargs args;
	struct nfs_renameres res;
	struct rpc_task task;
	const struct cred *cred;
	struct inode *old_dir;
	struct dentry *old_dentry;
	struct nfs_fattr old_fattr;
	struct inode *new_dir;
	struct dentry *new_dentry;
	struct nfs_fattr new_fattr;
	void (*complete)(struct rpc_task *, struct nfs_renamedata *);
	long int timeout;
	bool cancelled;
};

struct nlmclnt_operations;

struct nfs_access_entry;

struct nfs_client_initdata;

struct nfs_rpc_ops {
	u32 version;
	const struct dentry_operations *dentry_ops;
	const struct inode_operations *dir_inode_ops;
	const struct inode_operations *file_inode_ops;
	const struct file_operations *file_ops;
	const struct nlmclnt_operations *nlmclnt_ops;
	int (*getroot)(struct nfs_server *, struct nfs_fh *, struct nfs_fsinfo *);
	int (*submount)(struct fs_context *, struct nfs_server *);
	int (*try_get_tree)(struct fs_context *);
	int (*getattr)(struct nfs_server *, struct nfs_fh *, struct nfs_fattr *, struct inode *);
	int (*setattr)(struct dentry *, struct nfs_fattr *, struct iattr *);
	int (*lookup)(struct inode *, struct dentry *, struct nfs_fh *, struct nfs_fattr *);
	int (*lookupp)(struct inode *, struct nfs_fh *, struct nfs_fattr *);
	int (*access)(struct inode *, struct nfs_access_entry *, const struct cred *);
	int (*readlink)(struct inode *, struct page *, unsigned int, unsigned int);
	int (*create)(struct inode *, struct dentry *, struct iattr *, int);
	int (*remove)(struct inode *, struct dentry *);
	void (*unlink_setup)(struct rpc_message *, struct dentry *, struct inode *);
	void (*unlink_rpc_prepare)(struct rpc_task *, struct nfs_unlinkdata *);
	int (*unlink_done)(struct rpc_task *, struct inode *);
	void (*rename_setup)(struct rpc_message *, struct dentry *, struct dentry *);
	void (*rename_rpc_prepare)(struct rpc_task *, struct nfs_renamedata *);
	int (*rename_done)(struct rpc_task *, struct inode *, struct inode *);
	int (*link)(struct inode *, struct inode *, const struct qstr *);
	int (*symlink)(struct inode *, struct dentry *, struct page *, unsigned int, struct iattr *);
	int (*mkdir)(struct inode *, struct dentry *, struct iattr *);
	int (*rmdir)(struct inode *, const struct qstr *);
	int (*readdir)(struct nfs_readdir_arg *, struct nfs_readdir_res *);
	int (*mknod)(struct inode *, struct dentry *, struct iattr *, dev_t);
	int (*statfs)(struct nfs_server *, struct nfs_fh *, struct nfs_fsstat *);
	int (*fsinfo)(struct nfs_server *, struct nfs_fh *, struct nfs_fsinfo *);
	int (*pathconf)(struct nfs_server *, struct nfs_fh *, struct nfs_pathconf *);
	int (*set_capabilities)(struct nfs_server *, struct nfs_fh *);
	int (*decode_dirent)(struct xdr_stream *, struct nfs_entry *, bool);
	int (*pgio_rpc_prepare)(struct rpc_task *, struct nfs_pgio_header *);
	void (*read_setup)(struct nfs_pgio_header *, struct rpc_message *);
	int (*read_done)(struct rpc_task *, struct nfs_pgio_header *);
	void (*write_setup)(struct nfs_pgio_header *, struct rpc_message *, struct rpc_clnt **);
	int (*write_done)(struct rpc_task *, struct nfs_pgio_header *);
	void (*commit_setup)(struct nfs_commit_data *, struct rpc_message *, struct rpc_clnt **);
	void (*commit_rpc_prepare)(struct rpc_task *, struct nfs_commit_data *);
	int (*commit_done)(struct rpc_task *, struct nfs_commit_data *);
	int (*lock)(struct file *, int, struct file_lock *);
	int (*lock_check_bounds)(const struct file_lock *);
	void (*clear_acl_cache)(struct inode *);
	void (*close_context)(struct nfs_open_context *, int);
	struct inode * (*open_context)(struct inode *, struct nfs_open_context *, int, struct iattr *, int *);
	int (*have_delegation)(struct inode *, fmode_t);
	struct nfs_client * (*alloc_client)(const struct nfs_client_initdata *);
	struct nfs_client * (*init_client)(struct nfs_client *, const struct nfs_client_initdata *);
	void (*free_client)(struct nfs_client *);
	struct nfs_server * (*create_server)(struct fs_context *);
	struct nfs_server * (*clone_server)(struct nfs_server *, struct nfs_fh *, struct nfs_fattr *, rpc_authflavor_t);
	int (*discover_trunking)(struct nfs_server *, struct nfs_fh *);
	void (*enable_swap)(struct inode *);
	void (*disable_swap)(struct inode *);
};

struct nlmclnt_operations {
	void (*nlmclnt_alloc_call)(void *);
	bool (*nlmclnt_unlock_prepare)(struct rpc_task *, void *);
	void (*nlmclnt_release_call)(void *);
};

struct nfs_access_entry {
	struct rb_node rb_node;
	struct list_head lru;
	kuid_t fsuid;
	kgid_t fsgid;
	struct group_info *group_info;
	__u32 mask;
	struct callback_head callback_head;
};

struct nfs_client_initdata {
	long unsigned int init_flags;
	const char *hostname;
	const struct sockaddr *addr;
	const char *nodename;
	const char *ip_addr;
	size_t addrlen;
	struct nfs_subversion *nfs_mod;
	int proto;
	u32 minorversion;
	unsigned int nconnect;
	unsigned int max_connect;
	struct net *net;
	const struct rpc_timeout *timeparms;
	const struct cred *cred;
};

struct nfs_subversion {
	struct module *owner;
	struct file_system_type *nfs_fs;
	const struct rpc_version *rpc_vers;
	const struct nfs_rpc_ops *rpc_ops;
	const struct super_operations *sops;
	const struct xattr_handler **xattr;
	struct list_head list;
};

struct nfs_iostats {
	long long unsigned int bytes[8];
	long unsigned int events[27];
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct svc_cred {
	kuid_t cr_uid;
	kgid_t cr_gid;
	struct group_info *cr_group_info;
	u32 cr_flavor;
	char *cr_raw_principal;
	char *cr_principal;
	char *cr_targ_princ;
	struct gss_api_mech *cr_gss_mech;
};

struct cache_deferred_req;

struct cache_req {
	struct cache_deferred_req * (*defer)(struct cache_req *);
	int thread_wait;
};

struct svc_cacherep;

struct svc_pool;

struct svc_procedure;

struct svc_deferred_req;

struct svc_rqst {
	struct list_head rq_all;
	struct callback_head rq_rcu_head;
	struct svc_xprt *rq_xprt;
	struct __kernel_sockaddr_storage rq_addr;
	size_t rq_addrlen;
	struct __kernel_sockaddr_storage rq_daddr;
	size_t rq_daddrlen;
	struct svc_serv *rq_server;
	struct svc_pool *rq_pool;
	const struct svc_procedure *rq_procinfo;
	struct auth_ops *rq_authop;
	struct svc_cred rq_cred;
	void *rq_xprt_ctxt;
	struct svc_deferred_req *rq_deferred;
	size_t rq_xprt_hlen;
	struct xdr_buf rq_arg;
	struct xdr_stream rq_arg_stream;
	struct xdr_stream rq_res_stream;
	struct page *rq_scratch_page;
	struct xdr_buf rq_res;
	struct page *rq_pages[132];
	struct page **rq_respages;
	struct page **rq_next_page;
	struct page **rq_page_end;
	struct pagevec rq_pvec;
	struct kvec rq_vec[131];
	struct bio_vec rq_bvec[131];
	__be32 rq_xid;
	u32 rq_prog;
	u32 rq_vers;
	u32 rq_proc;
	u32 rq_prot;
	int rq_cachetype;
	long unsigned int rq_flags;
	ktime_t rq_qtime;
	void *rq_argp;
	void *rq_resp;
	void *rq_auth_data;
	__be32 rq_auth_stat;
	int rq_auth_slack;
	int rq_reserved;
	ktime_t rq_stime;
	struct cache_req rq_chandle;
	struct auth_domain *rq_client;
	struct auth_domain *rq_gssclient;
	struct svc_cacherep *rq_cacherep;
	struct task_struct *rq_task;
	spinlock_t rq_lock;
	struct net *rq_bc_net;
	void **rq_lease_breaker;
};

struct nlmclnt_initdata {
	const char *hostname;
	const struct sockaddr *address;
	size_t addrlen;
	short unsigned int protocol;
	u32 nfs_version;
	int noresvport;
	struct net *net;
	const struct nlmclnt_operations *nlmclnt_ops;
	const struct cred *cred;
};

struct cache_head {
	struct hlist_node cache_list;
	time64_t expiry_time;
	time64_t last_refresh;
	struct kref ref;
	long unsigned int flags;
};

struct cache_detail {
	struct module *owner;
	int hash_size;
	struct hlist_head *hash_table;
	spinlock_t hash_lock;
	char *name;
	void (*cache_put)(struct kref *);
	int (*cache_upcall)(struct cache_detail *, struct cache_head *);
	void (*cache_request)(struct cache_detail *, struct cache_head *, char **, int *);
	int (*cache_parse)(struct cache_detail *, char *, int);
	int (*cache_show)(struct seq_file *, struct cache_detail *, struct cache_head *);
	void (*warn_no_listener)(struct cache_detail *, int);
	struct cache_head * (*alloc)();
	void (*flush)();
	int (*match)(struct cache_head *, struct cache_head *);
	void (*init)(struct cache_head *, struct cache_head *);
	void (*update)(struct cache_head *, struct cache_head *);
	time64_t flush_time;
	struct list_head others;
	time64_t nextcheck;
	int entries;
	struct list_head queue;
	atomic_t writers;
	time64_t last_close;
	time64_t last_warn;
	union {
		struct proc_dir_entry *procfs;
		struct dentry *pipefs;
	};
	struct net *net;
};

struct cache_deferred_req {
	struct hlist_node hash;
	struct list_head recent;
	struct cache_head *item;
	void *owner;
	void (*revisit)(struct cache_deferred_req *, int);
};

struct auth_ops {
	char *name;
	struct module *owner;
	int flavour;
	int (*accept)(struct svc_rqst *);
	int (*release)(struct svc_rqst *);
	void (*domain_release)(struct auth_domain *);
	int (*set_client)(struct svc_rqst *);
};

struct svc_pool_stats {
	atomic_long_t packets;
	long unsigned int sockets_queued;
	atomic_long_t threads_woken;
	atomic_long_t threads_timedout;
};

struct svc_pool {
	unsigned int sp_id;
	spinlock_t sp_lock;
	struct list_head sp_sockets;
	unsigned int sp_nrthreads;
	struct list_head sp_all_threads;
	struct svc_pool_stats sp_stats;
	long unsigned int sp_flags;
};

struct svc_serv {
	struct svc_program *sv_program;
	struct svc_stat *sv_stats;
	spinlock_t sv_lock;
	struct kref sv_refcnt;
	unsigned int sv_nrthreads;
	unsigned int sv_maxconn;
	unsigned int sv_max_payload;
	unsigned int sv_max_mesg;
	unsigned int sv_xdrsize;
	struct list_head sv_permsocks;
	struct list_head sv_tempsocks;
	int sv_tmpcnt;
	struct timer_list sv_temptimer;
	char *sv_name;
	unsigned int sv_nrpools;
	struct svc_pool *sv_pools;
	int (*sv_threadfn)(void *);
};

struct svc_procedure {
	__be32 (*pc_func)(struct svc_rqst *);
	bool (*pc_decode)(struct svc_rqst *, struct xdr_stream *);
	bool (*pc_encode)(struct svc_rqst *, struct xdr_stream *);
	void (*pc_release)(struct svc_rqst *);
	unsigned int pc_argsize;
	unsigned int pc_ressize;
	unsigned int pc_cachetype;
	unsigned int pc_xdrressize;
	const char *pc_name;
};

struct svc_deferred_req {
	u32 prot;
	struct svc_xprt *xprt;
	struct __kernel_sockaddr_storage addr;
	size_t addrlen;
	struct __kernel_sockaddr_storage daddr;
	size_t daddrlen;
	void *xprt_ctxt;
	struct cache_deferred_req handle;
	size_t xprt_hlen;
	int argslen;
	__be32 args[0];
};

struct svc_process_info {
	union {
		int (*dispatch)(struct svc_rqst *, __be32 *);
		struct {
			unsigned int lovers;
			unsigned int hivers;
		} mismatch;
	};
};

struct svc_version {
	u32 vs_vers;
	u32 vs_nproc;
	const struct svc_procedure *vs_proc;
	unsigned int *vs_count;
	u32 vs_xdrsize;
	bool vs_hidden;
	bool vs_rpcb_optnl;
	bool vs_need_cong_ctrl;
	int (*vs_dispatch)(struct svc_rqst *, __be32 *);
};

struct svc_xprt_ops {
	struct svc_xprt * (*xpo_create)(struct svc_serv *, struct net *, struct sockaddr *, int, int);
	struct svc_xprt * (*xpo_accept)(struct svc_xprt *);
	int (*xpo_has_wspace)(struct svc_xprt *);
	int (*xpo_recvfrom)(struct svc_rqst *);
	int (*xpo_sendto)(struct svc_rqst *);
	int (*xpo_result_payload)(struct svc_rqst *, unsigned int, unsigned int);
	void (*xpo_release_rqst)(struct svc_rqst *);
	void (*xpo_detach)(struct svc_xprt *);
	void (*xpo_free)(struct svc_xprt *);
	void (*xpo_secure_port)(struct svc_rqst *);
	void (*xpo_kill_temp_xprt)(struct svc_xprt *);
	void (*xpo_start_tls)(struct svc_xprt *);
};

struct svc_xprt_class {
	const char *xcl_name;
	struct module *xcl_owner;
	const struct svc_xprt_ops *xcl_ops;
	struct list_head xcl_list;
	u32 xcl_max_payload;
	int xcl_ident;
};

enum nfs_stat_bytecounters {
	NFSIOS_NORMALREADBYTES = 0,
	NFSIOS_NORMALWRITTENBYTES = 1,
	NFSIOS_DIRECTREADBYTES = 2,
	NFSIOS_DIRECTWRITTENBYTES = 3,
	NFSIOS_SERVERREADBYTES = 4,
	NFSIOS_SERVERWRITTENBYTES = 5,
	NFSIOS_READPAGES = 6,
	NFSIOS_WRITEPAGES = 7,
	__NFSIOS_BYTESMAX = 8,
};

enum nfs_stat_eventcounters {
	NFSIOS_INODEREVALIDATE = 0,
	NFSIOS_DENTRYREVALIDATE = 1,
	NFSIOS_DATAINVALIDATE = 2,
	NFSIOS_ATTRINVALIDATE = 3,
	NFSIOS_VFSOPEN = 4,
	NFSIOS_VFSLOOKUP = 5,
	NFSIOS_VFSACCESS = 6,
	NFSIOS_VFSUPDATEPAGE = 7,
	NFSIOS_VFSREADPAGE = 8,
	NFSIOS_VFSREADPAGES = 9,
	NFSIOS_VFSWRITEPAGE = 10,
	NFSIOS_VFSWRITEPAGES = 11,
	NFSIOS_VFSGETDENTS = 12,
	NFSIOS_VFSSETATTR = 13,
	NFSIOS_VFSFLUSH = 14,
	NFSIOS_VFSFSYNC = 15,
	NFSIOS_VFSLOCK = 16,
	NFSIOS_VFSRELEASE = 17,
	NFSIOS_CONGESTIONWAIT = 18,
	NFSIOS_SETATTRTRUNC = 19,
	NFSIOS_EXTENDWRITE = 20,
	NFSIOS_SILLYRENAME = 21,
	NFSIOS_SHORTREAD = 22,
	NFSIOS_SHORTWRITE = 23,
	NFSIOS_DELAY = 24,
	NFSIOS_PNFS_READ = 25,
	NFSIOS_PNFS_WRITE = 26,
	__NFSIOS_COUNTSMAX = 27,
};

struct nfs_clone_mount {
	struct super_block *sb;
	struct dentry *dentry;
	struct nfs_fattr *fattr;
	unsigned int inherited_bsize;
};

struct nfs_fs_context {
	bool internal;
	bool skip_reconfig_option_check;
	bool need_mount;
	bool sloppy;
	unsigned int flags;
	unsigned int rsize;
	unsigned int wsize;
	unsigned int timeo;
	unsigned int retrans;
	unsigned int acregmin;
	unsigned int acregmax;
	unsigned int acdirmin;
	unsigned int acdirmax;
	unsigned int namlen;
	unsigned int options;
	unsigned int bsize;
	struct nfs_auth_info auth_info;
	rpc_authflavor_t selected_flavor;
	char *client_address;
	unsigned int version;
	unsigned int minorversion;
	char *fscache_uniq;
	short unsigned int protofamily;
	short unsigned int mountfamily;
	bool has_sec_mnt_opts;
	struct {
		union {
			struct sockaddr address;
			struct __kernel_sockaddr_storage _address;
		};
		size_t addrlen;
		char *hostname;
		u32 version;
		int port;
		short unsigned int protocol;
	} mount_server;
	struct {
		union {
			struct sockaddr address;
			struct __kernel_sockaddr_storage _address;
		};
		size_t addrlen;
		char *hostname;
		char *export_path;
		int port;
		short unsigned int protocol;
		short unsigned int nconnect;
		short unsigned int max_connect;
		short unsigned int export_path_len;
	} nfs_server;
	struct nfs_fh *mntfh;
	struct nfs_server *server;
	struct nfs_subversion *nfs_mod;
	struct nfs_clone_mount clone_data;
};

struct bl_dev_msg {
	int32_t status;
	uint32_t major;
	uint32_t minor;
};

struct nfs_netns_client;

struct nfs_net {
	struct cache_detail *nfs_dns_resolve;
	struct rpc_pipe *bl_device_pipe;
	struct bl_dev_msg bl_mount_reply;
	wait_queue_head_t bl_wq;
	struct mutex bl_mutex;
	struct list_head nfs_client_list;
	struct list_head nfs_volume_list;
	struct nfs_netns_client *nfs_client;
	spinlock_t nfs_client_lock;
	ktime_t boot_time;
	struct proc_dir_entry *proc_nfsfs;
};

struct nfs_netns_client {
	struct kobject kobject;
	struct net *net;
	const char *identifier;
};

struct nfs_open_dir_context {
	struct list_head list;
	atomic_t cache_hits;
	atomic_t cache_misses;
	long unsigned int attr_gencount;
	__be32 verf[2];
	__u64 dir_cookie;
	__u64 last_cookie;
	long unsigned int page_index;
	unsigned int dtsize;
	bool force_clear;
	bool eof;
	struct callback_head callback_head;
};

struct nfs_inode {
	__u64 fileid;
	struct nfs_fh fh;
	long unsigned int flags;
	long unsigned int cache_validity;
	long unsigned int read_cache_jiffies;
	long unsigned int attrtimeo;
	long unsigned int attrtimeo_timestamp;
	long unsigned int attr_gencount;
	struct rb_root access_cache;
	struct list_head access_cache_entry_lru;
	struct list_head access_cache_inode_lru;
	union {
		struct {
			long unsigned int cache_change_attribute;
			__be32 cookieverf[2];
			struct rw_semaphore rmdir_sem;
		};
		struct {
			atomic_long_t nrequests;
			struct nfs_mds_commit_info commit_info;
			struct mutex commit_mutex;
		};
	};
	struct list_head open_files;
	__u64 write_io;
	__u64 read_io;
	struct inode vfs_inode;
};

struct nfs_cache_array_entry {
	u64 cookie;
	u64 ino;
	const char *name;
	unsigned int name_len;
	unsigned char d_type;
};

struct nfs_cache_array {
	u64 change_attr;
	u64 last_cookie;
	unsigned int size;
	unsigned char page_full: 1;
	unsigned char page_is_eof: 1;
	unsigned char cookies_are_ordered: 1;
	struct nfs_cache_array_entry array[0];
};

struct nfs_readdir_descriptor {
	struct file *file;
	struct page *page;
	struct dir_context *ctx;
	long unsigned int page_index;
	long unsigned int page_index_max;
	u64 dir_cookie;
	u64 last_cookie;
	loff_t current_index;
	__be32 verf[2];
	long unsigned int dir_verifier;
	long unsigned int timestamp;
	long unsigned int gencount;
	long unsigned int attr_gencount;
	unsigned int cache_entry_index;
	unsigned int buffer_fills;
	unsigned int dtsize;
	bool clear_cache;
	bool plus;
	bool eob;
	bool eof;
};

struct nfs_find_desc {
	struct nfs_fh *fh;
	struct nfs_fattr *fattr;
};

struct nfs_mount_request {
	struct sockaddr *sap;
	size_t salen;
	char *hostname;
	char *dirpath;
	u32 version;
	short unsigned int protocol;
	struct nfs_fh *fh;
	int noresvport;
	unsigned int *auth_flav_len;
	rpc_authflavor_t *auth_flavs;
	struct net *net;
};

struct proc_nfs_info {
	int flag;
	const char *str;
	const char *nostr;
};

enum {
	NFS_IOHDR_ERROR = 0,
	NFS_IOHDR_EOF = 1,
	NFS_IOHDR_REDO = 2,
	NFS_IOHDR_STAT = 3,
	NFS_IOHDR_RESEND_PNFS = 4,
	NFS_IOHDR_RESEND_MDS = 5,
};

struct nfs_direct_req {
	struct kref kref;
	struct nfs_open_context *ctx;
	struct nfs_lock_context *l_ctx;
	struct kiocb *iocb;
	struct inode *inode;
	atomic_t io_count;
	spinlock_t lock;
	loff_t io_start;
	ssize_t count;
	ssize_t max_count;
	ssize_t bytes_left;
	ssize_t error;
	struct completion completion;
	struct nfs_mds_commit_info mds_cinfo;
	struct pnfs_ds_commit_info ds_cinfo;
	struct work_struct work;
	int flags;
};

enum {
	PG_BUSY = 0,
	PG_MAPPED = 1,
	PG_CLEAN = 2,
	PG_COMMIT_TO_DS = 3,
	PG_INODE_REF = 4,
	PG_HEADLOCK = 5,
	PG_TEARDOWN = 6,
	PG_UNLOCKPAGE = 7,
	PG_UPTODATE = 8,
	PG_WB_END = 9,
	PG_REMOVE = 10,
	PG_CONTENDED1 = 11,
	PG_CONTENDED2 = 12,
};

struct nfs_pageio_descriptor;

struct nfs_pgio_mirror;

struct nfs_pageio_ops {
	void (*pg_init)(struct nfs_pageio_descriptor *, struct nfs_page *);
	size_t (*pg_test)(struct nfs_pageio_descriptor *, struct nfs_page *, struct nfs_page *);
	int (*pg_doio)(struct nfs_pageio_descriptor *);
	unsigned int (*pg_get_mirror_count)(struct nfs_pageio_descriptor *, struct nfs_page *);
	void (*pg_cleanup)(struct nfs_pageio_descriptor *);
	struct nfs_pgio_mirror * (*pg_get_mirror)(struct nfs_pageio_descriptor *, u32);
	u32 (*pg_set_mirror)(struct nfs_pageio_descriptor *, u32);
};

struct nfs_pgio_mirror {
	struct list_head pg_list;
	long unsigned int pg_bytes_written;
	size_t pg_count;
	size_t pg_bsize;
	unsigned int pg_base;
	unsigned char pg_recoalesce: 1;
};

struct nfs_pageio_descriptor {
	struct inode *pg_inode;
	const struct nfs_pageio_ops *pg_ops;
	const struct nfs_rw_ops *pg_rw_ops;
	int pg_ioflags;
	int pg_error;
	const struct rpc_call_ops *pg_rpc_callops;
	const struct nfs_pgio_completion_ops *pg_completion_ops;
	struct pnfs_layout_segment *pg_lseg;
	struct nfs_io_completion *pg_io_completion;
	struct nfs_direct_req *pg_dreq;
	unsigned int pg_bsize;
	u32 pg_mirror_count;
	struct nfs_pgio_mirror *pg_mirrors;
	struct nfs_pgio_mirror pg_mirrors_static[1];
	struct nfs_pgio_mirror *pg_mirrors_dynamic;
	u32 pg_mirror_idx;
	short unsigned int pg_maxretrans;
	unsigned char pg_moreio: 1;
};

typedef void (*rpc_action)(struct rpc_task *);

struct nfs_readdesc {
	struct nfs_pageio_descriptor pgio;
	struct nfs_open_context *ctx;
};

struct nfs_io_completion {
	void (*complete)(void *);
	void *data;
	struct kref refcount;
};

enum pnfs_try_status {
	PNFS_ATTEMPTED = 0,
	PNFS_NOT_ATTEMPTED = 1,
	PNFS_TRY_AGAIN = 2,
};

enum {
	MOUNTPROC_NULL = 0,
	MOUNTPROC_MNT = 1,
	MOUNTPROC_DUMP = 2,
	MOUNTPROC_UMNT = 3,
	MOUNTPROC_UMNTALL = 4,
	MOUNTPROC_EXPORT = 5,
};

enum {
	MOUNTPROC3_NULL = 0,
	MOUNTPROC3_MNT = 1,
	MOUNTPROC3_DUMP = 2,
	MOUNTPROC3_UMNT = 3,
	MOUNTPROC3_UMNTALL = 4,
	MOUNTPROC3_EXPORT = 5,
};

enum mountstat {
	MNT_OK = 0,
	MNT_EPERM = 1,
	MNT_ENOENT = 2,
	MNT_EACCES = 13,
	MNT_EINVAL = 22,
};

enum mountstat3 {
	MNT3_OK = 0,
	MNT3ERR_PERM = 1,
	MNT3ERR_NOENT = 2,
	MNT3ERR_IO = 5,
	MNT3ERR_ACCES = 13,
	MNT3ERR_NOTDIR = 20,
	MNT3ERR_INVAL = 22,
	MNT3ERR_NAMETOOLONG = 63,
	MNT3ERR_NOTSUPP = 10004,
	MNT3ERR_SERVERFAULT = 10006,
};

struct mountres {
	int errno;
	struct nfs_fh *fh;
	unsigned int *auth_count;
	rpc_authflavor_t *auth_flavors;
};

enum {
	FILEID_HIGH_OFF = 0,
	FILEID_LOW_OFF = 1,
	FILE_I_TYPE_OFF = 2,
	EMBED_FH_OFF = 3,
};

enum nfs_stat {
	NFS_OK = 0,
	NFSERR_PERM = 1,
	NFSERR_NOENT = 2,
	NFSERR_IO = 5,
	NFSERR_NXIO = 6,
	NFSERR_EAGAIN = 11,
	NFSERR_ACCES = 13,
	NFSERR_EXIST = 17,
	NFSERR_XDEV = 18,
	NFSERR_NODEV = 19,
	NFSERR_NOTDIR = 20,
	NFSERR_ISDIR = 21,
	NFSERR_INVAL = 22,
	NFSERR_FBIG = 27,
	NFSERR_NOSPC = 28,
	NFSERR_ROFS = 30,
	NFSERR_MLINK = 31,
	NFSERR_OPNOTSUPP = 45,
	NFSERR_NAMETOOLONG = 63,
	NFSERR_NOTEMPTY = 66,
	NFSERR_DQUOT = 69,
	NFSERR_STALE = 70,
	NFSERR_REMOTE = 71,
	NFSERR_WFLUSH = 99,
	NFSERR_BADHANDLE = 10001,
	NFSERR_NOT_SYNC = 10002,
	NFSERR_BAD_COOKIE = 10003,
	NFSERR_NOTSUPP = 10004,
	NFSERR_TOOSMALL = 10005,
	NFSERR_SERVERFAULT = 10006,
	NFSERR_BADTYPE = 10007,
	NFSERR_JUKEBOX = 10008,
	NFSERR_SAME = 10009,
	NFSERR_DENIED = 10010,
	NFSERR_EXPIRED = 10011,
	NFSERR_LOCKED = 10012,
	NFSERR_GRACE = 10013,
	NFSERR_FHEXPIRED = 10014,
	NFSERR_SHARE_DENIED = 10015,
	NFSERR_WRONGSEC = 10016,
	NFSERR_CLID_INUSE = 10017,
	NFSERR_RESOURCE = 10018,
	NFSERR_MOVED = 10019,
	NFSERR_NOFILEHANDLE = 10020,
	NFSERR_MINOR_VERS_MISMATCH = 10021,
	NFSERR_STALE_CLIENTID = 10022,
	NFSERR_STALE_STATEID = 10023,
	NFSERR_OLD_STATEID = 10024,
	NFSERR_BAD_STATEID = 10025,
	NFSERR_BAD_SEQID = 10026,
	NFSERR_NOT_SAME = 10027,
	NFSERR_LOCK_RANGE = 10028,
	NFSERR_SYMLINK = 10029,
	NFSERR_RESTOREFH = 10030,
	NFSERR_LEASE_MOVED = 10031,
	NFSERR_ATTRNOTSUPP = 10032,
	NFSERR_NO_GRACE = 10033,
	NFSERR_RECLAIM_BAD = 10034,
	NFSERR_RECLAIM_CONFLICT = 10035,
	NFSERR_BAD_XDR = 10036,
	NFSERR_LOCKS_HELD = 10037,
	NFSERR_OPENMODE = 10038,
	NFSERR_BADOWNER = 10039,
	NFSERR_BADCHAR = 10040,
	NFSERR_BADNAME = 10041,
	NFSERR_BAD_RANGE = 10042,
	NFSERR_LOCK_NOTSUPP = 10043,
	NFSERR_OP_ILLEGAL = 10044,
	NFSERR_DEADLOCK = 10045,
	NFSERR_FILE_OPEN = 10046,
	NFSERR_ADMIN_REVOKED = 10047,
	NFSERR_CB_PATH_DOWN = 10048,
};

enum nfsstat4 {
	NFS4_OK = 0,
	NFS4ERR_PERM = 1,
	NFS4ERR_NOENT = 2,
	NFS4ERR_IO = 5,
	NFS4ERR_NXIO = 6,
	NFS4ERR_ACCESS = 13,
	NFS4ERR_EXIST = 17,
	NFS4ERR_XDEV = 18,
	NFS4ERR_NOTDIR = 20,
	NFS4ERR_ISDIR = 21,
	NFS4ERR_INVAL = 22,
	NFS4ERR_FBIG = 27,
	NFS4ERR_NOSPC = 28,
	NFS4ERR_ROFS = 30,
	NFS4ERR_MLINK = 31,
	NFS4ERR_NAMETOOLONG = 63,
	NFS4ERR_NOTEMPTY = 66,
	NFS4ERR_DQUOT = 69,
	NFS4ERR_STALE = 70,
	NFS4ERR_BADHANDLE = 10001,
	NFS4ERR_BAD_COOKIE = 10003,
	NFS4ERR_NOTSUPP = 10004,
	NFS4ERR_TOOSMALL = 10005,
	NFS4ERR_SERVERFAULT = 10006,
	NFS4ERR_BADTYPE = 10007,
	NFS4ERR_DELAY = 10008,
	NFS4ERR_SAME = 10009,
	NFS4ERR_DENIED = 10010,
	NFS4ERR_EXPIRED = 10011,
	NFS4ERR_LOCKED = 10012,
	NFS4ERR_GRACE = 10013,
	NFS4ERR_FHEXPIRED = 10014,
	NFS4ERR_SHARE_DENIED = 10015,
	NFS4ERR_WRONGSEC = 10016,
	NFS4ERR_CLID_INUSE = 10017,
	NFS4ERR_RESOURCE = 10018,
	NFS4ERR_MOVED = 10019,
	NFS4ERR_NOFILEHANDLE = 10020,
	NFS4ERR_MINOR_VERS_MISMATCH = 10021,
	NFS4ERR_STALE_CLIENTID = 10022,
	NFS4ERR_STALE_STATEID = 10023,
	NFS4ERR_OLD_STATEID = 10024,
	NFS4ERR_BAD_STATEID = 10025,
	NFS4ERR_BAD_SEQID = 10026,
	NFS4ERR_NOT_SAME = 10027,
	NFS4ERR_LOCK_RANGE = 10028,
	NFS4ERR_SYMLINK = 10029,
	NFS4ERR_RESTOREFH = 10030,
	NFS4ERR_LEASE_MOVED = 10031,
	NFS4ERR_ATTRNOTSUPP = 10032,
	NFS4ERR_NO_GRACE = 10033,
	NFS4ERR_RECLAIM_BAD = 10034,
	NFS4ERR_RECLAIM_CONFLICT = 10035,
	NFS4ERR_BADXDR = 10036,
	NFS4ERR_LOCKS_HELD = 10037,
	NFS4ERR_OPENMODE = 10038,
	NFS4ERR_BADOWNER = 10039,
	NFS4ERR_BADCHAR = 10040,
	NFS4ERR_BADNAME = 10041,
	NFS4ERR_BAD_RANGE = 10042,
	NFS4ERR_LOCK_NOTSUPP = 10043,
	NFS4ERR_OP_ILLEGAL = 10044,
	NFS4ERR_DEADLOCK = 10045,
	NFS4ERR_FILE_OPEN = 10046,
	NFS4ERR_ADMIN_REVOKED = 10047,
	NFS4ERR_CB_PATH_DOWN = 10048,
	NFS4ERR_BADIOMODE = 10049,
	NFS4ERR_BADLAYOUT = 10050,
	NFS4ERR_BAD_SESSION_DIGEST = 10051,
	NFS4ERR_BADSESSION = 10052,
	NFS4ERR_BADSLOT = 10053,
	NFS4ERR_COMPLETE_ALREADY = 10054,
	NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055,
	NFS4ERR_DELEG_ALREADY_WANTED = 10056,
	NFS4ERR_BACK_CHAN_BUSY = 10057,
	NFS4ERR_LAYOUTTRYLATER = 10058,
	NFS4ERR_LAYOUTUNAVAILABLE = 10059,
	NFS4ERR_NOMATCHING_LAYOUT = 10060,
	NFS4ERR_RECALLCONFLICT = 10061,
	NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062,
	NFS4ERR_SEQ_MISORDERED = 10063,
	NFS4ERR_SEQUENCE_POS = 10064,
	NFS4ERR_REQ_TOO_BIG = 10065,
	NFS4ERR_REP_TOO_BIG = 10066,
	NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067,
	NFS4ERR_RETRY_UNCACHED_REP = 10068,
	NFS4ERR_UNSAFE_COMPOUND = 10069,
	NFS4ERR_TOO_MANY_OPS = 10070,
	NFS4ERR_OP_NOT_IN_SESSION = 10071,
	NFS4ERR_HASH_ALG_UNSUPP = 10072,
	NFS4ERR_CLIENTID_BUSY = 10074,
	NFS4ERR_PNFS_IO_HOLE = 10075,
	NFS4ERR_SEQ_FALSE_RETRY = 10076,
	NFS4ERR_BAD_HIGH_SLOT = 10077,
	NFS4ERR_DEADSESSION = 10078,
	NFS4ERR_ENCR_ALG_UNSUPP = 10079,
	NFS4ERR_PNFS_NO_LAYOUT = 10080,
	NFS4ERR_NOT_ONLY_OP = 10081,
	NFS4ERR_WRONG_CRED = 10082,
	NFS4ERR_WRONG_TYPE = 10083,
	NFS4ERR_DIRDELEG_UNAVAIL = 10084,
	NFS4ERR_REJECT_DELEG = 10085,
	NFS4ERR_RETURNCONFLICT = 10086,
	NFS4ERR_DELEG_REVOKED = 10087,
	NFS4ERR_PARTNER_NOTSUPP = 10088,
	NFS4ERR_PARTNER_NO_AUTH = 10089,
	NFS4ERR_UNION_NOTSUPP = 10090,
	NFS4ERR_OFFLOAD_DENIED = 10091,
	NFS4ERR_WRONG_LFS = 10092,
	NFS4ERR_BADLABEL = 10093,
	NFS4ERR_OFFLOAD_NO_REQS = 10094,
	NFS4ERR_NOXATTR = 10095,
	NFS4ERR_XATTR2BIG = 10096,
};

enum pnfs_iomode {
	IOMODE_READ = 1,
	IOMODE_RW = 2,
	IOMODE_ANY = 3,
};

struct trace_event_raw_nfs_inode_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 version;
	char __data[0];
};

struct trace_event_raw_nfs_inode_event_done {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	unsigned char type;
	u64 fileid;
	u64 version;
	loff_t size;
	long unsigned int nfsi_flags;
	long unsigned int cache_validity;
	char __data[0];
};

struct trace_event_raw_nfs_access_exit {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u32 fhandle;
	unsigned char type;
	u64 fileid;
	u64 version;
	loff_t size;
	long unsigned int nfsi_flags;
	long unsigned int cache_validity;
	unsigned int mask;
	unsigned int permitted;
	char __data[0];
};

struct trace_event_raw_nfs_update_size_class {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 version;
	loff_t cur_size;
	loff_t new_size;
	char __data[0];
};

struct trace_event_raw_nfs_inode_range_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 version;
	loff_t range_start;
	loff_t range_end;
	char __data[0];
};

struct trace_event_raw_nfs_readdir_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 version;
	char verifier[8];
	u64 cookie;
	long unsigned int index;
	unsigned int dtsize;
	char __data[0];
};

struct trace_event_raw_nfs_lookup_event {
	struct trace_entry ent;
	long unsigned int flags;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_lookup_event_done {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int flags;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_atomic_open_enter {
	struct trace_entry ent;
	long unsigned int flags;
	long unsigned int fmode;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_atomic_open_exit {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int flags;
	long unsigned int fmode;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_create_enter {
	struct trace_entry ent;
	long unsigned int flags;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_create_exit {
	struct trace_entry ent;
	long unsigned int error;
	long unsigned int flags;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_directory_event {
	struct trace_entry ent;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_directory_event_done {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_link_enter {
	struct trace_entry ent;
	dev_t dev;
	u64 fileid;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_link_exit {
	struct trace_entry ent;
	long unsigned int error;
	dev_t dev;
	u64 fileid;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_rename_event {
	struct trace_entry ent;
	dev_t dev;
	u64 old_dir;
	u64 new_dir;
	u32 __data_loc_old_name;
	u32 __data_loc_new_name;
	char __data[0];
};

struct trace_event_raw_nfs_rename_event_done {
	struct trace_entry ent;
	dev_t dev;
	long unsigned int error;
	u64 old_dir;
	u32 __data_loc_old_name;
	u64 new_dir;
	u32 __data_loc_new_name;
	char __data[0];
};

struct trace_event_raw_nfs_sillyrename_unlink {
	struct trace_entry ent;
	dev_t dev;
	long unsigned int error;
	u64 dir;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_nfs_aop_readpage {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 version;
	loff_t offset;
	char __data[0];
};

struct trace_event_raw_nfs_aop_readpage_done {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	int ret;
	u64 fileid;
	u64 version;
	loff_t offset;
	char __data[0];
};

struct trace_event_raw_nfs_aop_readahead {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	u64 version;
	loff_t offset;
	unsigned int nr_pages;
	char __data[0];
};

struct trace_event_raw_nfs_aop_readahead_done {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	int ret;
	u64 fileid;
	u64 version;
	loff_t offset;
	unsigned int nr_pages;
	char __data[0];
};

struct trace_event_raw_nfs_initiate_read {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 count;
	char __data[0];
};

struct trace_event_raw_nfs_readpage_done {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 arg_count;
	u32 res_count;
	bool eof;
	int status;
	char __data[0];
};

struct trace_event_raw_nfs_readpage_short {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 arg_count;
	u32 res_count;
	bool eof;
	int status;
	char __data[0];
};

struct trace_event_raw_nfs_fscache_page_event {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	char __data[0];
};

struct trace_event_raw_nfs_fscache_page_event_done {
	struct trace_entry ent;
	int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	char __data[0];
};

struct trace_event_raw_nfs_pgio_error {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 arg_count;
	u32 res_count;
	loff_t pos;
	int status;
	char __data[0];
};

struct trace_event_raw_nfs_initiate_write {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 count;
	long unsigned int stable;
	char __data[0];
};

struct trace_event_raw_nfs_writeback_done {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 arg_count;
	u32 res_count;
	int status;
	long unsigned int stable;
	char verifier[8];
	char __data[0];
};

struct trace_event_raw_nfs_page_error_class {
	struct trace_entry ent;
	const void *req;
	long unsigned int index;
	unsigned int offset;
	unsigned int pgbase;
	unsigned int bytes;
	int error;
	char __data[0];
};

struct trace_event_raw_nfs_initiate_commit {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	u32 count;
	char __data[0];
};

struct trace_event_raw_nfs_commit_done {
	struct trace_entry ent;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	loff_t offset;
	int status;
	long unsigned int stable;
	char verifier[8];
	char __data[0];
};

struct trace_event_raw_nfs_fh_to_dentry {
	struct trace_entry ent;
	int error;
	dev_t dev;
	u32 fhandle;
	u64 fileid;
	char __data[0];
};

struct trace_event_raw_nfs_xdr_event {
	struct trace_entry ent;
	unsigned int task_id;
	unsigned int client_id;
	u32 xid;
	int version;
	long unsigned int error;
	u32 __data_loc_program;
	u32 __data_loc_procedure;
	char __data[0];
};

struct trace_event_data_offsets_nfs_inode_event {};

struct trace_event_data_offsets_nfs_inode_event_done {};

struct trace_event_data_offsets_nfs_access_exit {};

struct trace_event_data_offsets_nfs_update_size_class {};

struct trace_event_data_offsets_nfs_inode_range_event {};

struct trace_event_data_offsets_nfs_readdir_event {};

struct trace_event_data_offsets_nfs_lookup_event {
	u32 name;
};

struct trace_event_data_offsets_nfs_lookup_event_done {
	u32 name;
};

struct trace_event_data_offsets_nfs_atomic_open_enter {
	u32 name;
};

struct trace_event_data_offsets_nfs_atomic_open_exit {
	u32 name;
};

struct trace_event_data_offsets_nfs_create_enter {
	u32 name;
};

struct trace_event_data_offsets_nfs_create_exit {
	u32 name;
};

struct trace_event_data_offsets_nfs_directory_event {
	u32 name;
};

struct trace_event_data_offsets_nfs_directory_event_done {
	u32 name;
};

struct trace_event_data_offsets_nfs_link_enter {
	u32 name;
};

struct trace_event_data_offsets_nfs_link_exit {
	u32 name;
};

struct trace_event_data_offsets_nfs_rename_event {
	u32 old_name;
	u32 new_name;
};

struct trace_event_data_offsets_nfs_rename_event_done {
	u32 old_name;
	u32 new_name;
};

struct trace_event_data_offsets_nfs_sillyrename_unlink {
	u32 name;
};

struct trace_event_data_offsets_nfs_aop_readpage {};

struct trace_event_data_offsets_nfs_aop_readpage_done {};

struct trace_event_data_offsets_nfs_aop_readahead {};

struct trace_event_data_offsets_nfs_aop_readahead_done {};

struct trace_event_data_offsets_nfs_initiate_read {};

struct trace_event_data_offsets_nfs_readpage_done {};

struct trace_event_data_offsets_nfs_readpage_short {};

struct trace_event_data_offsets_nfs_fscache_page_event {};

struct trace_event_data_offsets_nfs_fscache_page_event_done {};

struct trace_event_data_offsets_nfs_pgio_error {};

struct trace_event_data_offsets_nfs_initiate_write {};

struct trace_event_data_offsets_nfs_writeback_done {};

struct trace_event_data_offsets_nfs_page_error_class {};

struct trace_event_data_offsets_nfs_initiate_commit {};

struct trace_event_data_offsets_nfs_commit_done {};

struct trace_event_data_offsets_nfs_fh_to_dentry {};

struct trace_event_data_offsets_nfs_xdr_event {
	u32 program;
	u32 procedure;
};

typedef void (*btf_trace_nfs_set_inode_stale)(void *, const struct inode *);

typedef void (*btf_trace_nfs_refresh_inode_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_refresh_inode_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_revalidate_inode_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_revalidate_inode_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_invalidate_mapping_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_invalidate_mapping_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_getattr_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_getattr_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_setattr_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_setattr_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_writeback_page_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_writeback_page_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_writeback_inode_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_writeback_inode_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_fsync_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_fsync_exit)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_access_enter)(void *, const struct inode *);

typedef void (*btf_trace_nfs_set_cache_invalid)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_readdir_force_readdirplus)(void *, const struct inode *);

typedef void (*btf_trace_nfs_readdir_cache_fill_done)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_readdir_uncached_done)(void *, const struct inode *, int);

typedef void (*btf_trace_nfs_access_exit)(void *, const struct inode *, unsigned int, unsigned int, int);

typedef void (*btf_trace_nfs_size_truncate)(void *, const struct inode *, loff_t);

typedef void (*btf_trace_nfs_size_wcc)(void *, const struct inode *, loff_t);

typedef void (*btf_trace_nfs_size_update)(void *, const struct inode *, loff_t);

typedef void (*btf_trace_nfs_size_grow)(void *, const struct inode *, loff_t);

typedef void (*btf_trace_nfs_readdir_invalidate_cache_range)(void *, const struct inode *, loff_t, loff_t);

typedef void (*btf_trace_nfs_readdir_cache_fill)(void *, const struct file *, const __be32 *, u64, long unsigned int, unsigned int);

typedef void (*btf_trace_nfs_readdir_uncached)(void *, const struct file *, const __be32 *, u64, long unsigned int, unsigned int);

typedef void (*btf_trace_nfs_lookup_enter)(void *, const struct inode *, const struct dentry *, unsigned int);

typedef void (*btf_trace_nfs_lookup_exit)(void *, const struct inode *, const struct dentry *, unsigned int, int);

typedef void (*btf_trace_nfs_lookup_revalidate_enter)(void *, const struct inode *, const struct dentry *, unsigned int);

typedef void (*btf_trace_nfs_lookup_revalidate_exit)(void *, const struct inode *, const struct dentry *, unsigned int, int);

typedef void (*btf_trace_nfs_readdir_lookup)(void *, const struct inode *, const struct dentry *, unsigned int);

typedef void (*btf_trace_nfs_readdir_lookup_revalidate_failed)(void *, const struct inode *, const struct dentry *, unsigned int);

typedef void (*btf_trace_nfs_readdir_lookup_revalidate)(void *, const struct inode *, const struct dentry *, unsigned int, int);

typedef void (*btf_trace_nfs_atomic_open_enter)(void *, const struct inode *, const struct nfs_open_context *, unsigned int);

typedef void (*btf_trace_nfs_atomic_open_exit)(void *, const struct inode *, const struct nfs_open_context *, unsigned int, int);

typedef void (*btf_trace_nfs_create_enter)(void *, const struct inode *, const struct dentry *, unsigned int);

typedef void (*btf_trace_nfs_create_exit)(void *, const struct inode *, const struct dentry *, unsigned int, int);

typedef void (*btf_trace_nfs_mknod_enter)(void *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_mknod_exit)(void *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_mkdir_enter)(void *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_mkdir_exit)(void *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_rmdir_enter)(void *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_rmdir_exit)(void *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_remove_enter)(void *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_remove_exit)(void *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_unlink_enter)(void *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_unlink_exit)(void *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_symlink_enter)(void *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_symlink_exit)(void *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_link_enter)(void *, const struct inode *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_link_exit)(void *, const struct inode *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_rename_enter)(void *, const struct inode *, const struct dentry *, const struct inode *, const struct dentry *);

typedef void (*btf_trace_nfs_rename_exit)(void *, const struct inode *, const struct dentry *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_sillyrename_rename)(void *, const struct inode *, const struct dentry *, const struct inode *, const struct dentry *, int);

typedef void (*btf_trace_nfs_sillyrename_unlink)(void *, const struct nfs_unlinkdata *, int);

typedef void (*btf_trace_nfs_aop_readpage)(void *, const struct inode *, struct page *);

typedef void (*btf_trace_nfs_aop_readpage_done)(void *, const struct inode *, struct page *, int);

typedef void (*btf_trace_nfs_aop_readahead)(void *, const struct inode *, loff_t, unsigned int);

typedef void (*btf_trace_nfs_aop_readahead_done)(void *, const struct inode *, unsigned int, int);

typedef void (*btf_trace_nfs_initiate_read)(void *, const struct nfs_pgio_header *);

typedef void (*btf_trace_nfs_readpage_done)(void *, const struct rpc_task *, const struct nfs_pgio_header *);

typedef void (*btf_trace_nfs_readpage_short)(void *, const struct rpc_task *, const struct nfs_pgio_header *);

typedef void (*btf_trace_nfs_fscache_read_page)(void *, const struct inode *, struct page *);

typedef void (*btf_trace_nfs_fscache_read_page_exit)(void *, const struct inode *, struct page *, int);

typedef void (*btf_trace_nfs_fscache_write_page)(void *, const struct inode *, struct page *);

typedef void (*btf_trace_nfs_fscache_write_page_exit)(void *, const struct inode *, struct page *, int);

typedef void (*btf_trace_nfs_pgio_error)(void *, const struct nfs_pgio_header *, int, loff_t);

typedef void (*btf_trace_nfs_initiate_write)(void *, const struct nfs_pgio_header *);

typedef void (*btf_trace_nfs_writeback_done)(void *, const struct rpc_task *, const struct nfs_pgio_header *);

typedef void (*btf_trace_nfs_write_error)(void *, const struct nfs_page *, int);

typedef void (*btf_trace_nfs_comp_error)(void *, const struct nfs_page *, int);

typedef void (*btf_trace_nfs_commit_error)(void *, const struct nfs_page *, int);

typedef void (*btf_trace_nfs_initiate_commit)(void *, const struct nfs_commit_data *);

typedef void (*btf_trace_nfs_commit_done)(void *, const struct rpc_task *, const struct nfs_commit_data *);

typedef void (*btf_trace_nfs_fh_to_dentry)(void *, const struct super_block *, const struct nfs_fh *, u64, int);

typedef void (*btf_trace_nfs_xdr_status)(void *, const struct xdr_stream *, int);

typedef void (*btf_trace_nfs_xdr_bad_filehandle)(void *, const struct xdr_stream *, int);

struct nfs2_fh {
	char data[32];
};

struct nfs3_fh {
	short unsigned int size;
	unsigned char data[64];
};

struct nfs_mount_data {
	int version;
	int fd;
	struct nfs2_fh old_root;
	int flags;
	int rsize;
	int wsize;
	int timeo;
	int retrans;
	int acregmin;
	int acregmax;
	int acdirmin;
	int acdirmax;
	struct sockaddr_in addr;
	char hostname[256];
	int namlen;
	unsigned int bsize;
	struct nfs3_fh root;
	int pseudoflavor;
	char context[257];
};

enum nfs_param {
	Opt_ac = 0,
	Opt_acdirmax = 1,
	Opt_acdirmin = 2,
	Opt_acl___2 = 3,
	Opt_acregmax = 4,
	Opt_acregmin = 5,
	Opt_actimeo = 6,
	Opt_addr = 7,
	Opt_bg = 8,
	Opt_bsize = 9,
	Opt_clientaddr = 10,
	Opt_cto = 11,
	Opt_fg = 12,
	Opt_fscache = 13,
	Opt_fscache_flag = 14,
	Opt_hard = 15,
	Opt_intr = 16,
	Opt_local_lock = 17,
	Opt_lock = 18,
	Opt_lookupcache = 19,
	Opt_migration = 20,
	Opt_minorversion = 21,
	Opt_mountaddr = 22,
	Opt_mounthost = 23,
	Opt_mountport = 24,
	Opt_mountproto = 25,
	Opt_mountvers = 26,
	Opt_namelen = 27,
	Opt_nconnect = 28,
	Opt_max_connect = 29,
	Opt_port = 30,
	Opt_posix = 31,
	Opt_proto = 32,
	Opt_rdirplus = 33,
	Opt_rdma = 34,
	Opt_resvport = 35,
	Opt_retrans = 36,
	Opt_retry = 37,
	Opt_rsize = 38,
	Opt_sec = 39,
	Opt_sharecache = 40,
	Opt_sloppy = 41,
	Opt_soft = 42,
	Opt_softerr = 43,
	Opt_softreval = 44,
	Opt_source = 45,
	Opt_tcp = 46,
	Opt_timeo = 47,
	Opt_trunkdiscovery = 48,
	Opt_udp = 49,
	Opt_v = 50,
	Opt_vers = 51,
	Opt_wsize = 52,
	Opt_write = 53,
};

enum {
	Opt_local_lock_all = 0,
	Opt_local_lock_flock = 1,
	Opt_local_lock_none = 2,
	Opt_local_lock_posix = 3,
};

enum {
	Opt_lookupcache_all = 0,
	Opt_lookupcache_none = 1,
	Opt_lookupcache_positive = 2,
};

enum {
	Opt_write_lazy = 0,
	Opt_write_eager = 1,
	Opt_write_wait = 2,
};

enum {
	Opt_vers_2 = 0,
	Opt_vers_3 = 1,
	Opt_vers_4 = 2,
	Opt_vers_4_0 = 3,
	Opt_vers_4_1 = 4,
	Opt_vers_4_2 = 5,
};

enum {
	Opt_xprt_rdma = 0,
	Opt_xprt_rdma6 = 1,
	Opt_xprt_tcp = 2,
	Opt_xprt_tcp6 = 3,
	Opt_xprt_udp = 4,
	Opt_xprt_udp6 = 5,
	nr__Opt_xprt = 6,
};

enum {
	Opt_sec_krb5 = 0,
	Opt_sec_krb5i = 1,
	Opt_sec_krb5p = 2,
	Opt_sec_lkey = 3,
	Opt_sec_lkeyi = 4,
	Opt_sec_lkeyp = 5,
	Opt_sec_none = 6,
	Opt_sec_spkm = 7,
	Opt_sec_spkmi = 8,
	Opt_sec_spkmp = 9,
	Opt_sec_sys = 10,
	nr__Opt_sec = 11,
};

struct nfs2_fsstat {
	__u32 tsize;
	__u32 bsize;
	__u32 blocks;
	__u32 bfree;
	__u32 bavail;
};

struct nfs_sattrargs {
	struct nfs_fh *fh;
	struct iattr *sattr;
};

struct nfs_diropargs {
	struct nfs_fh *fh;
	const char *name;
	unsigned int len;
};

struct nfs_createargs {
	struct nfs_fh *fh;
	const char *name;
	unsigned int len;
	struct iattr *sattr;
};

struct nfs_linkargs {
	struct nfs_fh *fromfh;
	struct nfs_fh *tofh;
	const char *toname;
	unsigned int tolen;
};

struct nfs_symlinkargs {
	struct nfs_fh *fromfh;
	const char *fromname;
	unsigned int fromlen;
	struct page **pages;
	unsigned int pathlen;
	struct iattr *sattr;
};

struct nfs_readdirargs {
	struct nfs_fh *fh;
	__u32 cookie;
	unsigned int count;
	struct page **pages;
};

struct nfs_diropok {
	struct nfs_fh *fh;
	struct nfs_fattr *fattr;
};

struct nfs_readlinkargs {
	struct nfs_fh *fh;
	unsigned int pgbase;
	unsigned int pglen;
	struct page **pages;
};

struct nfs_createdata {
	struct nfs_createargs arg;
	struct nfs_diropok res;
	struct nfs_fh fhandle;
	struct nfs_fattr fattr;
};

enum nfs_ftype {
	NFNON = 0,
	NFREG = 1,
	NFDIR = 2,
	NFBLK = 3,
	NFCHR = 4,
	NFLNK = 5,
	NFSOCK = 6,
	NFBAD = 7,
	NFFIFO = 8,
};

enum nfs2_ftype {
	NF2NON = 0,
	NF2REG = 1,
	NF2DIR = 2,
	NF2BLK = 3,
	NF2CHR = 4,
	NF2LNK = 5,
	NF2SOCK = 6,
	NF2BAD = 7,
	NF2FIFO = 8,
};

enum nfs3_createmode {
	NFS3_CREATE_UNCHECKED = 0,
	NFS3_CREATE_GUARDED = 1,
	NFS3_CREATE_EXCLUSIVE = 2,
};

enum nfs3_ftype {
	NF3NON = 0,
	NF3REG = 1,
	NF3DIR = 2,
	NF3BLK = 3,
	NF3CHR = 4,
	NF3LNK = 5,
	NF3SOCK = 6,
	NF3FIFO = 7,
	NF3BAD = 8,
};

struct nfs3_sattrargs {
	struct nfs_fh *fh;
	struct iattr *sattr;
	unsigned int guard;
	struct timespec64 guardtime;
};

struct nfs3_diropargs {
	struct nfs_fh *fh;
	const char *name;
	unsigned int len;
};

struct nfs3_accessargs {
	struct nfs_fh *fh;
	__u32 access;
};

struct nfs3_createargs {
	struct nfs_fh *fh;
	const char *name;
	unsigned int len;
	struct iattr *sattr;
	enum nfs3_createmode createmode;
	__be32 verifier[2];
};

struct nfs3_mkdirargs {
	struct nfs_fh *fh;
	const char *name;
	unsigned int len;
	struct iattr *sattr;
};

struct nfs3_symlinkargs {
	struct nfs_fh *fromfh;
	const char *fromname;
	unsigned int fromlen;
	struct page **pages;
	unsigned int pathlen;
	struct iattr *sattr;
};

struct nfs3_mknodargs {
	struct nfs_fh *fh;
	const char *name;
	unsigned int len;
	enum nfs3_ftype type;
	struct iattr *sattr;
	dev_t rdev;
};

struct nfs3_linkargs {
	struct nfs_fh *fromfh;
	struct nfs_fh *tofh;
	const char *toname;
	unsigned int tolen;
};

struct nfs3_readdirargs {
	struct nfs_fh *fh;
	__u64 cookie;
	__be32 verf[2];
	bool plus;
	unsigned int count;
	struct page **pages;
};

struct nfs3_diropres {
	struct nfs_fattr *dir_attr;
	struct nfs_fh *fh;
	struct nfs_fattr *fattr;
};

struct nfs3_accessres {
	struct nfs_fattr *fattr;
	__u32 access;
};

struct nfs3_readlinkargs {
	struct nfs_fh *fh;
	unsigned int pgbase;
	unsigned int pglen;
	struct page **pages;
};

struct nfs3_linkres {
	struct nfs_fattr *dir_attr;
	struct nfs_fattr *fattr;
};

struct nfs3_readdirres {
	struct nfs_fattr *dir_attr;
	__be32 *verf;
	bool plus;
};

struct nfs3_createdata {
	struct rpc_message msg;
	union {
		struct nfs3_createargs create;
		struct nfs3_mkdirargs mkdir;
		struct nfs3_symlinkargs symlink;
		struct nfs3_mknodargs mknod;
	} arg;
	struct nfs3_diropres res;
	struct nfs_fh fh;
	struct nfs_fattr fattr;
	struct nfs_fattr dir_attr;
};

struct getdents_callback___2 {
	struct dir_context ctx;
	char *name;
	u64 ino;
	int found;
	int sequence;
};

struct nlm_host;

struct nlm_lockowner {
	struct list_head list;
	refcount_t count;
	struct nlm_host *host;
	fl_owner_t owner;
	uint32_t pid;
};

struct nsm_handle;

struct nlm_host {
	struct hlist_node h_hash;
	struct __kernel_sockaddr_storage h_addr;
	size_t h_addrlen;
	struct __kernel_sockaddr_storage h_srcaddr;
	size_t h_srcaddrlen;
	struct rpc_clnt *h_rpcclnt;
	char *h_name;
	u32 h_version;
	short unsigned int h_proto;
	short unsigned int h_reclaiming: 1;
	short unsigned int h_server: 1;
	short unsigned int h_noresvport: 1;
	short unsigned int h_inuse: 1;
	wait_queue_head_t h_gracewait;
	struct rw_semaphore h_rwsem;
	u32 h_state;
	u32 h_nsmstate;
	u32 h_pidcount;
	refcount_t h_count;
	struct mutex h_mutex;
	long unsigned int h_nextrebind;
	long unsigned int h_expires;
	struct list_head h_lockowners;
	spinlock_t h_lock;
	struct list_head h_granted;
	struct list_head h_reclaim;
	struct nsm_handle *h_nsmhandle;
	char *h_addrbuf;
	struct net *net;
	const struct cred *h_cred;
	char nodename[65];
	const struct nlmclnt_operations *h_nlmclnt_ops;
};

enum {
	NLM_LCK_GRANTED = 0,
	NLM_LCK_DENIED = 1,
	NLM_LCK_DENIED_NOLOCKS = 2,
	NLM_LCK_BLOCKED = 3,
	NLM_LCK_DENIED_GRACE_PERIOD = 4,
	NLM_DEADLCK = 5,
	NLM_ROFS = 6,
	NLM_STALE_FH = 7,
	NLM_FBIG = 8,
	NLM_FAILED = 9,
};

struct nsm_private {
	unsigned char data[16];
};

struct nlm_lock {
	char *caller;
	unsigned int len;
	struct nfs_fh fh;
	struct xdr_netobj oh;
	u32 svid;
	struct file_lock fl;
};

struct nlm_cookie {
	unsigned char data[32];
	unsigned int len;
};

struct nlm_args {
	struct nlm_cookie cookie;
	struct nlm_lock lock;
	u32 block;
	u32 reclaim;
	u32 state;
	u32 monitor;
	u32 fsm_access;
	u32 fsm_mode;
};

struct nlm_res {
	struct nlm_cookie cookie;
	__be32 status;
	struct nlm_lock lock;
};

struct nsm_handle {
	struct list_head sm_link;
	refcount_t sm_count;
	char *sm_mon_name;
	char *sm_name;
	struct __kernel_sockaddr_storage sm_addr;
	size_t sm_addrlen;
	unsigned int sm_monitored: 1;
	unsigned int sm_sticky: 1;
	struct nsm_private sm_priv;
	char sm_addrbuf[51];
};

struct nlm_block;

struct nlm_rqst {
	refcount_t a_count;
	unsigned int a_flags;
	struct nlm_host *a_host;
	struct nlm_args a_args;
	struct nlm_res a_res;
	struct nlm_block *a_block;
	unsigned int a_retries;
	u8 a_owner[74];
	void *a_callback_data;
};

struct nlm_file;

struct nlm_block {
	struct kref b_count;
	struct list_head b_list;
	struct list_head b_flist;
	struct nlm_rqst *b_call;
	struct svc_serv *b_daemon;
	struct nlm_host *b_host;
	long unsigned int b_when;
	unsigned int b_id;
	unsigned char b_granted;
	struct nlm_file *b_file;
	struct cache_req *b_cache_req;
	struct cache_deferred_req *b_deferred_req;
	unsigned int b_flags;
};

struct nlm_share;

struct nlm_file {
	struct hlist_node f_list;
	struct nfs_fh f_handle;
	struct file *f_file[2];
	struct nlm_share *f_shares;
	struct list_head f_blocks;
	unsigned int f_locks;
	unsigned int f_count;
	struct mutex f_mutex;
};

struct nlm_wait {
	struct list_head b_list;
	wait_queue_head_t b_wait;
	struct nlm_host *b_host;
	struct file_lock *b_lock;
	short unsigned int b_reclaim;
	__be32 b_status;
};

struct nlm_wait;

struct nlm_reboot {
	char *mon;
	unsigned int len;
	u32 state;
	struct nsm_private priv;
};

struct lockd_net {
	unsigned int nlmsvc_users;
	long unsigned int next_gc;
	long unsigned int nrhosts;
	struct delayed_work grace_period_end;
	struct lock_manager lockd_manager;
	struct list_head nsm_handles;
};

struct nlm_lookup_host_info {
	const int server;
	const struct sockaddr *sap;
	const size_t salen;
	const short unsigned int protocol;
	const u32 version;
	const char *hostname;
	const size_t hostname_len;
	const int noresvport;
	struct net *net;
	const struct cred *cred;
};

enum {
	IPV4_DEVCONF_FORWARDING = 1,
	IPV4_DEVCONF_MC_FORWARDING = 2,
	IPV4_DEVCONF_PROXY_ARP = 3,
	IPV4_DEVCONF_ACCEPT_REDIRECTS = 4,
	IPV4_DEVCONF_SECURE_REDIRECTS = 5,
	IPV4_DEVCONF_SEND_REDIRECTS = 6,
	IPV4_DEVCONF_SHARED_MEDIA = 7,
	IPV4_DEVCONF_RP_FILTER = 8,
	IPV4_DEVCONF_ACCEPT_SOURCE_ROUTE = 9,
	IPV4_DEVCONF_BOOTP_RELAY = 10,
	IPV4_DEVCONF_LOG_MARTIANS = 11,
	IPV4_DEVCONF_TAG = 12,
	IPV4_DEVCONF_ARPFILTER = 13,
	IPV4_DEVCONF_MEDIUM_ID = 14,
	IPV4_DEVCONF_NOXFRM = 15,
	IPV4_DEVCONF_NOPOLICY = 16,
	IPV4_DEVCONF_FORCE_IGMP_VERSION = 17,
	IPV4_DEVCONF_ARP_ANNOUNCE = 18,
	IPV4_DEVCONF_ARP_IGNORE = 19,
	IPV4_DEVCONF_PROMOTE_SECONDARIES = 20,
	IPV4_DEVCONF_ARP_ACCEPT = 21,
	IPV4_DEVCONF_ARP_NOTIFY = 22,
	IPV4_DEVCONF_ACCEPT_LOCAL = 23,
	IPV4_DEVCONF_SRC_VMARK = 24,
	IPV4_DEVCONF_PROXY_ARP_PVLAN = 25,
	IPV4_DEVCONF_ROUTE_LOCALNET = 26,
	IPV4_DEVCONF_IGMPV2_UNSOLICITED_REPORT_INTERVAL = 27,
	IPV4_DEVCONF_IGMPV3_UNSOLICITED_REPORT_INTERVAL = 28,
	IPV4_DEVCONF_IGNORE_ROUTES_WITH_LINKDOWN = 29,
	IPV4_DEVCONF_DROP_UNICAST_IN_L2_MULTICAST = 30,
	IPV4_DEVCONF_DROP_GRATUITOUS_ARP = 31,
	IPV4_DEVCONF_BC_FORWARDING = 32,
	IPV4_DEVCONF_ARP_EVICT_NOCARRIER = 33,
	__IPV4_DEVCONF_MAX = 34,
};

struct ipv4_devconf {
	void *sysctl;
	int data[33];
	long unsigned int state[2];
};

struct in_ifaddr;

struct ip_mc_list;

struct in_device {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	refcount_t refcnt;
	int dead;
	struct in_ifaddr *ifa_list;
	struct ip_mc_list *mc_list;
	struct ip_mc_list **mc_hash;
	int mc_count;
	spinlock_t mc_tomb_lock;
	struct ip_mc_list *mc_tomb;
	long unsigned int mr_v1_seen;
	long unsigned int mr_v2_seen;
	long unsigned int mr_maxdelay;
	long unsigned int mr_qi;
	long unsigned int mr_qri;
	unsigned char mr_qrv;
	unsigned char mr_gq_running;
	u32 mr_ifc_count;
	struct timer_list mr_gq_timer;
	struct timer_list mr_ifc_timer;
	struct neigh_parms *arp_parms;
	struct ipv4_devconf cnf;
	struct callback_head callback_head;
};

struct in_ifaddr {
	struct hlist_node hash;
	struct in_ifaddr *ifa_next;
	struct in_device *ifa_dev;
	struct callback_head callback_head;
	__be32 ifa_local;
	__be32 ifa_address;
	__be32 ifa_mask;
	__u32 ifa_rt_priority;
	__be32 ifa_broadcast;
	unsigned char ifa_scope;
	unsigned char ifa_prefixlen;
	unsigned char ifa_proto;
	__u32 ifa_flags;
	char ifa_label[16];
	__u32 ifa_valid_lft;
	__u32 ifa_preferred_lft;
	long unsigned int ifa_cstamp;
	long unsigned int ifa_tstamp;
};

enum rpc_accept_stat {
	RPC_SUCCESS = 0,
	RPC_PROG_UNAVAIL = 1,
	RPC_PROG_MISMATCH = 2,
	RPC_PROC_UNAVAIL = 3,
	RPC_GARBAGE_ARGS = 4,
	RPC_SYSTEM_ERR = 5,
	RPC_DROP_REPLY = 60000,
};

enum rpc_auth_stat {
	RPC_AUTH_OK = 0,
	RPC_AUTH_BADCRED = 1,
	RPC_AUTH_REJECTEDCRED = 2,
	RPC_AUTH_BADVERF = 3,
	RPC_AUTH_REJECTEDVERF = 4,
	RPC_AUTH_TOOWEAK = 5,
	RPCSEC_GSS_CREDPROBLEM = 13,
	RPCSEC_GSS_CTXPROBLEM = 14,
};

struct nlmsvc_binding {
	__be32 (*fopen)(struct svc_rqst *, struct nfs_fh *, struct file **, int);
	void (*fclose)(struct file *);
};

typedef int (*nlm_host_match_fn_t)(void *, struct nlm_host *);

struct nlm_share {
	struct nlm_share *s_next;
	struct nlm_host *s_host;
	struct nlm_file *s_file;
	struct xdr_netobj s_owner;
	u32 s_access;
	u32 s_mode;
};

enum {
	NSMPROC_NULL = 0,
	NSMPROC_STAT = 1,
	NSMPROC_MON = 2,
	NSMPROC_UNMON = 3,
	NSMPROC_UNMON_ALL = 4,
	NSMPROC_SIMU_CRASH = 5,
	NSMPROC_NOTIFY = 6,
};

struct nsm_args {
	struct nsm_private *priv;
	u32 prog;
	u32 vers;
	u32 proc;
	char *mon_name;
	const char *nodename;
};

struct nsm_res {
	u32 status;
	u32 state;
};

struct debugfs_fsdata {
	const struct file_operations *real_fops;
	refcount_t active_users;
	struct completion active_users_drained;
};

struct debugfs_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

enum {
	Opt_uid___3 = 0,
	Opt_gid___4 = 1,
	Opt_mode___4 = 2,
	Opt_err___3 = 3,
};

struct debugfs_fs_info {
	struct debugfs_mount_opts mount_opts;
};

struct debugfs_blob_wrapper {
	void *data;
	long unsigned int size;
};

struct debugfs_reg32 {
	char *name;
	long unsigned int offset;
};

struct debugfs_regset32 {
	const struct debugfs_reg32 *regs;
	int nregs;
	void *base;
	struct device *dev;
};

struct debugfs_u32_array {
	u32 *array;
	u32 n_elements;
};

struct debugfs_devm_entry {
	int (*read)(struct seq_file *, void *);
	struct device *dev;
};

struct tracefs_dir_ops {
	int (*mkdir)(const char *);
	int (*rmdir)(const char *);
};

struct tracefs_mount_opts {
	kuid_t uid;
	kgid_t gid;
	umode_t mode;
};

struct tracefs_fs_info {
	struct tracefs_mount_opts mount_opts;
};

struct ipc64_perm {
	__kernel_key_t key;
	__kernel_uid32_t uid;
	__kernel_gid32_t gid;
	__kernel_uid32_t cuid;
	__kernel_gid32_t cgid;
	__kernel_mode_t mode;
	unsigned char __pad1[0];
	short unsigned int seq;
	short unsigned int __pad2;
	__kernel_ulong_t __unused1;
	__kernel_ulong_t __unused2;
};

struct kern_ipc_perm {
	spinlock_t lock;
	bool deleted;
	int id;
	key_t key;
	kuid_t uid;
	kgid_t gid;
	kuid_t cuid;
	kgid_t cgid;
	umode_t mode;
	long unsigned int seq;
	void *security;
	struct rhash_head khtnode;
	struct callback_head rcu;
	refcount_t refcount;
};

struct ipc_params {
	key_t key;
	int flg;
	union {
		size_t size;
		int nsems;
	} u;
};

struct ipc_ops {
	int (*getnew)(struct ipc_namespace *, struct ipc_params *);
	int (*associate)(struct kern_ipc_perm *, int);
	int (*more_checks)(struct kern_ipc_perm *, struct ipc_params *);
};

struct ipc_proc_iface {
	const char *path;
	const char *header;
	int ids;
	int (*show)(struct seq_file *, void *);
};

struct ipc_proc_iter {
	struct ipc_namespace *ns;
	struct pid_namespace *pid_ns;
	struct ipc_proc_iface *iface;
};

struct msg_msgseg;

struct msg_msg {
	struct list_head m_list;
	long int m_type;
	size_t m_ts;
	struct msg_msgseg *next;
	void *security;
};

struct msg_msgseg {
	struct msg_msgseg *next;
};

struct msgbuf {
	__kernel_long_t mtype;
	char mtext[1];
};

struct msg;

struct msqid_ds {
	struct ipc_perm msg_perm;
	struct msg *msg_first;
	struct msg *msg_last;
	__kernel_old_time_t msg_stime;
	__kernel_old_time_t msg_rtime;
	__kernel_old_time_t msg_ctime;
	long unsigned int msg_lcbytes;
	long unsigned int msg_lqbytes;
	short unsigned int msg_cbytes;
	short unsigned int msg_qnum;
	short unsigned int msg_qbytes;
	__kernel_ipc_pid_t msg_lspid;
	__kernel_ipc_pid_t msg_lrpid;
};

struct msqid64_ds {
	struct ipc64_perm msg_perm;
	long unsigned int msg_stime;
	long unsigned int msg_stime_high;
	long unsigned int msg_rtime;
	long unsigned int msg_rtime_high;
	long unsigned int msg_ctime;
	long unsigned int msg_ctime_high;
	long unsigned int msg_cbytes;
	long unsigned int msg_qnum;
	long unsigned int msg_qbytes;
	__kernel_pid_t msg_lspid;
	__kernel_pid_t msg_lrpid;
	long unsigned int __unused4;
	long unsigned int __unused5;
};

struct msginfo {
	int msgpool;
	int msgmap;
	int msgmax;
	int msgmnb;
	int msgmni;
	int msgssz;
	int msgtql;
	short unsigned int msgseg;
};

struct msg_queue {
	struct kern_ipc_perm q_perm;
	time64_t q_stime;
	time64_t q_rtime;
	time64_t q_ctime;
	long unsigned int q_cbytes;
	long unsigned int q_qnum;
	long unsigned int q_qbytes;
	struct pid *q_lspid;
	struct pid *q_lrpid;
	struct list_head q_messages;
	struct list_head q_receivers;
	struct list_head q_senders;
};

struct msg_receiver {
	struct list_head r_list;
	struct task_struct *r_tsk;
	int r_mode;
	long int r_msgtype;
	long int r_maxsize;
	struct msg_msg *r_msg;
};

struct msg_sender {
	struct list_head list;
	struct task_struct *tsk;
	size_t msgsz;
};

struct sem;

struct sem_queue;

struct sem_undo;

struct semid_ds {
	struct ipc_perm sem_perm;
	__kernel_old_time_t sem_otime;
	__kernel_old_time_t sem_ctime;
	struct sem *sem_base;
	struct sem_queue *sem_pending;
	struct sem_queue **sem_pending_last;
	struct sem_undo *undo;
	short unsigned int sem_nsems;
};

struct sem {
	int semval;
	struct pid *sempid;
	spinlock_t lock;
	struct list_head pending_alter;
	struct list_head pending_const;
	time64_t sem_otime;
};

struct sem_queue {
	struct list_head list;
	struct task_struct *sleeper;
	struct sem_undo *undo;
	struct pid *pid;
	int status;
	struct sembuf *sops;
	struct sembuf *blocking;
	int nsops;
	bool alter;
	bool dupsop;
};

struct sem_undo {
	struct list_head list_proc;
	struct callback_head rcu;
	struct sem_undo_list *ulp;
	struct list_head list_id;
	int semid;
	short int *semadj;
};

struct semid64_ds {
	struct ipc64_perm sem_perm;
	long unsigned int sem_otime;
	long unsigned int sem_otime_high;
	long unsigned int sem_ctime;
	long unsigned int sem_ctime_high;
	long unsigned int sem_nsems;
	long unsigned int __unused3;
	long unsigned int __unused4;
};

struct seminfo {
	int semmap;
	int semmni;
	int semmns;
	int semmnu;
	int semmsl;
	int semopm;
	int semume;
	int semusz;
	int semvmx;
	int semaem;
};

struct sem_undo_list {
	refcount_t refcnt;
	spinlock_t lock;
	struct list_head list_proc;
};

struct sem_array {
	struct kern_ipc_perm sem_perm;
	time64_t sem_ctime;
	struct list_head pending_alter;
	struct list_head pending_const;
	struct list_head list_id;
	int sem_nsems;
	int complex_count;
	unsigned int use_global_lock;
	struct sem sems[0];
};

struct shmid64_ds {
	struct ipc64_perm shm_perm;
	__kernel_size_t shm_segsz;
	long unsigned int shm_atime;
	long unsigned int shm_atime_high;
	long unsigned int shm_dtime;
	long unsigned int shm_dtime_high;
	long unsigned int shm_ctime;
	long unsigned int shm_ctime_high;
	__kernel_pid_t shm_cpid;
	__kernel_pid_t shm_lpid;
	long unsigned int shm_nattch;
	long unsigned int __unused4;
	long unsigned int __unused5;
};

struct shminfo64 {
	long unsigned int shmmax;
	long unsigned int shmmin;
	long unsigned int shmmni;
	long unsigned int shmseg;
	long unsigned int shmall;
	long unsigned int __unused1;
	long unsigned int __unused2;
	long unsigned int __unused3;
	long unsigned int __unused4;
};

struct shminfo {
	int shmmax;
	int shmmin;
	int shmmni;
	int shmseg;
	int shmall;
};

struct shm_info {
	int used_ids;
	__kernel_ulong_t shm_tot;
	__kernel_ulong_t shm_rss;
	__kernel_ulong_t shm_swp;
	__kernel_ulong_t swap_attempts;
	__kernel_ulong_t swap_successes;
};

struct shmid_kernel {
	struct kern_ipc_perm shm_perm;
	struct file *shm_file;
	long unsigned int shm_nattch;
	long unsigned int shm_segsz;
	time64_t shm_atim;
	time64_t shm_dtim;
	time64_t shm_ctim;
	struct pid *shm_cprid;
	struct pid *shm_lprid;
	struct ucounts *mlock_ucounts;
	struct task_struct *shm_creator;
	struct list_head shm_clist;
	struct ipc_namespace *ns;
};

struct shm_file_data {
	int id;
	struct ipc_namespace *ns;
	struct file *file;
	const struct vm_operations_struct *vm_ops;
};

struct mq_attr {
	__kernel_long_t mq_flags;
	__kernel_long_t mq_maxmsg;
	__kernel_long_t mq_msgsize;
	__kernel_long_t mq_curmsgs;
	__kernel_long_t __reserved[4];
};

struct mqueue_fs_context {
	struct ipc_namespace *ipc_ns;
};

struct posix_msg_tree_node {
	struct rb_node rb_node;
	struct list_head msg_list;
	int priority;
};

struct ext_wait_queue {
	struct task_struct *task;
	struct list_head list;
	struct msg_msg *msg;
	int state;
};

struct mqueue_inode_info {
	spinlock_t lock;
	struct inode vfs_inode;
	wait_queue_head_t wait_q;
	struct rb_root msg_tree;
	struct rb_node *msg_tree_rightmost;
	struct posix_msg_tree_node *node_cache;
	struct mq_attr attr;
	struct sigevent notify;
	struct pid *notify_owner;
	u32 notify_self_exec_id;
	struct user_namespace *notify_user_ns;
	struct ucounts *ucounts;
	struct sock *notify_sock;
	struct sk_buff *notify_cookie;
	struct ext_wait_queue e_wait_q[2];
	long unsigned int qsize;
};

struct vfs_cap_data {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
};

struct vfs_ns_cap_data {
	__le32 magic_etc;
	struct {
		__le32 permitted;
		__le32 inheritable;
	} data[2];
	__le32 rootid;
};

struct cpu_vfs_cap_data {
	__u32 magic_etc;
	kernel_cap_t permitted;
	kernel_cap_t inheritable;
	kuid_t rootid;
};

struct crypto_async_request;

typedef void (*crypto_completion_t)(struct crypto_async_request *, int);

struct crypto_tfm;

struct crypto_async_request {
	struct list_head list;
	crypto_completion_t complete;
	void *data;
	struct crypto_tfm *tfm;
	u32 flags;
};

struct crypto_alg;

struct crypto_tfm {
	u32 crt_flags;
	int node;
	void (*exit)(struct crypto_tfm *);
	struct crypto_alg *__crt_alg;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	void *__crt_ctx[0];
};

struct cipher_alg {
	unsigned int cia_min_keysize;
	unsigned int cia_max_keysize;
	int (*cia_setkey)(struct crypto_tfm *, const u8 *, unsigned int);
	void (*cia_encrypt)(struct crypto_tfm *, u8 *, const u8 *);
	void (*cia_decrypt)(struct crypto_tfm *, u8 *, const u8 *);
};

struct compress_alg {
	int (*coa_compress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
	int (*coa_decompress)(struct crypto_tfm *, const u8 *, unsigned int, u8 *, unsigned int *);
};

struct crypto_type;

struct crypto_alg {
	struct list_head cra_list;
	struct list_head cra_users;
	u32 cra_flags;
	unsigned int cra_blocksize;
	unsigned int cra_ctxsize;
	unsigned int cra_alignmask;
	int cra_priority;
	refcount_t cra_refcnt;
	char cra_name[128];
	char cra_driver_name[128];
	const struct crypto_type *cra_type;
	union {
		struct cipher_alg cipher;
		struct compress_alg compress;
	} cra_u;
	int (*cra_init)(struct crypto_tfm *);
	void (*cra_exit)(struct crypto_tfm *);
	void (*cra_destroy)(struct crypto_alg *);
	struct module *cra_module;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct crypto_instance;

struct crypto_type {
	unsigned int (*ctxsize)(struct crypto_alg *, u32, u32);
	unsigned int (*extsize)(struct crypto_alg *);
	int (*init)(struct crypto_tfm *, u32, u32);
	int (*init_tfm)(struct crypto_tfm *);
	void (*show)(struct seq_file *, struct crypto_alg *);
	int (*report)(struct sk_buff *, struct crypto_alg *);
	void (*free)(struct crypto_instance *);
	unsigned int type;
	unsigned int maskclear;
	unsigned int maskset;
	unsigned int tfmsize;
};

struct crypto_wait {
	struct completion completion;
	int err;
};

struct crypto_template;

struct crypto_spawn;

struct crypto_instance {
	struct crypto_alg alg;
	struct crypto_template *tmpl;
	union {
		struct hlist_node list;
		struct crypto_spawn *spawns;
	};
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	void *__ctx[0];
};

struct crypto_spawn {
	struct list_head list;
	struct crypto_alg *alg;
	union {
		struct crypto_instance *inst;
		struct crypto_spawn *next;
	};
	const struct crypto_type *frontend;
	u32 mask;
	bool dead;
	bool registered;
};

struct rtattr;

struct crypto_template {
	struct list_head list;
	struct hlist_head instances;
	struct module *module;
	int (*create)(struct crypto_template *, struct rtattr **);
	char name[128];
};

enum {
	CRYPTO_MSG_ALG_REQUEST = 0,
	CRYPTO_MSG_ALG_REGISTER = 1,
	CRYPTO_MSG_ALG_LOADED = 2,
};

struct crypto_larval {
	struct crypto_alg alg;
	struct crypto_alg *adult;
	struct completion completion;
	u32 mask;
	bool test_started;
	int: 24;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

struct crypto_cipher {
	struct crypto_tfm base;
};

struct crypto_comp {
	struct crypto_tfm base;
};

struct scatter_walk {
	struct scatterlist *sg;
	unsigned int offset;
};

struct rtattr {
	short unsigned int rta_len;
	short unsigned int rta_type;
};

struct crypto_queue {
	struct list_head list;
	struct list_head *backlog;
	unsigned int qlen;
	unsigned int max_qlen;
};

struct crypto_attr_alg {
	char name[128];
};

struct crypto_attr_type {
	u32 type;
	u32 mask;
};

enum {
	CRYPTOA_UNSPEC = 0,
	CRYPTOA_ALG = 1,
	CRYPTOA_TYPE = 2,
	__CRYPTOA_MAX = 3,
};

struct hash_alg_common {
	unsigned int digestsize;
	unsigned int statesize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_alg base;
};

struct ahash_request {
	struct crypto_async_request base;
	unsigned int nbytes;
	struct scatterlist *src;
	u8 *result;
	void *priv;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	void *__ctx[0];
};

struct crypto_ahash;

struct ahash_alg {
	int (*init)(struct ahash_request *);
	int (*update)(struct ahash_request *);
	int (*final)(struct ahash_request *);
	int (*finup)(struct ahash_request *);
	int (*digest)(struct ahash_request *);
	int (*export)(struct ahash_request *, void *);
	int (*import)(struct ahash_request *, const void *);
	int (*setkey)(struct crypto_ahash *, const u8 *, unsigned int);
	int (*init_tfm)(struct crypto_ahash *);
	void (*exit_tfm)(struct crypto_ahash *);
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct hash_alg_common halg;
};

struct crypto_ahash {
	int (*init)(struct ahash_request *);
	int (*update)(struct ahash_request *);
	int (*final)(struct ahash_request *);
	int (*finup)(struct ahash_request *);
	int (*digest)(struct ahash_request *);
	int (*export)(struct ahash_request *, void *);
	int (*import)(struct ahash_request *, const void *);
	int (*setkey)(struct crypto_ahash *, const u8 *, unsigned int);
	unsigned int reqsize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_tfm base;
};

struct crypto_shash;

struct shash_desc {
	struct crypto_shash *tfm;
	int: 32;
	void *__ctx[0];
};

struct crypto_shash {
	unsigned int descsize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_tfm base;
};

struct shash_alg {
	int (*init)(struct shash_desc *);
	int (*update)(struct shash_desc *, const u8 *, unsigned int);
	int (*final)(struct shash_desc *, u8 *);
	int (*finup)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*digest)(struct shash_desc *, const u8 *, unsigned int, u8 *);
	int (*export)(struct shash_desc *, void *);
	int (*import)(struct shash_desc *, const void *);
	int (*setkey)(struct crypto_shash *, const u8 *, unsigned int);
	int (*init_tfm)(struct crypto_shash *);
	void (*exit_tfm)(struct crypto_shash *);
	unsigned int descsize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	unsigned int digestsize;
	unsigned int statesize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_alg base;
};

struct crypto_hash_walk {
	char *data;
	unsigned int offset;
	unsigned int alignmask;
	struct page *pg;
	unsigned int entrylen;
	unsigned int total;
	struct scatterlist *sg;
	unsigned int flags;
};

struct ahash_instance {
	void (*free)(struct ahash_instance *);
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	union {
		struct {
			char head[256];
			struct crypto_instance base;
		} s;
		struct ahash_alg alg;
	};
};

struct crypto_ahash_spawn {
	struct crypto_spawn base;
};

enum crypto_attr_type_t {
	CRYPTOCFGA_UNSPEC = 0,
	CRYPTOCFGA_PRIORITY_VAL = 1,
	CRYPTOCFGA_REPORT_LARVAL = 2,
	CRYPTOCFGA_REPORT_HASH = 3,
	CRYPTOCFGA_REPORT_BLKCIPHER = 4,
	CRYPTOCFGA_REPORT_AEAD = 5,
	CRYPTOCFGA_REPORT_COMPRESS = 6,
	CRYPTOCFGA_REPORT_RNG = 7,
	CRYPTOCFGA_REPORT_CIPHER = 8,
	CRYPTOCFGA_REPORT_AKCIPHER = 9,
	CRYPTOCFGA_REPORT_KPP = 10,
	CRYPTOCFGA_REPORT_ACOMP = 11,
	CRYPTOCFGA_STAT_LARVAL = 12,
	CRYPTOCFGA_STAT_HASH = 13,
	CRYPTOCFGA_STAT_BLKCIPHER = 14,
	CRYPTOCFGA_STAT_AEAD = 15,
	CRYPTOCFGA_STAT_COMPRESS = 16,
	CRYPTOCFGA_STAT_RNG = 17,
	CRYPTOCFGA_STAT_CIPHER = 18,
	CRYPTOCFGA_STAT_AKCIPHER = 19,
	CRYPTOCFGA_STAT_KPP = 20,
	CRYPTOCFGA_STAT_ACOMP = 21,
	__CRYPTOCFGA_MAX = 22,
};

struct crypto_report_hash {
	char type[64];
	unsigned int blocksize;
	unsigned int digestsize;
};

struct ahash_request_priv {
	crypto_completion_t complete;
	void *data;
	u8 *result;
	u32 flags;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	void *ubuf[0];
};

struct aead_request {
	struct crypto_async_request base;
	unsigned int assoclen;
	unsigned int cryptlen;
	u8 *iv;
	struct scatterlist *src;
	struct scatterlist *dst;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	void *__ctx[0];
};

struct crypto_aead;

struct aead_alg {
	int (*setkey)(struct crypto_aead *, const u8 *, unsigned int);
	int (*setauthsize)(struct crypto_aead *, unsigned int);
	int (*encrypt)(struct aead_request *);
	int (*decrypt)(struct aead_request *);
	int (*init)(struct crypto_aead *);
	void (*exit)(struct crypto_aead *);
	unsigned int ivsize;
	unsigned int maxauthsize;
	unsigned int chunksize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_alg base;
};

struct crypto_aead {
	unsigned int authsize;
	unsigned int reqsize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_tfm base;
};

struct crypto_cipher_spawn {
	struct crypto_spawn base;
};

struct skcipher_request {
	unsigned int cryptlen;
	u8 *iv;
	struct scatterlist *src;
	struct scatterlist *dst;
	struct crypto_async_request base;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	void *__ctx[0];
};

struct crypto_skcipher {
	unsigned int reqsize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_tfm base;
};

struct crypto_sync_skcipher {
	struct crypto_skcipher base;
};

struct skcipher_alg {
	int (*setkey)(struct crypto_skcipher *, const u8 *, unsigned int);
	int (*encrypt)(struct skcipher_request *);
	int (*decrypt)(struct skcipher_request *);
	int (*init)(struct crypto_skcipher *);
	void (*exit)(struct crypto_skcipher *);
	unsigned int min_keysize;
	unsigned int max_keysize;
	unsigned int ivsize;
	unsigned int chunksize;
	unsigned int walksize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_alg base;
};

struct skcipher_instance {
	void (*free)(struct skcipher_instance *);
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	union {
		struct {
			char head[128];
			struct crypto_instance base;
		} s;
		struct skcipher_alg alg;
	};
};

struct crypto_skcipher_spawn {
	struct crypto_spawn base;
};

struct skcipher_walk {
	union {
		struct {
			struct page *page;
			long unsigned int offset;
		} phys;
		struct {
			u8 *page;
			void *addr;
		} virt;
	} src;
	union {
		struct {
			struct page *page;
			long unsigned int offset;
		} phys;
		struct {
			u8 *page;
			void *addr;
		} virt;
	} dst;
	struct scatter_walk in;
	unsigned int nbytes;
	struct scatter_walk out;
	unsigned int total;
	struct list_head buffers;
	u8 *page;
	u8 *buffer;
	u8 *oiv;
	void *iv;
	unsigned int ivsize;
	int flags;
	unsigned int blocksize;
	unsigned int stride;
	unsigned int alignmask;
};

struct skcipher_ctx_simple {
	struct crypto_cipher *cipher;
};

struct crypto_report_blkcipher {
	char type[64];
	char geniv[64];
	unsigned int blocksize;
	unsigned int min_keysize;
	unsigned int max_keysize;
	unsigned int ivsize;
};

enum {
	SKCIPHER_WALK_PHYS = 1,
	SKCIPHER_WALK_SLOW = 2,
	SKCIPHER_WALK_COPY = 4,
	SKCIPHER_WALK_DIFF = 8,
	SKCIPHER_WALK_SLEEP = 16,
};

struct skcipher_walk_buffer {
	struct list_head entry;
	struct scatter_walk dst;
	unsigned int len;
	u8 *data;
	u8 buffer[0];
};

struct shash_instance {
	void (*free)(struct shash_instance *);
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	union {
		struct {
			char head[256];
			struct crypto_instance base;
		} s;
		struct shash_alg alg;
	};
};

struct crypto_shash_spawn {
	struct crypto_spawn base;
};

struct crypto_rng;

struct rng_alg {
	int (*generate)(struct crypto_rng *, const u8 *, unsigned int, u8 *, unsigned int);
	int (*seed)(struct crypto_rng *, const u8 *, unsigned int);
	void (*set_ent)(struct crypto_rng *, const u8 *, unsigned int);
	unsigned int seedsize;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct crypto_alg base;
};

struct crypto_rng {
	struct crypto_tfm base;
};

struct crypto_report_rng {
	char type[64];
	unsigned int seedsize;
};

struct disk_stats {
	u64 nsecs[4];
	long unsigned int sectors[4];
	long unsigned int ios[4];
	long unsigned int merges[4];
	long unsigned int io_ticks;
	local_t in_flight[2];
};

enum stat_group {
	STAT_READ = 0,
	STAT_WRITE = 1,
	STAT_DISCARD = 2,
	STAT_FLUSH = 3,
	NR_STAT_GROUPS = 4,
};

enum {
	DISK_EVENT_MEDIA_CHANGE = 1,
	DISK_EVENT_EJECT_REQUEST = 2,
};

enum {
	DISK_EVENT_FLAG_POLL = 1,
	DISK_EVENT_FLAG_UEVENT = 2,
	DISK_EVENT_FLAG_BLOCK_ON_EXCL_WRITE = 4,
};

struct blk_integrity_profile;

struct blk_integrity {
	const struct blk_integrity_profile *profile;
	unsigned char flags;
	unsigned char tuple_size;
	unsigned char interval_exp;
	unsigned char tag_size;
};

struct blk_integrity_iter;

typedef blk_status_t integrity_processing_fn(struct blk_integrity_iter *);

typedef void integrity_prepare_fn(struct request *);

typedef void integrity_complete_fn(struct request *, unsigned int);

struct blk_integrity_profile {
	integrity_processing_fn *generate_fn;
	integrity_processing_fn *verify_fn;
	integrity_prepare_fn *prepare_fn;
	integrity_complete_fn *complete_fn;
	const char *name;
};

struct blk_integrity_iter {
	void *prot_buf;
	void *data_buf;
	sector_t seed;
	unsigned int data_size;
	short unsigned int interval;
	unsigned char tuple_size;
	const char *disk_name;
};

struct bdev_inode {
	struct block_device bdev;
	int: 32;
	struct inode vfs_inode;
};

enum {
	DIO_SHOULD_DIRTY = 1,
	DIO_IS_SYNC = 2,
};

struct blkdev_dio {
	union {
		struct kiocb *iocb;
		struct task_struct *waiter;
	};
	size_t size;
	atomic_t ref;
	unsigned int flags;
	struct bio bio;
};

struct bio_alloc_cache {
	struct bio *free_list;
	unsigned int nr;
};

enum rq_qos_id {
	RQ_QOS_WBT = 0,
	RQ_QOS_LATENCY = 1,
	RQ_QOS_COST = 2,
	RQ_QOS_IOPRIO = 3,
};

struct rq_qos_ops;

struct rq_qos {
	struct rq_qos_ops *ops;
	struct request_queue *q;
	enum rq_qos_id id;
	struct rq_qos *next;
	struct dentry *debugfs_dir;
};

enum {
	sysctl_hung_task_timeout_secs = 0,
};

enum xen_domain_type {
	XEN_NATIVE = 0,
	XEN_PV_DOMAIN = 1,
	XEN_HVM_DOMAIN = 2,
};

struct blk_mq_debugfs_attr {
	const char *name;
	umode_t mode;
	int (*show)(void *, struct seq_file *);
	ssize_t (*write)(void *, const char *, size_t, loff_t *);
	const struct seq_operations *seq_ops;
};

struct rq_qos_ops {
	void (*throttle)(struct rq_qos *, struct bio *);
	void (*track)(struct rq_qos *, struct request *, struct bio *);
	void (*merge)(struct rq_qos *, struct request *, struct bio *);
	void (*issue)(struct rq_qos *, struct request *);
	void (*requeue)(struct rq_qos *, struct request *);
	void (*done)(struct rq_qos *, struct request *);
	void (*done_bio)(struct rq_qos *, struct bio *);
	void (*cleanup)(struct rq_qos *, struct bio *);
	void (*queue_depth_changed)(struct rq_qos *);
	void (*exit)(struct rq_qos *);
	const struct blk_mq_debugfs_attr *debugfs_attrs;
};

struct biovec_slab {
	int nr_vecs;
	char *name;
	struct kmem_cache *slab;
};

struct bio_slab {
	struct kmem_cache *slab;
	unsigned int slab_ref;
	unsigned int slab_size;
	char name[8];
};

struct elevator_type;

struct elevator_queue {
	struct elevator_type *type;
	void *elevator_data;
	struct kobject kobj;
	struct mutex sysfs_lock;
	unsigned int registered: 1;
	struct hlist_head hash[64];
};

struct blk_mq_ctxs;

struct blk_mq_ctx {
	struct {
		spinlock_t lock;
		struct list_head rq_lists[3];
	};
	unsigned int cpu;
	short unsigned int index_hw[3];
	struct blk_mq_hw_ctx *hctxs[3];
	struct request_queue *queue;
	struct blk_mq_ctxs *ctxs;
	struct kobject kobj;
};

struct blk_stat_callback {
	struct list_head list;
	struct timer_list timer;
	struct blk_rq_stat *cpu_stat;
	int (*bucket_fn)(const struct request *);
	unsigned int buckets;
	struct blk_rq_stat *stat;
	void (*timer_fn)(struct blk_stat_callback *);
	void *data;
	struct callback_head rcu;
};

enum {
	BLK_MQ_F_SHOULD_MERGE = 1,
	BLK_MQ_F_TAG_QUEUE_SHARED = 2,
	BLK_MQ_F_STACKING = 4,
	BLK_MQ_F_TAG_HCTX_SHARED = 8,
	BLK_MQ_F_BLOCKING = 32,
	BLK_MQ_F_NO_SCHED = 64,
	BLK_MQ_F_NO_SCHED_BY_DEFAULT = 128,
	BLK_MQ_F_ALLOC_POLICY_START_BIT = 8,
	BLK_MQ_F_ALLOC_POLICY_BITS = 1,
	BLK_MQ_S_STOPPED = 0,
	BLK_MQ_S_TAG_ACTIVE = 1,
	BLK_MQ_S_SCHED_RESTART = 2,
	BLK_MQ_S_INACTIVE = 3,
	BLK_MQ_MAX_DEPTH = 10240,
	BLK_MQ_CPU_WORK_BATCH = 8,
};

enum elv_merge {
	ELEVATOR_NO_MERGE = 0,
	ELEVATOR_FRONT_MERGE = 1,
	ELEVATOR_BACK_MERGE = 2,
	ELEVATOR_DISCARD_MERGE = 3,
};

struct blk_mq_alloc_data;

struct elevator_mq_ops {
	int (*init_sched)(struct request_queue *, struct elevator_type *);
	void (*exit_sched)(struct elevator_queue *);
	int (*init_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*exit_hctx)(struct blk_mq_hw_ctx *, unsigned int);
	void (*depth_updated)(struct blk_mq_hw_ctx *);
	bool (*allow_merge)(struct request_queue *, struct request *, struct bio *);
	bool (*bio_merge)(struct request_queue *, struct bio *, unsigned int);
	int (*request_merge)(struct request_queue *, struct request **, struct bio *);
	void (*request_merged)(struct request_queue *, struct request *, enum elv_merge);
	void (*requests_merged)(struct request_queue *, struct request *, struct request *);
	void (*limit_depth)(unsigned int, struct blk_mq_alloc_data *);
	void (*prepare_request)(struct request *);
	void (*finish_request)(struct request *);
	void (*insert_requests)(struct blk_mq_hw_ctx *, struct list_head *, bool);
	struct request * (*dispatch_request)(struct blk_mq_hw_ctx *);
	bool (*has_work)(struct blk_mq_hw_ctx *);
	void (*completed_request)(struct request *, u64);
	void (*requeue_request)(struct request *);
	struct request * (*former_request)(struct request_queue *, struct request *);
	struct request * (*next_request)(struct request_queue *, struct request *);
	void (*init_icq)(struct io_cq *);
	void (*exit_icq)(struct io_cq *);
};

struct elv_fs_entry;

struct elevator_type {
	struct kmem_cache *icq_cache;
	struct elevator_mq_ops ops;
	size_t icq_size;
	size_t icq_align;
	struct elv_fs_entry *elevator_attrs;
	const char *elevator_name;
	const char *elevator_alias;
	const unsigned int elevator_features;
	struct module *elevator_owner;
	const struct blk_mq_debugfs_attr *queue_debugfs_attrs;
	const struct blk_mq_debugfs_attr *hctx_debugfs_attrs;
	char icq_cache_name[22];
	struct list_head list;
};

struct blk_mq_alloc_data {
	struct request_queue *q;
	blk_mq_req_flags_t flags;
	unsigned int shallow_depth;
	unsigned int cmd_flags;
	req_flags_t rq_flags;
	unsigned int nr_tags;
	struct request **cached_rq;
	struct blk_mq_ctx *ctx;
	struct blk_mq_hw_ctx *hctx;
};

struct elv_fs_entry {
	struct attribute attr;
	ssize_t (*show)(struct elevator_queue *, char *);
	ssize_t (*store)(struct elevator_queue *, const char *, size_t);
};

struct blk_mq_ctxs {
	struct kobject kobj;
	struct blk_mq_ctx *queue_ctx;
};

enum {
	WBT_RWQ_BG = 0,
	WBT_RWQ_KSWAPD = 1,
	WBT_RWQ_DISCARD = 2,
	WBT_NUM_RWQ = 3,
};

enum blkg_rwstat_type {
	BLKG_RWSTAT_READ = 0,
	BLKG_RWSTAT_WRITE = 1,
	BLKG_RWSTAT_SYNC = 2,
	BLKG_RWSTAT_ASYNC = 3,
	BLKG_RWSTAT_DISCARD = 4,
	BLKG_RWSTAT_NR = 5,
	BLKG_RWSTAT_TOTAL = 5,
};

enum {
	LIMIT_LOW = 0,
	LIMIT_MAX = 1,
	LIMIT_CNT = 2,
};

struct queue_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct request_queue *, char *);
	ssize_t (*store)(struct request_queue *, const char *, size_t);
};

enum rpm_status {
	RPM_INVALID = 4294967295,
	RPM_ACTIVE = 0,
	RPM_RESUMING = 1,
	RPM_SUSPENDED = 2,
	RPM_SUSPENDING = 3,
};

struct blk_plug_cb;

typedef void (*blk_plug_cb_fn)(struct blk_plug_cb *, bool);

struct blk_plug_cb {
	struct list_head list;
	blk_plug_cb_fn callback;
	void *data;
};

enum {
	BLK_MQ_REQ_NOWAIT = 1,
	BLK_MQ_REQ_RESERVED = 2,
	BLK_MQ_REQ_PM = 4,
};

struct trace_event_raw_block_buffer {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	size_t size;
	char __data[0];
};

struct trace_event_raw_block_rq_requeue {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	char rwbs[8];
	u32 __data_loc_cmd;
	char __data[0];
};

struct trace_event_raw_block_rq_completion {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	int error;
	char rwbs[8];
	u32 __data_loc_cmd;
	char __data[0];
};

struct trace_event_raw_block_rq {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	unsigned int bytes;
	char rwbs[8];
	char comm[16];
	u32 __data_loc_cmd;
	char __data[0];
};

struct trace_event_raw_block_bio_complete {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	int error;
	char rwbs[8];
	char __data[0];
};

struct trace_event_raw_block_bio {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	char rwbs[8];
	char comm[16];
	char __data[0];
};

struct trace_event_raw_block_plug {
	struct trace_entry ent;
	char comm[16];
	char __data[0];
};

struct trace_event_raw_block_unplug {
	struct trace_entry ent;
	int nr_rq;
	char comm[16];
	char __data[0];
};

struct trace_event_raw_block_split {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	sector_t new_sector;
	char rwbs[8];
	char comm[16];
	char __data[0];
};

struct trace_event_raw_block_bio_remap {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	dev_t old_dev;
	sector_t old_sector;
	char rwbs[8];
	char __data[0];
};

struct trace_event_raw_block_rq_remap {
	struct trace_entry ent;
	dev_t dev;
	sector_t sector;
	unsigned int nr_sector;
	dev_t old_dev;
	sector_t old_sector;
	unsigned int nr_bios;
	char rwbs[8];
	char __data[0];
};

struct trace_event_data_offsets_block_buffer {};

struct trace_event_data_offsets_block_rq_requeue {
	u32 cmd;
};

struct trace_event_data_offsets_block_rq_completion {
	u32 cmd;
};

struct trace_event_data_offsets_block_rq {
	u32 cmd;
};

struct trace_event_data_offsets_block_bio_complete {};

struct trace_event_data_offsets_block_bio {};

struct trace_event_data_offsets_block_plug {};

struct trace_event_data_offsets_block_unplug {};

struct trace_event_data_offsets_block_split {};

struct trace_event_data_offsets_block_bio_remap {};

struct trace_event_data_offsets_block_rq_remap {};

typedef void (*btf_trace_block_touch_buffer)(void *, struct buffer_head *);

typedef void (*btf_trace_block_dirty_buffer)(void *, struct buffer_head *);

typedef void (*btf_trace_block_rq_requeue)(void *, struct request *);

typedef void (*btf_trace_block_rq_complete)(void *, struct request *, blk_status_t, unsigned int);

typedef void (*btf_trace_block_rq_error)(void *, struct request *, blk_status_t, unsigned int);

typedef void (*btf_trace_block_rq_insert)(void *, struct request *);

typedef void (*btf_trace_block_rq_issue)(void *, struct request *);

typedef void (*btf_trace_block_rq_merge)(void *, struct request *);

typedef void (*btf_trace_block_bio_complete)(void *, struct request_queue *, struct bio *);

typedef void (*btf_trace_block_bio_bounce)(void *, struct bio *);

typedef void (*btf_trace_block_bio_backmerge)(void *, struct bio *);

typedef void (*btf_trace_block_bio_frontmerge)(void *, struct bio *);

typedef void (*btf_trace_block_bio_queue)(void *, struct bio *);

typedef void (*btf_trace_block_getrq)(void *, struct bio *);

typedef void (*btf_trace_block_plug)(void *, struct request_queue *);

typedef void (*btf_trace_block_unplug)(void *, struct request_queue *, unsigned int, bool);

typedef void (*btf_trace_block_split)(void *, struct bio *, unsigned int);

typedef void (*btf_trace_block_bio_remap)(void *, struct bio *, dev_t, sector_t);

typedef void (*btf_trace_block_rq_remap)(void *, struct request *, dev_t, sector_t);

enum {
	BLK_MQ_NO_TAG = 4294967295,
	BLK_MQ_TAG_MIN = 1,
	BLK_MQ_TAG_MAX = 4294967294,
};

enum {
	REQ_FSEQ_PREFLUSH = 1,
	REQ_FSEQ_DATA = 2,
	REQ_FSEQ_POSTFLUSH = 4,
	REQ_FSEQ_DONE = 8,
	REQ_FSEQ_ACTIONS = 7,
	FLUSH_PENDING_TIMEOUT = 500,
};

enum blk_default_limits {
	BLK_MAX_SEGMENTS = 128,
	BLK_SAFE_MAX_SECTORS = 255,
	BLK_DEF_MAX_SECTORS = 2560,
	BLK_MAX_SEGMENT_SIZE = 65536,
	BLK_SEG_BOUNDARY_MASK = 4294967295,
};

struct rq_map_data {
	struct page **pages;
	int page_order;
	int nr_entries;
	long unsigned int offset;
	int null_mapped;
	int from_user;
};

struct bio_map_data {
	bool is_our_pages: 1;
	bool is_null_mapped: 1;
	struct iov_iter iter;
	struct iovec iov[0];
};

struct req_iterator {
	struct bvec_iter iter;
	struct bio *bio;
};

enum bio_merge_status {
	BIO_MERGE_OK = 0,
	BIO_MERGE_NONE = 1,
	BIO_MERGE_FAILED = 2,
};

typedef bool (*sb_for_each_fn)(struct sbitmap *, unsigned int, void *);

struct sbq_wait {
	struct sbitmap_queue *sbq;
	struct wait_queue_entry wait;
};

typedef bool busy_tag_iter_fn(struct request *, void *, bool);

enum {
	BLK_MQ_UNIQUE_TAG_BITS = 16,
	BLK_MQ_UNIQUE_TAG_MASK = 65535,
};

struct bt_iter_data {
	struct blk_mq_hw_ctx *hctx;
	struct request_queue *q;
	busy_tag_iter_fn *fn;
	void *data;
	bool reserved;
};

struct bt_tags_iter_data {
	struct blk_mq_tags *tags;
	busy_tag_iter_fn *fn;
	void *data;
	unsigned int flags;
};

struct mq_inflight {
	struct block_device *part;
	unsigned int inflight[2];
};

struct flush_busy_ctx_data {
	struct blk_mq_hw_ctx *hctx;
	struct list_head *list;
};

struct dispatch_rq_data {
	struct blk_mq_hw_ctx *hctx;
	struct request *rq;
};

enum prep_dispatch {
	PREP_DISPATCH_OK = 0,
	PREP_DISPATCH_NO_TAG = 1,
	PREP_DISPATCH_NO_BUDGET = 2,
};

struct rq_iter_data {
	struct blk_mq_hw_ctx *hctx;
	bool has_rq;
};

struct blk_mq_qe_pair {
	struct list_head node;
	struct request_queue *q;
	struct elevator_type *type;
};

struct blk_queue_stats {
	struct list_head callbacks;
	spinlock_t lock;
	int accounting;
};

struct blk_mq_hw_ctx_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct blk_mq_hw_ctx *, char *);
	ssize_t (*store)(struct blk_mq_hw_ctx *, const char *, size_t);
};

struct hd_geometry {
	unsigned char heads;
	unsigned char sectors;
	short unsigned int cylinders;
	long unsigned int start;
};

struct blkpg_ioctl_arg {
	int op;
	int flags;
	int datalen;
	void *data;
};

struct blkpg_partition {
	long long int start;
	long long int length;
	int pno;
	char devname[64];
	char volname[64];
};

struct pr_reservation {
	__u64 key;
	__u32 type;
	__u32 flags;
};

struct pr_registration {
	__u64 old_key;
	__u64 new_key;
	__u32 flags;
	__u32 __pad;
};

struct pr_preempt {
	__u64 old_key;
	__u64 new_key;
	__u32 type;
	__u32 flags;
};

struct pr_clear {
	__u64 key;
	__u32 flags;
	__u32 __pad;
};

struct klist_node;

struct klist {
	spinlock_t k_lock;
	struct list_head k_list;
	void (*get)(struct klist_node *);
	void (*put)(struct klist_node *);
};

struct klist_node {
	void *n_klist;
	struct list_head n_node;
	struct kref n_ref;
};

struct klist_iter {
	struct klist *i_klist;
	struct klist_node *i_cur;
};

struct class_dev_iter {
	struct klist_iter ki;
	const struct device_type *type;
};

enum {
	GENHD_FL_REMOVABLE = 1,
	GENHD_FL_HIDDEN = 2,
	GENHD_FL_NO_PART = 4,
};

struct badblocks {
	struct device *dev;
	int count;
	int unacked_exist;
	int shift;
	u64 *page;
	int changed;
	seqlock_t lock;
	sector_t sector;
	sector_t size;
};

struct blk_major_name {
	struct blk_major_name *next;
	int major;
	char name[16];
	void (*probe)(dev_t);
};

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP = 2,
	IOPRIO_WHO_USER = 3,
};

struct parsed_partitions {
	struct gendisk *disk;
	char name[32];
	struct {
		sector_t from;
		sector_t size;
		int flags;
		bool has_info;
		struct partition_meta_info info;
	} *parts;
	int next;
	int limit;
	bool access_beyond_eod;
	char *pp_buf;
};

typedef struct {
	struct page *v;
} Sector;

struct fat_boot_sector {
	__u8 ignored[3];
	__u8 system_id[8];
	__u8 sector_size[2];
	__u8 sec_per_clus;
	__le16 reserved;
	__u8 fats;
	__u8 dir_entries[2];
	__u8 sectors[2];
	__u8 media;
	__le16 fat_length;
	__le16 secs_track;
	__le16 heads;
	__le32 hidden;
	__le32 total_sect;
	union {
		struct {
			__u8 drive_number;
			__u8 state;
			__u8 signature;
			__u8 vol_id[4];
			__u8 vol_label[11];
			__u8 fs_type[8];
		} fat16;
		struct {
			__le32 length;
			__le16 flags;
			__u8 version[2];
			__le32 root_cluster;
			__le16 info_sector;
			__le16 backup_boot;
			__le16 reserved2[6];
			__u8 drive_number;
			__u8 state;
			__u8 signature;
			__u8 vol_id[4];
			__u8 vol_label[11];
			__u8 fs_type[8];
		} fat32;
	};
};

struct msdos_partition {
	u8 boot_ind;
	u8 head;
	u8 sector;
	u8 cyl;
	u8 sys_ind;
	u8 end_head;
	u8 end_sector;
	u8 end_cyl;
	__le32 start_sect;
	__le32 nr_sects;
};

enum msdos_sys_ind {
	DOS_EXTENDED_PARTITION = 5,
	LINUX_EXTENDED_PARTITION = 133,
	WIN98_EXTENDED_PARTITION = 15,
	LINUX_DATA_PARTITION = 131,
	LINUX_LVM_PARTITION = 142,
	LINUX_RAID_PARTITION = 253,
	SOLARIS_X86_PARTITION = 130,
	NEW_SOLARIS_X86_PARTITION = 191,
	DM6_AUX1PARTITION = 81,
	DM6_AUX3PARTITION = 83,
	DM6_PARTITION = 84,
	EZD_PARTITION = 85,
	FREEBSD_PARTITION = 165,
	OPENBSD_PARTITION = 166,
	NETBSD_PARTITION = 169,
	BSDI_PARTITION = 183,
	MINIX_PARTITION = 129,
	UNIXWARE_PARTITION = 99,
};

typedef struct {
	__u8 b[16];
} guid_t;

typedef guid_t efi_guid_t;

struct _gpt_header {
	__le64 signature;
	__le32 revision;
	__le32 header_size;
	__le32 header_crc32;
	__le32 reserved1;
	__le64 my_lba;
	__le64 alternate_lba;
	__le64 first_usable_lba;
	__le64 last_usable_lba;
	efi_guid_t disk_guid;
	__le64 partition_entry_lba;
	__le32 num_partition_entries;
	__le32 sizeof_partition_entry;
	__le32 partition_entry_array_crc32;
};

typedef struct _gpt_header gpt_header;

struct _gpt_entry_attributes {
	u64 required_to_function: 1;
	u64 reserved: 47;
	u64 type_guid_specific: 16;
};

typedef struct _gpt_entry_attributes gpt_entry_attributes;

struct _gpt_entry {
	efi_guid_t partition_type_guid;
	efi_guid_t unique_partition_guid;
	__le64 starting_lba;
	__le64 ending_lba;
	gpt_entry_attributes attributes;
	__le16 partition_name[36];
};

typedef struct _gpt_entry gpt_entry;

struct _gpt_mbr_record {
	u8 boot_indicator;
	u8 start_head;
	u8 start_sector;
	u8 start_track;
	u8 os_type;
	u8 end_head;
	u8 end_sector;
	u8 end_track;
	__le32 starting_lba;
	__le32 size_in_lba;
};

typedef struct _gpt_mbr_record gpt_mbr_record;

struct _legacy_mbr {
	u8 boot_code[440];
	__le32 unique_mbr_signature;
	__le16 unknown;
	gpt_mbr_record partition_record[4];
	__le16 signature;
} __attribute__((packed));

typedef struct _legacy_mbr legacy_mbr;

struct rq_wait {
	wait_queue_head_t wait;
	atomic_t inflight;
};

struct rq_depth {
	unsigned int max_depth;
	int scale_step;
	bool scaled_max;
	unsigned int queue_depth;
	unsigned int default_depth;
};

typedef bool acquire_inflight_cb_t(struct rq_wait *, void *);

typedef void cleanup_cb_t(struct rq_wait *, void *);

struct rq_qos_wait_data {
	struct wait_queue_entry wq;
	struct task_struct *task;
	struct rq_wait *rqw;
	acquire_inflight_cb_t *cb;
	void *private_data;
	bool got_token;
};

struct disk_events {
	struct list_head node;
	struct gendisk *disk;
	spinlock_t lock;
	struct mutex block_mutex;
	int block;
	unsigned int pending;
	unsigned int clearing;
	long int poll_msecs;
	struct delayed_work dwork;
};

struct blk_ia_range_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct blk_independent_access_range *, char *);
};

enum dd_data_dir {
	DD_READ = 0,
	DD_WRITE = 1,
};

enum {
	DD_DIR_COUNT = 2,
};

enum dd_prio {
	DD_RT_PRIO = 0,
	DD_BE_PRIO = 1,
	DD_IDLE_PRIO = 2,
	DD_PRIO_MAX = 2,
};

enum {
	DD_PRIO_COUNT = 3,
};

struct io_stats_per_prio {
	uint32_t inserted;
	uint32_t merged;
	uint32_t dispatched;
	atomic_t completed;
};

struct dd_per_prio {
	struct list_head dispatch;
	struct rb_root sort_list[2];
	struct list_head fifo_list[2];
	struct request *next_rq[2];
	struct io_stats_per_prio stats;
};

struct deadline_data {
	struct dd_per_prio per_prio[3];
	enum dd_data_dir last_dir;
	unsigned int batching;
	unsigned int starved;
	int fifo_expire[2];
	int fifo_batch;
	int writes_starved;
	int front_merges;
	u32 async_depth;
	int prio_aging_expire;
	spinlock_t lock;
	spinlock_t zone_lock;
};

struct trace_event_raw_kyber_latency {
	struct trace_entry ent;
	dev_t dev;
	char domain[16];
	char type[8];
	u8 percentile;
	u8 numerator;
	u8 denominator;
	unsigned int samples;
	char __data[0];
};

struct trace_event_raw_kyber_adjust {
	struct trace_entry ent;
	dev_t dev;
	char domain[16];
	unsigned int depth;
	char __data[0];
};

struct trace_event_raw_kyber_throttled {
	struct trace_entry ent;
	dev_t dev;
	char domain[16];
	char __data[0];
};

struct trace_event_data_offsets_kyber_latency {};

struct trace_event_data_offsets_kyber_adjust {};

struct trace_event_data_offsets_kyber_throttled {};

typedef void (*btf_trace_kyber_latency)(void *, dev_t, const char *, const char *, unsigned int, unsigned int, unsigned int, unsigned int);

typedef void (*btf_trace_kyber_adjust)(void *, dev_t, const char *, unsigned int);

typedef void (*btf_trace_kyber_throttled)(void *, dev_t, const char *);

enum {
	KYBER_READ = 0,
	KYBER_WRITE = 1,
	KYBER_DISCARD = 2,
	KYBER_OTHER = 3,
	KYBER_NUM_DOMAINS = 4,
};

enum {
	KYBER_ASYNC_PERCENT = 75,
};

enum {
	KYBER_LATENCY_SHIFT = 2,
	KYBER_GOOD_BUCKETS = 4,
	KYBER_LATENCY_BUCKETS = 8,
};

enum {
	KYBER_TOTAL_LATENCY = 0,
	KYBER_IO_LATENCY = 1,
};

struct kyber_cpu_latency {
	atomic_t buckets[48];
};

struct kyber_ctx_queue {
	spinlock_t lock;
	struct list_head rq_list[4];
};

struct kyber_queue_data {
	struct request_queue *q;
	dev_t dev;
	struct sbitmap_queue domain_tokens[4];
	unsigned int async_depth;
	struct kyber_cpu_latency *cpu_latency;
	struct timer_list timer;
	unsigned int latency_buckets[48];
	long unsigned int latency_timeout[3];
	int domain_p99[3];
	u64 latency_targets[3];
};

struct kyber_hctx_data {
	spinlock_t lock;
	struct list_head rqs[4];
	unsigned int cur_domain;
	unsigned int batching;
	struct kyber_ctx_queue *kcqs;
	struct sbitmap kcq_map[4];
	struct sbq_wait domain_wait[4];
	struct sbq_wait_state *domain_ws[4];
	atomic_t wait_index[4];
};

struct flush_kcq_data {
	struct kyber_hctx_data *khd;
	unsigned int sched_domain;
	struct list_head *list;
};

struct irq_affinity {
	unsigned int pre_vectors;
	unsigned int post_vectors;
	unsigned int nr_sets;
	unsigned int set_size[4];
	void (*calc_sets)(struct irq_affinity *, unsigned int);
	void *priv;
};

struct virtio_device_id {
	__u32 device;
	__u32 vendor;
};

struct virtio_device;

struct virtqueue {
	struct list_head list;
	void (*callback)(struct virtqueue *);
	const char *name;
	struct virtio_device *vdev;
	unsigned int index;
	unsigned int num_free;
	void *priv;
};

struct vringh_config_ops;

struct virtio_config_ops;

struct virtio_device {
	int index;
	bool failed;
	bool config_enabled;
	bool config_change_pending;
	spinlock_t config_lock;
	spinlock_t vqs_list_lock;
	struct device dev;
	struct virtio_device_id id;
	const struct virtio_config_ops *config;
	const struct vringh_config_ops *vringh_config;
	struct list_head vqs;
	u64 features;
	void *priv;
};

typedef void vq_callback_t(struct virtqueue *);

struct virtio_shm_region;

struct virtio_config_ops {
	void (*get)(struct virtio_device *, unsigned int, void *, unsigned int);
	void (*set)(struct virtio_device *, unsigned int, const void *, unsigned int);
	u32 (*generation)(struct virtio_device *);
	u8 (*get_status)(struct virtio_device *);
	void (*set_status)(struct virtio_device *, u8);
	void (*reset)(struct virtio_device *);
	int (*find_vqs)(struct virtio_device *, unsigned int, struct virtqueue **, vq_callback_t **, const char * const *, const bool *, struct irq_affinity *);
	void (*del_vqs)(struct virtio_device *);
	u64 (*get_features)(struct virtio_device *);
	int (*finalize_features)(struct virtio_device *);
	const char * (*bus_name)(struct virtio_device *);
	int (*set_vq_affinity)(struct virtqueue *, const struct cpumask *);
	const struct cpumask * (*get_vq_affinity)(struct virtio_device *, int);
	bool (*get_shm_region)(struct virtio_device *, struct virtio_shm_region *, u8);
};

struct virtio_shm_region {
	u64 addr;
	u64 len;
};

typedef void (*swap_r_func_t)(void *, void *, int, const void *);

typedef int (*cmp_r_func_t)(const void *, const void *, const void *);

struct wrapper {
	cmp_func_t cmp;
	swap_func_t swap;
};

typedef long unsigned int cycles_t;

struct siprand_state {
	long unsigned int v0;
	long unsigned int v1;
	long unsigned int v2;
	long unsigned int v3;
};

struct show_busy_params {
	struct seq_file *m;
	struct blk_mq_hw_ctx *hctx;
};

typedef int __kernel_ptrdiff_t;

typedef __kernel_ptrdiff_t ptrdiff_t;

struct region {
	unsigned int start;
	unsigned int off;
	unsigned int group_len;
	unsigned int end;
	unsigned int nbits;
};

enum {
	REG_OP_ISFREE = 0,
	REG_OP_ALLOC = 1,
	REG_OP_RELEASE = 2,
};

struct sg_append_table {
	struct sg_table sgt;
	struct scatterlist *prv;
	unsigned int total_nents;
};

typedef struct scatterlist *sg_alloc_fn(unsigned int, gfp_t);

typedef void sg_free_fn(struct scatterlist *, unsigned int);

struct sg_page_iter {
	struct scatterlist *sg;
	unsigned int sg_pgoffset;
	unsigned int __nents;
	int __pg_advance;
};

struct sg_dma_page_iter {
	struct sg_page_iter base;
};

struct sg_mapping_iter {
	struct page *page;
	void *addr;
	size_t length;
	size_t consumed;
	struct sg_page_iter piter;
	unsigned int __offset;
	unsigned int __remaining;
	unsigned int __flags;
};

struct csum_state {
	__wsum csum;
	size_t off;
};

typedef s32 compat_ssize_t;

struct compat_iovec {
	compat_uptr_t iov_base;
	compat_size_t iov_len;
};

struct once_work {
	struct work_struct work;
	struct static_key_true *key;
	struct module *module;
};

struct rhltable {
	struct rhashtable ht;
};

struct rhashtable_walker {
	struct list_head list;
	struct bucket_table *tbl;
};

struct rhashtable_iter {
	struct rhashtable *ht;
	struct rhash_head *p;
	struct rhlist_head *list;
	struct rhashtable_walker walker;
	unsigned int slot;
	unsigned int skip;
	bool end_of_table;
};

union nested_table {
	union nested_table *table;
	struct rhash_lock_head *bucket;
};

struct genradix_iter {
	size_t offset;
	size_t pos;
};

struct genradix_node {
	union {
		struct genradix_node *children[2048];
		u8 data[8192];
	};
};

enum string_size_units {
	STRING_UNITS_10 = 0,
	STRING_UNITS_2 = 1,
};

struct strarray {
	char **array;
	size_t n;
};

struct reciprocal_value_adv {
	u32 m;
	u8 sh;
	u8 exp;
	bool is_wide_m;
};

enum blake2s_lengths {
	BLAKE2S_BLOCK_SIZE = 64,
	BLAKE2S_HASH_SIZE = 32,
	BLAKE2S_KEY_SIZE = 32,
	BLAKE2S_128_HASH_SIZE = 16,
	BLAKE2S_160_HASH_SIZE = 20,
	BLAKE2S_224_HASH_SIZE = 28,
	BLAKE2S_256_HASH_SIZE = 32,
};

struct blake2s_state {
	u32 h[8];
	u32 t[2];
	u32 f[2];
	u8 buf[64];
	unsigned int buflen;
	unsigned int outlen;
};

enum blake2s_iv {
	BLAKE2S_IV0 = 1779033703,
	BLAKE2S_IV1 = 3144134277,
	BLAKE2S_IV2 = 1013904242,
	BLAKE2S_IV3 = 2773480762,
	BLAKE2S_IV4 = 1359893119,
	BLAKE2S_IV5 = 2600822924,
	BLAKE2S_IV6 = 528734635,
	BLAKE2S_IV7 = 1541459225,
};

enum {
	PCI_STD_RESOURCES = 0,
	PCI_STD_RESOURCE_END = 5,
	PCI_ROM_RESOURCE = 6,
	PCI_BRIDGE_RESOURCES = 7,
	PCI_BRIDGE_RESOURCE_END = 10,
	PCI_NUM_RESOURCES = 11,
	DEVICE_COUNT_RESOURCE = 11,
};

typedef unsigned int pci_channel_state_t;

typedef unsigned int pcie_reset_state_t;

typedef short unsigned int pci_dev_flags_t;

typedef short unsigned int pci_bus_flags_t;

typedef unsigned int pci_ers_result_t;

enum devm_ioremap_type {
	DEVM_IOREMAP = 0,
	DEVM_IOREMAP_UC = 1,
	DEVM_IOREMAP_WC = 2,
	DEVM_IOREMAP_NP = 3,
};

struct arch_io_reserve_memtype_wc_devres {
	resource_size_t start;
	resource_size_t size;
};

typedef u8 uint8_t;

struct xxh32_state {
	uint32_t total_len_32;
	uint32_t large_len;
	uint32_t v1;
	uint32_t v2;
	uint32_t v3;
	uint32_t v4;
	uint32_t mem32[4];
	uint32_t memsize;
};

struct xxh64_state {
	uint64_t total_len;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
	uint64_t v4;
	uint64_t mem64[4];
	uint32_t memsize;
};

typedef unsigned char Byte;

typedef long unsigned int uLong;

struct internal_state;

struct z_stream_s {
	const Byte *next_in;
	uLong avail_in;
	uLong total_in;
	Byte *next_out;
	uLong avail_out;
	uLong total_out;
	char *msg;
	struct internal_state *state;
	void *workspace;
	int data_type;
	uLong adler;
	uLong reserved;
};

typedef struct z_stream_s z_stream;

typedef z_stream *z_streamp;

typedef struct {
	unsigned char op;
	unsigned char bits;
	short unsigned int val;
} code;

typedef enum {
	HEAD = 0,
	FLAGS = 1,
	TIME = 2,
	OS = 3,
	EXLEN = 4,
	EXTRA = 5,
	NAME = 6,
	COMMENT = 7,
	HCRC = 8,
	DICTID = 9,
	DICT = 10,
	TYPE = 11,
	TYPEDO = 12,
	STORED = 13,
	COPY = 14,
	TABLE = 15,
	LENLENS = 16,
	CODELENS = 17,
	LEN = 18,
	LENEXT = 19,
	DIST = 20,
	DISTEXT = 21,
	MATCH = 22,
	LIT = 23,
	CHECK = 24,
	LENGTH = 25,
	DONE = 26,
	BAD = 27,
	MEM = 28,
	SYNC = 29,
} inflate_mode;

struct inflate_state {
	inflate_mode mode;
	int last;
	int wrap;
	int havedict;
	int flags;
	unsigned int dmax;
	long unsigned int check;
	long unsigned int total;
	unsigned int wbits;
	unsigned int wsize;
	unsigned int whave;
	unsigned int write;
	unsigned char *window;
	long unsigned int hold;
	unsigned int bits;
	unsigned int length;
	unsigned int offset;
	unsigned int extra;
	const code *lencode;
	const code *distcode;
	unsigned int lenbits;
	unsigned int distbits;
	unsigned int ncode;
	unsigned int nlen;
	unsigned int ndist;
	unsigned int have;
	code *next;
	short unsigned int lens[320];
	short unsigned int work[288];
	code codes[2048];
};

union uu {
	short unsigned int us;
	unsigned char b[2];
};

typedef unsigned int uInt;

typedef enum {
	CODES = 0,
	LENS = 1,
	DISTS = 2,
} codetype;

struct inflate_workspace {
	struct inflate_state inflate_state;
	unsigned char working_window[32768];
};

struct internal_state {
	int dummy;
};

struct gen_pool_chunk {
	struct list_head next_chunk;
	atomic_long_t avail;
	phys_addr_t phys_addr;
	void *owner;
	long unsigned int start_addr;
	long unsigned int end_addr;
	long unsigned int bits[0];
};

struct genpool_data_align {
	int align;
};

struct genpool_data_fixed {
	long unsigned int offset;
};

typedef struct {
	const uint8_t *externalDict;
	size_t extDictSize;
	const uint8_t *prefixEnd;
	size_t prefixSize;
} LZ4_streamDecode_t_internal;

typedef union {
	long long unsigned int table[4];
	LZ4_streamDecode_t_internal internal_donotuse;
} LZ4_streamDecode_t;

typedef uint8_t BYTE;

typedef uint16_t U16;

typedef uint32_t U32;

typedef uintptr_t uptrval;

typedef enum {
	noDict = 0,
	withPrefix64k = 1,
	usingExtDict = 2,
} dict_directive;

typedef enum {
	endOnOutputSize = 0,
	endOnInputSize = 1,
} endCondition_directive;

typedef enum {
	decode_full_block = 0,
	partial_decode = 1,
} earlyEnd_directive;

typedef enum {
	ZSTD_error_no_error = 0,
	ZSTD_error_GENERIC = 1,
	ZSTD_error_prefix_unknown = 10,
	ZSTD_error_version_unsupported = 12,
	ZSTD_error_frameParameter_unsupported = 14,
	ZSTD_error_frameParameter_windowTooLarge = 16,
	ZSTD_error_corruption_detected = 20,
	ZSTD_error_checksum_wrong = 22,
	ZSTD_error_dictionary_corrupted = 30,
	ZSTD_error_dictionary_wrong = 32,
	ZSTD_error_dictionaryCreation_failed = 34,
	ZSTD_error_parameter_unsupported = 40,
	ZSTD_error_parameter_outOfBound = 42,
	ZSTD_error_tableLog_tooLarge = 44,
	ZSTD_error_maxSymbolValue_tooLarge = 46,
	ZSTD_error_maxSymbolValue_tooSmall = 48,
	ZSTD_error_stage_wrong = 60,
	ZSTD_error_init_missing = 62,
	ZSTD_error_memory_allocation = 64,
	ZSTD_error_workSpace_tooSmall = 66,
	ZSTD_error_dstSize_tooSmall = 70,
	ZSTD_error_srcSize_wrong = 72,
	ZSTD_error_dstBuffer_null = 74,
	ZSTD_error_frameIndex_tooLarge = 100,
	ZSTD_error_seekableIO = 102,
	ZSTD_error_dstBuffer_wrong = 104,
	ZSTD_error_srcBuffer_wrong = 105,
	ZSTD_error_maxCode = 120,
} ZSTD_ErrorCode;

struct ZSTD_DCtx_s;

typedef struct ZSTD_DCtx_s ZSTD_DCtx;

struct ZSTD_inBuffer_s {
	const void *src;
	size_t size;
	size_t pos;
};

typedef struct ZSTD_inBuffer_s ZSTD_inBuffer;

struct ZSTD_outBuffer_s {
	void *dst;
	size_t size;
	size_t pos;
};

typedef struct ZSTD_outBuffer_s ZSTD_outBuffer;

typedef ZSTD_DCtx ZSTD_DStream;

typedef void * (*ZSTD_allocFunction)(void *, size_t);

typedef void (*ZSTD_freeFunction)(void *, void *);

typedef struct {
	ZSTD_allocFunction customAlloc;
	ZSTD_freeFunction customFree;
	void *opaque;
} ZSTD_customMem;

typedef enum {
	ZSTD_frame = 0,
	ZSTD_skippableFrame = 1,
} ZSTD_frameType_e;

typedef struct {
	long long unsigned int frameContentSize;
	long long unsigned int windowSize;
	unsigned int blockSizeMax;
	ZSTD_frameType_e frameType;
	unsigned int headerSize;
	unsigned int dictID;
	unsigned int checksumFlag;
} ZSTD_frameHeader;

typedef ZSTD_ErrorCode zstd_error_code;

typedef ZSTD_DCtx zstd_dctx;

typedef ZSTD_inBuffer zstd_in_buffer;

typedef ZSTD_outBuffer zstd_out_buffer;

typedef ZSTD_DStream zstd_dstream;

typedef ZSTD_frameHeader zstd_frame_header;

typedef ZSTD_ErrorCode ERR_enum;

typedef s16 int16_t;

typedef int16_t S16;

typedef uint64_t U64;

typedef struct {
	size_t bitContainer;
	unsigned int bitsConsumed;
	const char *ptr;
	const char *start;
	const char *limitPtr;
} BIT_DStream_t;

typedef enum {
	BIT_DStream_unfinished = 0,
	BIT_DStream_endOfBuffer = 1,
	BIT_DStream_completed = 2,
	BIT_DStream_overflow = 3,
} BIT_DStream_status;

typedef unsigned int FSE_DTable;

typedef struct {
	size_t state;
	const void *table;
} FSE_DState_t;

typedef struct {
	U16 tableLog;
	U16 fastMode;
} FSE_DTableHeader;

typedef struct {
	short unsigned int newState;
	unsigned char symbol;
	unsigned char nbBits;
} FSE_decode_t;

typedef struct {
	short int ncount[256];
	FSE_DTable dtable[1];
} FSE_DecompressWksp;

typedef U32 HUF_DTable;

typedef struct {
	U16 nextState;
	BYTE nbAdditionalBits;
	BYTE nbBits;
	U32 baseValue;
} ZSTD_seqSymbol;

typedef struct {
	ZSTD_seqSymbol LLTable[513];
	ZSTD_seqSymbol OFTable[257];
	ZSTD_seqSymbol MLTable[513];
	HUF_DTable hufTable[4097];
	U32 rep[3];
	U32 workspace[157];
} ZSTD_entropyDTables_t;

typedef enum {
	bt_raw = 0,
	bt_rle = 1,
	bt_compressed = 2,
	bt_reserved = 3,
} blockType_e;

typedef enum {
	ZSTDds_getFrameHeaderSize = 0,
	ZSTDds_decodeFrameHeader = 1,
	ZSTDds_decodeBlockHeader = 2,
	ZSTDds_decompressBlock = 3,
	ZSTDds_decompressLastBlock = 4,
	ZSTDds_checkChecksum = 5,
	ZSTDds_decodeSkippableHeader = 6,
	ZSTDds_skipFrame = 7,
} ZSTD_dStage;

typedef enum {
	ZSTD_f_zstd1 = 0,
	ZSTD_f_zstd1_magicless = 1,
} ZSTD_format_e;

typedef enum {
	ZSTD_d_validateChecksum = 0,
	ZSTD_d_ignoreChecksum = 1,
} ZSTD_forceIgnoreChecksum_e;

typedef enum {
	ZSTD_use_indefinitely = 4294967295,
	ZSTD_dont_use = 0,
	ZSTD_use_once = 1,
} ZSTD_dictUses_e;

struct ZSTD_DDict_s;

typedef struct ZSTD_DDict_s ZSTD_DDict;

typedef struct {
	const ZSTD_DDict **ddictPtrTable;
	size_t ddictPtrTableSize;
	size_t ddictPtrCount;
} ZSTD_DDictHashSet;

typedef enum {
	ZSTD_rmd_refSingleDDict = 0,
	ZSTD_rmd_refMultipleDDicts = 1,
} ZSTD_refMultipleDDicts_e;

typedef enum {
	zdss_init = 0,
	zdss_loadHeader = 1,
	zdss_read = 2,
	zdss_load = 3,
	zdss_flush = 4,
} ZSTD_dStreamStage;

typedef enum {
	ZSTD_bm_buffered = 0,
	ZSTD_bm_stable = 1,
} ZSTD_bufferMode_e;

struct ZSTD_DCtx_s {
	const ZSTD_seqSymbol *LLTptr;
	const ZSTD_seqSymbol *MLTptr;
	const ZSTD_seqSymbol *OFTptr;
	const HUF_DTable *HUFptr;
	ZSTD_entropyDTables_t entropy;
	U32 workspace[640];
	const void *previousDstEnd;
	const void *prefixStart;
	const void *virtualStart;
	const void *dictEnd;
	size_t expected;
	ZSTD_frameHeader fParams;
	U64 processedCSize;
	U64 decodedSize;
	blockType_e bType;
	ZSTD_dStage stage;
	U32 litEntropy;
	U32 fseEntropy;
	struct xxh64_state xxhState;
	size_t headerSize;
	ZSTD_format_e format;
	ZSTD_forceIgnoreChecksum_e forceIgnoreChecksum;
	U32 validateChecksum;
	const BYTE *litPtr;
	ZSTD_customMem customMem;
	size_t litSize;
	size_t rleSize;
	size_t staticSize;
	int bmi2;
	ZSTD_DDict *ddictLocal;
	const ZSTD_DDict *ddict;
	U32 dictID;
	int ddictIsCold;
	ZSTD_dictUses_e dictUses;
	ZSTD_DDictHashSet *ddictSet;
	ZSTD_refMultipleDDicts_e refMultipleDDicts;
	ZSTD_dStreamStage streamStage;
	char *inBuff;
	size_t inBuffSize;
	size_t inPos;
	size_t maxWindowSize;
	char *outBuff;
	size_t outBuffSize;
	size_t outStart;
	size_t outEnd;
	size_t lhSize;
	void *legacyContext;
	U32 previousLegacyVersion;
	U32 legacyVersion;
	U32 hostageByte;
	int noForwardProgress;
	ZSTD_bufferMode_e outBufferMode;
	ZSTD_outBuffer expectedOutBuffer;
	BYTE litBuffer[131104];
	BYTE headerBuffer[18];
	size_t oversizedDuration;
};

typedef struct ZSTD_DCtx_s ZSTD_DCtx___2;

struct ZSTD_DDict_s {
	void *dictBuffer;
	const void *dictContent;
	size_t dictSize;
	ZSTD_entropyDTables_t entropy;
	U32 dictID;
	U32 entropyPresent;
	ZSTD_customMem cMem;
};

typedef enum {
	ZSTD_dct_auto = 0,
	ZSTD_dct_rawContent = 1,
	ZSTD_dct_fullDict = 2,
} ZSTD_dictContentType_e;

typedef enum {
	ZSTD_dlm_byCopy = 0,
	ZSTD_dlm_byRef = 1,
} ZSTD_dictLoadMethod_e;

typedef struct {
	BYTE maxTableLog;
	BYTE tableType;
	BYTE tableLog;
	BYTE reserved;
} DTableDesc;

typedef struct {
	BYTE byte;
	BYTE nbBits;
} HUF_DEltX1;

typedef struct {
	U32 rankVal[16];
	U32 rankStart[16];
	U32 statsWksp[218];
	BYTE symbols[256];
	BYTE huffWeight[256];
} HUF_ReadDTableX1_Workspace;

typedef struct {
	U16 sequence;
	BYTE nbBits;
	BYTE length;
} HUF_DEltX2;

typedef struct {
	BYTE symbol;
	BYTE weight;
} sortedSymbol_t;

typedef U32 rankValCol_t[13];

typedef struct {
	U32 rankVal[156];
	U32 rankStats[13];
	U32 rankStart0[14];
	sortedSymbol_t sortedSymbol[256];
	BYTE weightList[256];
	U32 calleeWksp[218];
} HUF_ReadDTableX2_Workspace;

typedef struct {
	U32 tableTime;
	U32 decode256Time;
} algo_time_t;

typedef struct {
	U32 f1c;
	U32 f1d;
	U32 f7b;
	U32 f7c;
} ZSTD_cpuid_t;

typedef struct {
	size_t error;
	int lowerBound;
	int upperBound;
} ZSTD_bounds;

typedef enum {
	ZSTD_reset_session_only = 1,
	ZSTD_reset_parameters = 2,
	ZSTD_reset_session_and_parameters = 3,
} ZSTD_ResetDirective;

typedef enum {
	ZSTD_d_windowLogMax = 100,
	ZSTD_d_experimentalParam1 = 1000,
	ZSTD_d_experimentalParam2 = 1001,
	ZSTD_d_experimentalParam3 = 1002,
	ZSTD_d_experimentalParam4 = 1003,
} ZSTD_dParameter;

typedef ZSTD_DCtx___2 ZSTD_DStream___2;

typedef enum {
	ZSTDnit_frameHeader = 0,
	ZSTDnit_blockHeader = 1,
	ZSTDnit_block = 2,
	ZSTDnit_lastBlock = 3,
	ZSTDnit_checksum = 4,
	ZSTDnit_skippableFrame = 5,
} ZSTD_nextInputType_e;

typedef struct {
	size_t compressedSize;
	long long unsigned int decompressedBound;
} ZSTD_frameSizeInfo;

typedef struct {
	blockType_e blockType;
	U32 lastBlock;
	U32 origSize;
} blockProperties_t;

typedef enum {
	set_basic = 0,
	set_rle = 1,
	set_compressed = 2,
	set_repeat = 3,
} symbolEncodingType_e;

typedef enum {
	ZSTD_no_overlap = 0,
	ZSTD_overlap_src_before_dst = 1,
} ZSTD_overlap_e;

typedef struct {
	U32 fastMode;
	U32 tableLog;
} ZSTD_seqSymbol_header;

typedef struct {
	size_t litLength;
	size_t matchLength;
	size_t offset;
	const BYTE *match;
} seq_t;

typedef struct {
	size_t state;
	const ZSTD_seqSymbol *table;
} ZSTD_fseState;

typedef struct {
	BIT_DStream_t DStream;
	ZSTD_fseState stateLL;
	ZSTD_fseState stateOffb;
	ZSTD_fseState stateML;
	size_t prevOffset[3];
	const BYTE *prefixStart;
	const BYTE *dictEnd;
	size_t pos;
} seqState_t;

typedef enum {
	ZSTD_lo_isRegularOffset = 0,
	ZSTD_lo_isLongOffset = 1,
} ZSTD_longOffset_e;

typedef enum {
	ZSTD_p_noPrefetch = 0,
	ZSTD_p_prefetch = 1,
} ZSTD_prefetch_e;

enum xz_mode {
	XZ_SINGLE = 0,
	XZ_PREALLOC = 1,
	XZ_DYNALLOC = 2,
};

enum xz_ret {
	XZ_OK = 0,
	XZ_STREAM_END = 1,
	XZ_UNSUPPORTED_CHECK = 2,
	XZ_MEM_ERROR = 3,
	XZ_MEMLIMIT_ERROR = 4,
	XZ_FORMAT_ERROR = 5,
	XZ_OPTIONS_ERROR = 6,
	XZ_DATA_ERROR = 7,
	XZ_BUF_ERROR = 8,
};

struct xz_buf {
	const uint8_t *in;
	size_t in_pos;
	size_t in_size;
	uint8_t *out;
	size_t out_pos;
	size_t out_size;
};

struct xz_dec;

typedef uint64_t vli_type;

enum xz_check {
	XZ_CHECK_NONE = 0,
	XZ_CHECK_CRC32 = 1,
	XZ_CHECK_CRC64 = 4,
	XZ_CHECK_SHA256 = 10,
};

struct xz_dec_hash {
	vli_type unpadded;
	vli_type uncompressed;
	uint32_t crc32;
};

struct xz_dec_lzma2;

struct xz_dec_bcj;

struct xz_dec {
	enum {
		SEQ_STREAM_HEADER = 0,
		SEQ_BLOCK_START = 1,
		SEQ_BLOCK_HEADER = 2,
		SEQ_BLOCK_UNCOMPRESS = 3,
		SEQ_BLOCK_PADDING = 4,
		SEQ_BLOCK_CHECK = 5,
		SEQ_INDEX = 6,
		SEQ_INDEX_PADDING = 7,
		SEQ_INDEX_CRC32 = 8,
		SEQ_STREAM_FOOTER = 9,
	} sequence;
	uint32_t pos;
	vli_type vli;
	size_t in_start;
	size_t out_start;
	uint32_t crc32;
	enum xz_check check_type;
	enum xz_mode mode;
	bool allow_buf_error;
	struct {
		vli_type compressed;
		vli_type uncompressed;
		uint32_t size;
	} block_header;
	struct {
		vli_type compressed;
		vli_type uncompressed;
		vli_type count;
		struct xz_dec_hash hash;
	} block;
	struct {
		enum {
			SEQ_INDEX_COUNT = 0,
			SEQ_INDEX_UNPADDED = 1,
			SEQ_INDEX_UNCOMPRESSED = 2,
		} sequence;
		vli_type size;
		vli_type count;
		struct xz_dec_hash hash;
	} index;
	struct {
		size_t pos;
		size_t size;
		uint8_t buf[1024];
	} temp;
	struct xz_dec_lzma2 *lzma2;
	struct xz_dec_bcj *bcj;
	bool bcj_active;
};

struct xz_dec_bcj {
	enum {
		BCJ_X86 = 4,
		BCJ_POWERPC = 5,
		BCJ_IA64 = 6,
		BCJ_ARM = 7,
		BCJ_ARMTHUMB = 8,
		BCJ_SPARC = 9,
	} type;
	enum xz_ret ret;
	bool single_call;
	uint32_t pos;
	uint32_t x86_prev_mask;
	uint8_t *out;
	size_t out_pos;
	size_t out_size;
	struct {
		size_t filtered;
		size_t size;
		uint8_t buf[16];
	} temp;
};

enum lzma_state {
	STATE_LIT_LIT = 0,
	STATE_MATCH_LIT_LIT = 1,
	STATE_REP_LIT_LIT = 2,
	STATE_SHORTREP_LIT_LIT = 3,
	STATE_MATCH_LIT = 4,
	STATE_REP_LIT = 5,
	STATE_SHORTREP_LIT = 6,
	STATE_LIT_MATCH = 7,
	STATE_LIT_LONGREP = 8,
	STATE_LIT_SHORTREP = 9,
	STATE_NONLIT_MATCH = 10,
	STATE_NONLIT_REP = 11,
};

struct dictionary {
	uint8_t *buf;
	size_t start;
	size_t pos;
	size_t full;
	size_t limit;
	size_t end;
	uint32_t size;
	uint32_t size_max;
	uint32_t allocated;
	enum xz_mode mode;
};

struct rc_dec {
	uint32_t range;
	uint32_t code;
	uint32_t init_bytes_left;
	const uint8_t *in;
	size_t in_pos;
	size_t in_limit;
};

struct lzma_len_dec {
	uint16_t choice;
	uint16_t choice2;
	uint16_t low[128];
	uint16_t mid[128];
	uint16_t high[256];
};

struct lzma_dec {
	uint32_t rep0;
	uint32_t rep1;
	uint32_t rep2;
	uint32_t rep3;
	enum lzma_state state;
	uint32_t len;
	uint32_t lc;
	uint32_t literal_pos_mask;
	uint32_t pos_mask;
	uint16_t is_match[192];
	uint16_t is_rep[12];
	uint16_t is_rep0[12];
	uint16_t is_rep1[12];
	uint16_t is_rep2[12];
	uint16_t is_rep0_long[192];
	uint16_t dist_slot[256];
	uint16_t dist_special[114];
	uint16_t dist_align[16];
	struct lzma_len_dec match_len_dec;
	struct lzma_len_dec rep_len_dec;
	uint16_t literal[12288];
};

enum lzma2_seq {
	SEQ_CONTROL = 0,
	SEQ_UNCOMPRESSED_1 = 1,
	SEQ_UNCOMPRESSED_2 = 2,
	SEQ_COMPRESSED_0 = 3,
	SEQ_COMPRESSED_1 = 4,
	SEQ_PROPERTIES = 5,
	SEQ_LZMA_PREPARE = 6,
	SEQ_LZMA_RUN = 7,
	SEQ_COPY = 8,
};

struct lzma2_dec {
	enum lzma2_seq sequence;
	enum lzma2_seq next_sequence;
	uint32_t uncompressed;
	uint32_t compressed;
	bool need_dict_reset;
	bool need_props;
};

struct xz_dec_lzma2 {
	struct rc_dec rc;
	struct dictionary dict;
	struct lzma2_dec lzma2;
	struct lzma_dec lzma;
	struct {
		uint32_t size;
		uint8_t buf[63];
	} temp;
};

typedef __u16 __sum16;

struct nla_bitfield32 {
	__u32 value;
	__u32 selector;
};

enum {
	NLA_UNSPEC = 0,
	NLA_U8 = 1,
	NLA_U16 = 2,
	NLA_U32 = 3,
	NLA_U64 = 4,
	NLA_STRING = 5,
	NLA_FLAG = 6,
	NLA_MSECS = 7,
	NLA_NESTED = 8,
	NLA_NESTED_ARRAY = 9,
	NLA_NUL_STRING = 10,
	NLA_BINARY = 11,
	NLA_S8 = 12,
	NLA_S16 = 13,
	NLA_S32 = 14,
	NLA_S64 = 15,
	NLA_BITFIELD32 = 16,
	NLA_REJECT = 17,
	__NLA_TYPE_MAX = 18,
};

enum nla_policy_validation {
	NLA_VALIDATE_NONE = 0,
	NLA_VALIDATE_RANGE = 1,
	NLA_VALIDATE_RANGE_WARN_TOO_LONG = 2,
	NLA_VALIDATE_MIN = 3,
	NLA_VALIDATE_MAX = 4,
	NLA_VALIDATE_MASK = 5,
	NLA_VALIDATE_RANGE_PTR = 6,
	NLA_VALIDATE_FUNCTION = 7,
};

enum netlink_validation {
	NL_VALIDATE_LIBERAL = 0,
	NL_VALIDATE_TRAILING = 1,
	NL_VALIDATE_MAXTYPE = 2,
	NL_VALIDATE_UNSPEC = 4,
	NL_VALIDATE_STRICT_ATTRS = 8,
	NL_VALIDATE_NESTED = 16,
};

struct word_at_a_time {
	const long unsigned int one_bits;
	const long unsigned int high_bits;
};

struct sg_pool {
	size_t size;
	char *name;
	struct kmem_cache *slab;
	mempool_t *pool;
};

struct compress_format {
	unsigned char magic[2];
	const char *name;
	decompress_fn decompressor;
};

typedef __u64 Elf64_Addr;

typedef __u16 Elf64_Half;

typedef __u64 Elf64_Off;

typedef __u32 Elf64_Word;

typedef __u64 Elf64_Xword;

struct elf64_hdr {
	unsigned char e_ident[16];
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;
	Elf64_Off e_phoff;
	Elf64_Off e_shoff;
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
};

typedef struct elf64_hdr Elf64_Ehdr;

typedef struct elf32_phdr Elf32_Phdr;

struct elf64_phdr {
	Elf64_Word p_type;
	Elf64_Word p_flags;
	Elf64_Off p_offset;
	Elf64_Addr p_vaddr;
	Elf64_Addr p_paddr;
	Elf64_Xword p_filesz;
	Elf64_Xword p_memsz;
	Elf64_Xword p_align;
};

typedef struct elf64_phdr Elf64_Phdr;

typedef struct elf32_note Elf32_Nhdr;

struct group_data {
	int limit[21];
	int base[20];
	int permute[258];
	int minLen;
	int maxLen;
};

struct bunzip_data {
	int writeCopies;
	int writePos;
	int writeRunCountdown;
	int writeCount;
	int writeCurrent;
	long int (*fill)(void *, long unsigned int);
	long int inbufCount;
	long int inbufPos;
	unsigned char *inbuf;
	unsigned int inbufBitCount;
	unsigned int inbufBits;
	unsigned int crc32Table[256];
	unsigned int headerCRC;
	unsigned int totalCRC;
	unsigned int writeCRC;
	unsigned int *dbuf;
	unsigned int dbufSize;
	unsigned char selectors[32768];
	struct group_data groups[6];
	int io_error;
	int byteCount[256];
	unsigned char symToByte[256];
	unsigned char mtfSymbol[256];
};

struct rc {
	long int (*fill)(void *, long unsigned int);
	uint8_t *ptr;
	uint8_t *buffer;
	uint8_t *buffer_end;
	long int buffer_size;
	uint32_t code;
	uint32_t range;
	uint32_t bound;
	void (*error)(char *);
};

struct lzma_header {
	uint8_t pos;
	uint32_t dict_size;
	uint64_t dst_size;
} __attribute__((packed));

struct writer {
	uint8_t *buffer;
	uint8_t previous_byte;
	size_t buffer_pos;
	int bufsize;
	size_t global_pos;
	long int (*flush)(void *, long unsigned int);
	struct lzma_header *header;
};

struct cstate {
	int state;
	uint32_t rep0;
	uint32_t rep1;
	uint32_t rep2;
	uint32_t rep3;
};

struct cpio_data {
	void *data;
	size_t size;
	char name[18];
};

enum cpio_fields {
	C_MAGIC = 0,
	C_INO = 1,
	C_MODE = 2,
	C_UID = 3,
	C_GID = 4,
	C_NLINK = 5,
	C_MTIME = 6,
	C_FILESIZE = 7,
	C_MAJ = 8,
	C_MIN = 9,
	C_RMAJ = 10,
	C_RMIN = 11,
	C_NAMESIZE = 12,
	C_CHKSUM = 13,
	C_NFIELDS = 14,
};

typedef __be32 fdt32_t;

struct fdt_header {
	fdt32_t magic;
	fdt32_t totalsize;
	fdt32_t off_dt_struct;
	fdt32_t off_dt_strings;
	fdt32_t off_mem_rsvmap;
	fdt32_t version;
	fdt32_t last_comp_version;
	fdt32_t boot_cpuid_phys;
	fdt32_t size_dt_strings;
	fdt32_t size_dt_struct;
};

enum {
	ASSUME_PERFECT = 255,
	ASSUME_VALID_DTB = 1,
	ASSUME_VALID_INPUT = 2,
	ASSUME_LATEST = 4,
	ASSUME_NO_ROLLBACK = 8,
	ASSUME_LIBFDT_ORDER = 16,
	ASSUME_LIBFDT_FLAWLESS = 32,
};

typedef __be64 fdt64_t;

struct fdt_reserve_entry {
	fdt64_t address;
	fdt64_t size;
};

struct fdt_node_header {
	fdt32_t tag;
	char name[0];
};

struct fdt_property {
	fdt32_t tag;
	fdt32_t len;
	fdt32_t nameoff;
	char data[0];
};

struct fdt_errtabent {
	const char *str;
};

struct fprop_local_single {
	long unsigned int events;
	unsigned int period;
	raw_spinlock_t lock;
};

struct radix_tree_iter {
	long unsigned int index;
	long unsigned int next_index;
	long unsigned int tags;
	struct xa_node *node;
};

enum {
	RADIX_TREE_ITER_TAG_MASK = 15,
	RADIX_TREE_ITER_TAGGED = 16,
	RADIX_TREE_ITER_CONTIG = 32,
};

struct ida_bitmap {
	long unsigned int bitmap[32];
};

struct klist_waiter {
	struct list_head list;
	struct klist_node *node;
	struct task_struct *process;
	int woken;
};

enum {
	LOGIC_PIO_INDIRECT = 0,
	LOGIC_PIO_CPU_MMIO = 1,
};

struct logic_pio_host_ops;

struct logic_pio_hwaddr {
	struct list_head list;
	struct fwnode_handle *fwnode;
	resource_size_t hw_start;
	resource_size_t io_start;
	resource_size_t size;
	long unsigned int flags;
	void *hostdata;
	const struct logic_pio_host_ops *ops;
};

struct logic_pio_host_ops {
	u32 (*in)(void *, long unsigned int, size_t);
	void (*out)(void *, long unsigned int, u32, size_t);
	u32 (*ins)(void *, long unsigned int, void *, size_t, unsigned int);
	void (*outs)(void *, long unsigned int, const void *, size_t, unsigned int);
};

struct scm_creds {
	u32 pid;
	kuid_t uid;
	kgid_t gid;
};

struct netlink_skb_parms {
	struct scm_creds creds;
	__u32 portid;
	__u32 dst_group;
	__u32 flags;
	struct sock *sk;
	bool nsid_is_set;
	int nsid;
};

struct netlink_kernel_cfg {
	unsigned int groups;
	unsigned int flags;
	void (*input)(struct sk_buff *);
	struct mutex *cb_mutex;
	int (*bind)(struct net *, int);
	void (*unbind)(struct net *, int);
	bool (*compare)(struct net *, struct sock *);
};

struct uevent_sock {
	struct list_head list;
	struct sock *sk;
};

typedef struct {
	long unsigned int key[2];
} hsiphash_key_t;

struct minmax_sample {
	u32 t;
	u32 v;
};

struct minmax {
	struct minmax_sample s[3];
};

struct of_dev_auxdata {
	char *compatible;
	resource_size_t phys_addr;
	char *name;
	void *platform_data;
};

struct clk_core;

struct clk {
	struct clk_core *core;
	struct device *dev;
	const char *dev_id;
	const char *con_id;
	long unsigned int min_rate;
	long unsigned int max_rate;
	unsigned int exclusive_count;
	struct hlist_node clks_node;
};

enum format_type {
	FORMAT_TYPE_NONE = 0,
	FORMAT_TYPE_WIDTH = 1,
	FORMAT_TYPE_PRECISION = 2,
	FORMAT_TYPE_CHAR = 3,
	FORMAT_TYPE_STR = 4,
	FORMAT_TYPE_PTR = 5,
	FORMAT_TYPE_PERCENT_CHAR = 6,
	FORMAT_TYPE_INVALID = 7,
	FORMAT_TYPE_LONG_LONG = 8,
	FORMAT_TYPE_ULONG = 9,
	FORMAT_TYPE_LONG = 10,
	FORMAT_TYPE_UBYTE = 11,
	FORMAT_TYPE_BYTE = 12,
	FORMAT_TYPE_USHORT = 13,
	FORMAT_TYPE_SHORT = 14,
	FORMAT_TYPE_UINT = 15,
	FORMAT_TYPE_INT = 16,
	FORMAT_TYPE_SIZE_T = 17,
	FORMAT_TYPE_PTRDIFF = 18,
};

struct printf_spec {
	unsigned int type: 8;
	int field_width: 24;
	unsigned int flags: 8;
	unsigned int base: 8;
	int precision: 16;
};

struct page_flags_fields {
	int width;
	int shift;
	int mask;
	const struct printf_spec *spec;
	const char *name;
};

struct clk_bulk_data {
	const char *id;
	struct clk *clk;
};

struct clk_bulk_devres {
	struct clk_bulk_data *clks;
	int num_clks;
};

enum con_scroll {
	SM_UP = 0,
	SM_DOWN = 1,
};

enum vc_intensity {
	VCI_HALF_BRIGHT = 0,
	VCI_NORMAL = 1,
	VCI_BOLD = 2,
	VCI_MASK = 3,
};

struct vc_data;

struct console_font;

struct consw {
	struct module *owner;
	const char * (*con_startup)();
	void (*con_init)(struct vc_data *, int);
	void (*con_deinit)(struct vc_data *);
	void (*con_clear)(struct vc_data *, int, int, int, int);
	void (*con_putc)(struct vc_data *, int, int, int);
	void (*con_putcs)(struct vc_data *, const short unsigned int *, int, int, int);
	void (*con_cursor)(struct vc_data *, int);
	bool (*con_scroll)(struct vc_data *, unsigned int, unsigned int, enum con_scroll, unsigned int);
	int (*con_switch)(struct vc_data *);
	int (*con_blank)(struct vc_data *, int, int);
	int (*con_font_set)(struct vc_data *, struct console_font *, unsigned int);
	int (*con_font_get)(struct vc_data *, struct console_font *);
	int (*con_font_default)(struct vc_data *, struct console_font *, char *);
	int (*con_resize)(struct vc_data *, unsigned int, unsigned int, unsigned int);
	void (*con_set_palette)(struct vc_data *, const unsigned char *);
	void (*con_scrolldelta)(struct vc_data *, int);
	int (*con_set_origin)(struct vc_data *);
	void (*con_save_screen)(struct vc_data *);
	u8 (*con_build_attr)(struct vc_data *, u8, enum vc_intensity, bool, bool, bool, bool);
	void (*con_invert_region)(struct vc_data *, u16 *, int);
	u16 * (*con_screen_pos)(const struct vc_data *, int);
	long unsigned int (*con_getxy)(struct vc_data *, long unsigned int, int *, int *);
	void (*con_flush_scrollback)(struct vc_data *);
	int (*con_debug_enter)(struct vc_data *);
	int (*con_debug_leave)(struct vc_data *);
};

struct vc_state {
	unsigned int x;
	unsigned int y;
	unsigned char color;
	unsigned char Gx_charset[2];
	unsigned int charset: 1;
	enum vc_intensity intensity;
	bool italic;
	bool underline;
	bool blink;
	bool reverse;
};

struct console_font {
	unsigned int width;
	unsigned int height;
	unsigned int charcount;
	unsigned char *data;
};

struct vt_mode {
	char mode;
	char waitv;
	short int relsig;
	short int acqsig;
	short int frsig;
};

struct uni_pagedir;

struct uni_screen;

struct vc_data {
	struct tty_port port;
	struct vc_state state;
	struct vc_state saved_state;
	short unsigned int vc_num;
	unsigned int vc_cols;
	unsigned int vc_rows;
	unsigned int vc_size_row;
	unsigned int vc_scan_lines;
	unsigned int vc_cell_height;
	long unsigned int vc_origin;
	long unsigned int vc_scr_end;
	long unsigned int vc_visible_origin;
	unsigned int vc_top;
	unsigned int vc_bottom;
	const struct consw *vc_sw;
	short unsigned int *vc_screenbuf;
	unsigned int vc_screenbuf_size;
	unsigned char vc_mode;
	unsigned char vc_attr;
	unsigned char vc_def_color;
	unsigned char vc_ulcolor;
	unsigned char vc_itcolor;
	unsigned char vc_halfcolor;
	unsigned int vc_cursor_type;
	short unsigned int vc_complement_mask;
	short unsigned int vc_s_complement_mask;
	long unsigned int vc_pos;
	short unsigned int vc_hi_font_mask;
	struct console_font vc_font;
	short unsigned int vc_video_erase_char;
	unsigned int vc_state;
	unsigned int vc_npar;
	unsigned int vc_par[16];
	struct vt_mode vt_mode;
	struct pid *vt_pid;
	int vt_newvt;
	wait_queue_head_t paste_wait;
	unsigned int vc_disp_ctrl: 1;
	unsigned int vc_toggle_meta: 1;
	unsigned int vc_decscnm: 1;
	unsigned int vc_decom: 1;
	unsigned int vc_decawm: 1;
	unsigned int vc_deccm: 1;
	unsigned int vc_decim: 1;
	unsigned int vc_priv: 3;
	unsigned int vc_need_wrap: 1;
	unsigned int vc_can_do_color: 1;
	unsigned int vc_report_mouse: 2;
	unsigned char vc_utf: 1;
	unsigned char vc_utf_count;
	int vc_utf_char;
	long unsigned int vc_tab_stop[8];
	unsigned char vc_palette[48];
	short unsigned int *vc_translate;
	unsigned int vc_resize_user;
	unsigned int vc_bell_pitch;
	unsigned int vc_bell_duration;
	short unsigned int vc_cur_blink_ms;
	struct vc_data **vc_display_fg;
	struct uni_pagedir *vc_uni_pagedir;
	struct uni_pagedir **vc_uni_pagedir_loc;
	struct uni_screen *vc_uni_screen;
};

struct clk_hw;

struct clk_lookup {
	struct list_head node;
	const char *dev_id;
	const char *con_id;
	struct clk *clk;
	struct clk_hw *clk_hw;
};

struct clk_init_data;

struct clk_hw {
	struct clk_core *core;
	struct clk *clk;
	const struct clk_init_data *init;
};

struct clk_rate_request {
	long unsigned int rate;
	long unsigned int min_rate;
	long unsigned int max_rate;
	long unsigned int best_parent_rate;
	struct clk_hw *best_parent_hw;
};

struct clk_duty {
	unsigned int num;
	unsigned int den;
};

struct clk_ops {
	int (*prepare)(struct clk_hw *);
	void (*unprepare)(struct clk_hw *);
	int (*is_prepared)(struct clk_hw *);
	void (*unprepare_unused)(struct clk_hw *);
	int (*enable)(struct clk_hw *);
	void (*disable)(struct clk_hw *);
	int (*is_enabled)(struct clk_hw *);
	void (*disable_unused)(struct clk_hw *);
	int (*save_context)(struct clk_hw *);
	void (*restore_context)(struct clk_hw *);
	long unsigned int (*recalc_rate)(struct clk_hw *, long unsigned int);
	long int (*round_rate)(struct clk_hw *, long unsigned int, long unsigned int *);
	int (*determine_rate)(struct clk_hw *, struct clk_rate_request *);
	int (*set_parent)(struct clk_hw *, u8);
	u8 (*get_parent)(struct clk_hw *);
	int (*set_rate)(struct clk_hw *, long unsigned int, long unsigned int);
	int (*set_rate_and_parent)(struct clk_hw *, long unsigned int, long unsigned int, u8);
	long unsigned int (*recalc_accuracy)(struct clk_hw *, long unsigned int);
	int (*get_phase)(struct clk_hw *);
	int (*set_phase)(struct clk_hw *, int);
	int (*get_duty_cycle)(struct clk_hw *, struct clk_duty *);
	int (*set_duty_cycle)(struct clk_hw *, struct clk_duty *);
	int (*init)(struct clk_hw *);
	void (*terminate)(struct clk_hw *);
	void (*debug_init)(struct clk_hw *, struct dentry *);
};

struct clk_parent_data {
	const struct clk_hw *hw;
	const char *fw_name;
	const char *name;
	int index;
};

struct clk_init_data {
	const char *name;
	const struct clk_ops *ops;
	const char * const *parent_names;
	const struct clk_parent_data *parent_data;
	const struct clk_hw **parent_hws;
	u8 num_parents;
	long unsigned int flags;
};

struct clk_lookup_alloc {
	struct clk_lookup cl;
	char dev_id[20];
	char con_id[16];
};

struct clk_div_table {
	unsigned int val;
	unsigned int div;
};

struct clk_divider {
	struct clk_hw hw;
	void *reg;
	u8 shift;
	u8 width;
	u8 flags;
	const struct clk_div_table *table;
	spinlock_t *lock;
};

typedef void (*of_init_fn_1)(struct device_node *);

struct clk_fixed_factor {
	struct clk_hw hw;
	unsigned int mult;
	unsigned int div;
};

struct clk_notifier {
	struct clk *clk;
	struct srcu_notifier_head notifier_head;
	struct list_head node;
};

struct clk_notifier_data {
	struct clk *clk;
	long unsigned int old_rate;
	long unsigned int new_rate;
};

struct clk_parent_map;

struct clk_core {
	const char *name;
	const struct clk_ops *ops;
	struct clk_hw *hw;
	struct module *owner;
	struct device *dev;
	struct device_node *of_node;
	struct clk_core *parent;
	struct clk_parent_map *parents;
	u8 num_parents;
	u8 new_parent_index;
	long unsigned int rate;
	long unsigned int req_rate;
	long unsigned int new_rate;
	struct clk_core *new_parent;
	struct clk_core *new_child;
	long unsigned int flags;
	bool orphan;
	bool rpm_enabled;
	unsigned int enable_count;
	unsigned int prepare_count;
	unsigned int protect_count;
	long unsigned int min_rate;
	long unsigned int max_rate;
	long unsigned int accuracy;
	int phase;
	struct clk_duty duty;
	struct hlist_head children;
	struct hlist_node child_node;
	struct hlist_head clks;
	unsigned int notifier_count;
	struct dentry *dentry;
	struct hlist_node debug_node;
	struct kref ref;
};

struct clk_onecell_data {
	struct clk **clks;
	unsigned int clk_num;
};

struct clk_hw_onecell_data {
	unsigned int num;
	struct clk_hw *hws[0];
};

struct clk_parent_map {
	const struct clk_hw *hw;
	struct clk_core *core;
	const char *fw_name;
	const char *name;
	int index;
};

struct trace_event_raw_clk {
	struct trace_entry ent;
	u32 __data_loc_name;
	char __data[0];
};

struct trace_event_raw_clk_rate {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int rate;
	char __data[0];
};

struct trace_event_raw_clk_rate_range {
	struct trace_entry ent;
	u32 __data_loc_name;
	long unsigned int min;
	long unsigned int max;
	char __data[0];
};

struct trace_event_raw_clk_parent {
	struct trace_entry ent;
	u32 __data_loc_name;
	u32 __data_loc_pname;
	char __data[0];
};

struct trace_event_raw_clk_phase {
	struct trace_entry ent;
	u32 __data_loc_name;
	int phase;
	char __data[0];
};

struct trace_event_raw_clk_duty_cycle {
	struct trace_entry ent;
	u32 __data_loc_name;
	unsigned int num;
	unsigned int den;
	char __data[0];
};

struct trace_event_data_offsets_clk {
	u32 name;
};

struct trace_event_data_offsets_clk_rate {
	u32 name;
};

struct trace_event_data_offsets_clk_rate_range {
	u32 name;
};

struct trace_event_data_offsets_clk_parent {
	u32 name;
	u32 pname;
};

struct trace_event_data_offsets_clk_phase {
	u32 name;
};

struct trace_event_data_offsets_clk_duty_cycle {
	u32 name;
};

typedef void (*btf_trace_clk_enable)(void *, struct clk_core *);

typedef void (*btf_trace_clk_enable_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_disable)(void *, struct clk_core *);

typedef void (*btf_trace_clk_disable_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_prepare)(void *, struct clk_core *);

typedef void (*btf_trace_clk_prepare_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_unprepare)(void *, struct clk_core *);

typedef void (*btf_trace_clk_unprepare_complete)(void *, struct clk_core *);

typedef void (*btf_trace_clk_set_rate)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_rate_complete)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_min_rate)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_max_rate)(void *, struct clk_core *, long unsigned int);

typedef void (*btf_trace_clk_set_rate_range)(void *, struct clk_core *, long unsigned int, long unsigned int);

typedef void (*btf_trace_clk_set_parent)(void *, struct clk_core *, struct clk_core *);

typedef void (*btf_trace_clk_set_parent_complete)(void *, struct clk_core *, struct clk_core *);

typedef void (*btf_trace_clk_set_phase)(void *, struct clk_core *, int);

typedef void (*btf_trace_clk_set_phase_complete)(void *, struct clk_core *, int);

typedef void (*btf_trace_clk_set_duty_cycle)(void *, struct clk_core *, struct clk_duty *);

typedef void (*btf_trace_clk_set_duty_cycle_complete)(void *, struct clk_core *, struct clk_duty *);

struct clk_notifier_devres {
	struct clk *clk;
	struct notifier_block *nb;
};

struct of_clk_provider {
	struct list_head link;
	struct device_node *node;
	struct clk * (*get)(struct of_phandle_args *, void *);
	struct clk_hw * (*get_hw)(struct of_phandle_args *, void *);
	void *data;
};

struct clock_provider {
	void (*clk_init_cb)(struct device_node *);
	struct device_node *np;
	struct list_head node;
};

struct clk_fixed_rate {
	struct clk_hw hw;
	long unsigned int fixed_rate;
	long unsigned int fixed_accuracy;
	long unsigned int flags;
};

struct clk_multiplier {
	struct clk_hw hw;
	void *reg;
	u8 shift;
	u8 width;
	u8 flags;
	spinlock_t *lock;
};

struct clk_gate {
	struct clk_hw hw;
	void *reg;
	u8 bit_idx;
	u8 flags;
	spinlock_t *lock;
};

struct clk_mux {
	struct clk_hw hw;
	void *reg;
	const u32 *table;
	u32 mask;
	u8 shift;
	u8 flags;
	spinlock_t *lock;
};

struct clk_composite {
	struct clk_hw hw;
	struct clk_ops ops;
	struct clk_hw *mux_hw;
	struct clk_hw *rate_hw;
	struct clk_hw *gate_hw;
	const struct clk_ops *mux_ops;
	const struct clk_ops *rate_ops;
	const struct clk_ops *gate_ops;
};

struct clk_fractional_divider {
	struct clk_hw hw;
	void *reg;
	u8 mshift;
	u8 mwidth;
	u32 mmask;
	u8 nshift;
	u8 nwidth;
	u32 nmask;
	u8 flags;
	void (*approximation)(struct clk_hw *, long unsigned int, long unsigned int *, long unsigned int *, long unsigned int *);
	spinlock_t *lock;
};

struct gpio_desc;

enum gpiod_flags {
	GPIOD_ASIS = 0,
	GPIOD_IN = 1,
	GPIOD_OUT_LOW = 3,
	GPIOD_OUT_HIGH = 7,
	GPIOD_OUT_LOW_OPEN_DRAIN = 11,
	GPIOD_OUT_HIGH_OPEN_DRAIN = 15,
};

struct clk_gpio {
	struct clk_hw hw;
	struct gpio_desc *gpiod;
};

struct virtio_driver {
	struct device_driver driver;
	const struct virtio_device_id *id_table;
	const unsigned int *feature_table;
	unsigned int feature_table_size;
	const unsigned int *feature_table_legacy;
	unsigned int feature_table_size_legacy;
	int (*validate)(struct virtio_device *);
	int (*probe)(struct virtio_device *);
	void (*scan)(struct virtio_device *);
	void (*remove)(struct virtio_device *);
	void (*config_changed)(struct virtio_device *);
};

typedef __u16 __virtio16;

typedef __u32 __virtio32;

typedef __u64 __virtio64;

struct vring_desc {
	__virtio64 addr;
	__virtio32 len;
	__virtio16 flags;
	__virtio16 next;
};

struct vring_avail {
	__virtio16 flags;
	__virtio16 idx;
	__virtio16 ring[0];
};

struct vring_used_elem {
	__virtio32 id;
	__virtio32 len;
};

typedef struct vring_used_elem vring_used_elem_t;

struct vring_used {
	__virtio16 flags;
	__virtio16 idx;
	vring_used_elem_t ring[0];
};

typedef struct vring_desc vring_desc_t;

typedef struct vring_avail vring_avail_t;

typedef struct vring_used vring_used_t;

struct vring {
	unsigned int num;
	vring_desc_t *desc;
	vring_avail_t *avail;
	vring_used_t *used;
};

struct vring_packed_desc_event {
	__le16 off_wrap;
	__le16 flags;
};

struct vring_packed_desc {
	__le64 addr;
	__le32 len;
	__le16 id;
	__le16 flags;
};

struct vring_desc_state_split {
	void *data;
	struct vring_desc *indir_desc;
};

struct vring_desc_state_packed {
	void *data;
	struct vring_packed_desc *indir_desc;
	u16 num;
	u16 last;
};

struct vring_desc_extra {
	dma_addr_t addr;
	u32 len;
	u16 flags;
	u16 next;
};

struct vring_virtqueue {
	struct virtqueue vq;
	bool packed_ring;
	bool use_dma_api;
	bool weak_barriers;
	bool broken;
	bool indirect;
	bool event;
	unsigned int free_head;
	unsigned int num_added;
	u16 last_used_idx;
	bool event_triggered;
	union {
		struct {
			struct vring vring;
			u16 avail_flags_shadow;
			u16 avail_idx_shadow;
			struct vring_desc_state_split *desc_state;
			struct vring_desc_extra *desc_extra;
			dma_addr_t queue_dma_addr;
			size_t queue_size_in_bytes;
		} split;
		struct {
			struct {
				unsigned int num;
				struct vring_packed_desc *desc;
				struct vring_packed_desc_event *driver;
				struct vring_packed_desc_event *device;
			} vring;
			bool avail_wrap_counter;
			bool used_wrap_counter;
			u16 avail_used_flags;
			u16 next_avail_idx;
			u16 event_flags_shadow;
			struct vring_desc_state_packed *desc_state;
			struct vring_desc_extra *desc_extra;
			dma_addr_t ring_dma_addr;
			dma_addr_t driver_event_dma_addr;
			dma_addr_t device_event_dma_addr;
			size_t ring_size_in_bytes;
			size_t event_size_in_bytes;
		} packed;
	};
	bool (*notify)(struct virtqueue *);
	bool we_own_ring;
};

struct virtio_mmio_device {
	struct virtio_device vdev;
	struct platform_device *pdev;
	void *base;
	long unsigned int version;
	spinlock_t lock;
	struct list_head virtqueues;
};

struct virtio_mmio_vq_info {
	struct virtqueue *vq;
	struct list_head node;
};

struct n_tty_data {
	size_t read_head;
	size_t commit_head;
	size_t canon_head;
	size_t echo_head;
	size_t echo_commit;
	size_t echo_mark;
	long unsigned int char_map[8];
	long unsigned int overrun_time;
	int num_overrun;
	bool no_room;
	unsigned char lnext: 1;
	unsigned char erasing: 1;
	unsigned char raw: 1;
	unsigned char real_raw: 1;
	unsigned char icanon: 1;
	unsigned char push: 1;
	char read_buf[4096];
	long unsigned int read_flags[128];
	unsigned char echo_buf[4096];
	size_t read_tail;
	size_t line_start;
	unsigned int column;
	unsigned int canon_column;
	size_t echo_tail;
	struct mutex atomic_read_lock;
	struct mutex output_lock;
};

enum {
	ERASE = 0,
	WERASE = 1,
	KILL = 2,
};

struct serial_icounter_struct {
	int cts;
	int dsr;
	int rng;
	int dcd;
	int rx;
	int tx;
	int frame;
	int overrun;
	int parity;
	int brk;
	int buf_overrun;
	int reserved[9];
};

struct serial_struct {
	int type;
	int line;
	unsigned int port;
	int irq;
	int flags;
	int xmit_fifo_size;
	int custom_divisor;
	int baud_base;
	short unsigned int close_delay;
	char io_type;
	char reserved_char[1];
	int hub6;
	short unsigned int closing_wait;
	short unsigned int closing_wait2;
	unsigned char *iomem_base;
	short unsigned int iomem_reg_shift;
	unsigned int port_high;
	long unsigned int iomap_base;
};

struct tty_file_private {
	struct tty_struct *tty;
	struct file *file;
	struct list_head list;
};

struct termios {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
};

struct termios2 {
	tcflag_t c_iflag;
	tcflag_t c_oflag;
	tcflag_t c_cflag;
	tcflag_t c_lflag;
	cc_t c_line;
	cc_t c_cc[19];
	speed_t c_ispeed;
	speed_t c_ospeed;
};

struct termio {
	short unsigned int c_iflag;
	short unsigned int c_oflag;
	short unsigned int c_cflag;
	short unsigned int c_lflag;
	unsigned char c_line;
	unsigned char c_cc[8];
};

struct ldsem_waiter {
	struct list_head list;
	struct task_struct *task;
};

struct pts_fs_info;

struct unipair {
	short unsigned int unicode;
	short unsigned int fontpos;
};

struct unimapdesc {
	short unsigned int entry_ct;
	struct unipair *entries;
};

struct kbentry {
	unsigned char kb_table;
	unsigned char kb_index;
	short unsigned int kb_value;
};

struct kbsentry {
	unsigned char kb_func;
	unsigned char kb_string[512];
};

struct kbkeycode {
	unsigned int scancode;
	unsigned int keycode;
};

struct kbd_repeat {
	int delay;
	int period;
};

struct console_font_op {
	unsigned int op;
	unsigned int flags;
	unsigned int width;
	unsigned int height;
	unsigned int charcount;
	unsigned char *data;
};

struct vt_stat {
	short unsigned int v_active;
	short unsigned int v_signal;
	short unsigned int v_state;
};

struct vt_sizes {
	short unsigned int v_rows;
	short unsigned int v_cols;
	short unsigned int v_scrollsize;
};

struct vt_consize {
	short unsigned int v_rows;
	short unsigned int v_cols;
	short unsigned int v_vlin;
	short unsigned int v_clin;
	short unsigned int v_vcol;
	short unsigned int v_ccol;
};

struct vt_event {
	unsigned int event;
	unsigned int oldev;
	unsigned int newev;
	unsigned int pad[4];
};

struct vt_setactivate {
	unsigned int console;
	struct vt_mode mode;
};

struct vc {
	struct vc_data *d;
	struct work_struct SAK_work;
};

struct vt_spawn_console {
	spinlock_t lock;
	struct pid *pid;
	int sig;
};

struct vt_event_wait {
	struct list_head list;
	struct vt_event event;
	int done;
};

struct vt_notifier_param {
	struct vc_data *vc;
	unsigned int c;
};

struct vcs_poll_data {
	struct notifier_block notifier;
	unsigned int cons_num;
	int event;
	wait_queue_head_t waitq;
	struct fasync_struct *fasync;
};

struct tiocl_selection {
	short unsigned int xs;
	short unsigned int ys;
	short unsigned int xe;
	short unsigned int ye;
	short unsigned int sel_mode;
};

struct vc_selection {
	struct mutex lock;
	struct vc_data *cons;
	char *buffer;
	unsigned int buf_len;
	volatile int start;
	int end;
};

struct input_id {
	__u16 bustype;
	__u16 vendor;
	__u16 product;
	__u16 version;
};

struct input_absinfo {
	__s32 value;
	__s32 minimum;
	__s32 maximum;
	__s32 fuzz;
	__s32 flat;
	__s32 resolution;
};

struct input_keymap_entry {
	__u8 flags;
	__u8 len;
	__u16 index;
	__u32 keycode;
	__u8 scancode[32];
};

struct ff_replay {
	__u16 length;
	__u16 delay;
};

struct ff_trigger {
	__u16 button;
	__u16 interval;
};

struct ff_envelope {
	__u16 attack_length;
	__u16 attack_level;
	__u16 fade_length;
	__u16 fade_level;
};

struct ff_constant_effect {
	__s16 level;
	struct ff_envelope envelope;
};

struct ff_ramp_effect {
	__s16 start_level;
	__s16 end_level;
	struct ff_envelope envelope;
};

struct ff_condition_effect {
	__u16 right_saturation;
	__u16 left_saturation;
	__s16 right_coeff;
	__s16 left_coeff;
	__u16 deadband;
	__s16 center;
};

struct ff_periodic_effect {
	__u16 waveform;
	__u16 period;
	__s16 magnitude;
	__s16 offset;
	__u16 phase;
	struct ff_envelope envelope;
	__u32 custom_len;
	__s16 *custom_data;
};

struct ff_rumble_effect {
	__u16 strong_magnitude;
	__u16 weak_magnitude;
};

struct ff_effect {
	__u16 type;
	__s16 id;
	__u16 direction;
	struct ff_trigger trigger;
	struct ff_replay replay;
	union {
		struct ff_constant_effect constant;
		struct ff_ramp_effect ramp;
		struct ff_periodic_effect periodic;
		struct ff_condition_effect condition[2];
		struct ff_rumble_effect rumble;
	} u;
};

struct input_device_id {
	kernel_ulong_t flags;
	__u16 bustype;
	__u16 vendor;
	__u16 product;
	__u16 version;
	kernel_ulong_t evbit[1];
	kernel_ulong_t keybit[24];
	kernel_ulong_t relbit[1];
	kernel_ulong_t absbit[2];
	kernel_ulong_t mscbit[1];
	kernel_ulong_t ledbit[1];
	kernel_ulong_t sndbit[1];
	kernel_ulong_t ffbit[4];
	kernel_ulong_t swbit[1];
	kernel_ulong_t propbit[1];
	kernel_ulong_t driver_info;
};

struct input_value {
	__u16 type;
	__u16 code;
	__s32 value;
};

enum input_clock_type {
	INPUT_CLK_REAL = 0,
	INPUT_CLK_MONO = 1,
	INPUT_CLK_BOOT = 2,
	INPUT_CLK_MAX = 3,
};

struct ff_device;

struct input_dev_poller;

struct input_mt;

struct input_handle;

struct input_dev {
	const char *name;
	const char *phys;
	const char *uniq;
	struct input_id id;
	long unsigned int propbit[1];
	long unsigned int evbit[1];
	long unsigned int keybit[24];
	long unsigned int relbit[1];
	long unsigned int absbit[2];
	long unsigned int mscbit[1];
	long unsigned int ledbit[1];
	long unsigned int sndbit[1];
	long unsigned int ffbit[4];
	long unsigned int swbit[1];
	unsigned int hint_events_per_packet;
	unsigned int keycodemax;
	unsigned int keycodesize;
	void *keycode;
	int (*setkeycode)(struct input_dev *, const struct input_keymap_entry *, unsigned int *);
	int (*getkeycode)(struct input_dev *, struct input_keymap_entry *);
	struct ff_device *ff;
	struct input_dev_poller *poller;
	unsigned int repeat_key;
	struct timer_list timer;
	int rep[2];
	struct input_mt *mt;
	struct input_absinfo *absinfo;
	long unsigned int key[24];
	long unsigned int led[1];
	long unsigned int snd[1];
	long unsigned int sw[1];
	int (*open)(struct input_dev *);
	void (*close)(struct input_dev *);
	int (*flush)(struct input_dev *, struct file *);
	int (*event)(struct input_dev *, unsigned int, unsigned int, int);
	struct input_handle *grab;
	spinlock_t event_lock;
	struct mutex mutex;
	unsigned int users;
	bool going_away;
	struct device dev;
	struct list_head h_list;
	struct list_head node;
	unsigned int num_vals;
	unsigned int max_vals;
	struct input_value *vals;
	bool devres_managed;
	ktime_t timestamp[3];
	bool inhibited;
};

struct ff_device {
	int (*upload)(struct input_dev *, struct ff_effect *, struct ff_effect *);
	int (*erase)(struct input_dev *, int);
	int (*playback)(struct input_dev *, int, int);
	void (*set_gain)(struct input_dev *, u16);
	void (*set_autocenter)(struct input_dev *, u16);
	void (*destroy)(struct ff_device *);
	void *private;
	long unsigned int ffbit[4];
	struct mutex mutex;
	int max_effects;
	struct ff_effect *effects;
	struct file *effect_owners[0];
};

struct input_handler;

struct input_handle {
	void *private;
	int open;
	const char *name;
	struct input_dev *dev;
	struct input_handler *handler;
	struct list_head d_node;
	struct list_head h_node;
};

struct input_handler {
	void *private;
	void (*event)(struct input_handle *, unsigned int, unsigned int, int);
	void (*events)(struct input_handle *, const struct input_value *, unsigned int);
	bool (*filter)(struct input_handle *, unsigned int, unsigned int, int);
	bool (*match)(struct input_handler *, struct input_dev *);
	int (*connect)(struct input_handler *, struct input_dev *, const struct input_device_id *);
	void (*disconnect)(struct input_handle *);
	void (*start)(struct input_handle *);
	bool legacy_minors;
	int minor;
	const char *name;
	const struct input_device_id *id_table;
	struct list_head h_list;
	struct list_head node;
};

struct kbdiacr {
	unsigned char diacr;
	unsigned char base;
	unsigned char result;
};

struct kbdiacrs {
	unsigned int kb_cnt;
	struct kbdiacr kbdiacr[256];
};

struct kbdiacruc {
	unsigned int diacr;
	unsigned int base;
	unsigned int result;
};

struct kbdiacrsuc {
	unsigned int kb_cnt;
	struct kbdiacruc kbdiacruc[256];
};

struct keyboard_notifier_param {
	struct vc_data *vc;
	int down;
	int shift;
	int ledstate;
	unsigned int value;
};

struct kbd_struct {
	unsigned char lockstate;
	unsigned char slockstate;
	unsigned char ledmode: 1;
	unsigned char ledflagstate: 4;
	char: 3;
	unsigned char default_ledflagstate: 4;
	unsigned char kbdmode: 3;
	char: 1;
	unsigned char modeflags: 5;
};

typedef void k_handler_fn(struct vc_data *, unsigned char, char);

typedef void fn_handler_fn(struct vc_data *);

struct getset_keycode_data {
	struct input_keymap_entry ke;
	int error;
};

typedef short unsigned int u_short;

struct uni_pagedir {
	u16 **uni_pgdir[32];
	long unsigned int refcount;
	long unsigned int sum;
	unsigned char *inverse_translations[4];
	u16 *inverse_trans_unicode;
};

typedef uint32_t char32_t;

struct uni_screen {
	char32_t *lines[0];
};

struct con_driver {
	const struct consw *con;
	const char *desc;
	struct device *dev;
	int node;
	int first;
	int last;
	int flag;
};

enum {
	blank_off = 0,
	blank_normal_wait = 1,
	blank_vesa_wait = 2,
};

enum {
	EPecma = 0,
	EPdec = 1,
	EPeq = 2,
	EPgt = 3,
	EPlt = 4,
};

struct rgb {
	u8 r;
	u8 g;
	u8 b;
};

enum {
	ESnormal = 0,
	ESesc = 1,
	ESsquare = 2,
	ESgetpars = 3,
	ESfunckey = 4,
	EShash = 5,
	ESsetG0 = 6,
	ESsetG1 = 7,
	ESpercent = 8,
	EScsiignore = 9,
	ESnonstd = 10,
	ESpalette = 11,
	ESosc = 12,
	ESapc = 13,
	ESpm = 14,
	ESdcs = 15,
};

struct interval {
	uint32_t first;
	uint32_t last;
};

struct vc_draw_region {
	long unsigned int from;
	long unsigned int to;
	int x;
};

struct serial_rs485 {
	__u32 flags;
	__u32 delay_rts_before_send;
	__u32 delay_rts_after_send;
	__u32 padding[5];
};

struct serial_iso7816 {
	__u32 flags;
	__u32 tg;
	__u32 sc_fi;
	__u32 sc_di;
	__u32 clk;
	__u32 reserved[5];
};

struct circ_buf {
	char *buf;
	int head;
	int tail;
};

struct uart_port;

struct uart_ops {
	unsigned int (*tx_empty)(struct uart_port *);
	void (*set_mctrl)(struct uart_port *, unsigned int);
	unsigned int (*get_mctrl)(struct uart_port *);
	void (*stop_tx)(struct uart_port *);
	void (*start_tx)(struct uart_port *);
	void (*throttle)(struct uart_port *);
	void (*unthrottle)(struct uart_port *);
	void (*send_xchar)(struct uart_port *, char);
	void (*stop_rx)(struct uart_port *);
	void (*enable_ms)(struct uart_port *);
	void (*break_ctl)(struct uart_port *, int);
	int (*startup)(struct uart_port *);
	void (*shutdown)(struct uart_port *);
	void (*flush_buffer)(struct uart_port *);
	void (*set_termios)(struct uart_port *, struct ktermios *, struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	const char * (*type)(struct uart_port *);
	void (*release_port)(struct uart_port *);
	int (*request_port)(struct uart_port *);
	void (*config_port)(struct uart_port *, int);
	int (*verify_port)(struct uart_port *, struct serial_struct *);
	int (*ioctl)(struct uart_port *, unsigned int, long unsigned int);
};

struct uart_icount {
	__u32 cts;
	__u32 dsr;
	__u32 rng;
	__u32 dcd;
	__u32 rx;
	__u32 tx;
	__u32 frame;
	__u32 overrun;
	__u32 parity;
	__u32 brk;
	__u32 buf_overrun;
};

typedef unsigned int upf_t;

typedef unsigned int upstat_t;

struct uart_state;

struct uart_port {
	spinlock_t lock;
	long unsigned int iobase;
	unsigned char *membase;
	unsigned int (*serial_in)(struct uart_port *, int);
	void (*serial_out)(struct uart_port *, int, int);
	void (*set_termios)(struct uart_port *, struct ktermios *, struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	unsigned int (*get_mctrl)(struct uart_port *);
	void (*set_mctrl)(struct uart_port *, unsigned int);
	unsigned int (*get_divisor)(struct uart_port *, unsigned int, unsigned int *);
	void (*set_divisor)(struct uart_port *, unsigned int, unsigned int, unsigned int);
	int (*startup)(struct uart_port *);
	void (*shutdown)(struct uart_port *);
	void (*throttle)(struct uart_port *);
	void (*unthrottle)(struct uart_port *);
	int (*handle_irq)(struct uart_port *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	void (*handle_break)(struct uart_port *);
	int (*rs485_config)(struct uart_port *, struct serial_rs485 *);
	int (*iso7816_config)(struct uart_port *, struct serial_iso7816 *);
	unsigned int irq;
	long unsigned int irqflags;
	unsigned int uartclk;
	unsigned int fifosize;
	unsigned char x_char;
	unsigned char regshift;
	unsigned char iotype;
	unsigned char quirks;
	unsigned int read_status_mask;
	unsigned int ignore_status_mask;
	struct uart_state *state;
	struct uart_icount icount;
	struct console *cons;
	upf_t flags;
	upstat_t status;
	int hw_stopped;
	unsigned int mctrl;
	unsigned int timeout;
	unsigned int type;
	const struct uart_ops *ops;
	unsigned int custom_divisor;
	unsigned int line;
	unsigned int minor;
	resource_size_t mapbase;
	resource_size_t mapsize;
	struct device *dev;
	long unsigned int sysrq;
	unsigned int sysrq_ch;
	unsigned char has_sysrq;
	unsigned char sysrq_seq;
	unsigned char hub6;
	unsigned char suspended;
	unsigned char console_reinit;
	const char *name;
	struct attribute_group *attr_group;
	const struct attribute_group **tty_groups;
	struct serial_rs485 rs485;
	struct gpio_desc *rs485_term_gpio;
	struct serial_iso7816 iso7816;
	void *private_data;
};

enum uart_pm_state {
	UART_PM_STATE_ON = 0,
	UART_PM_STATE_OFF = 3,
	UART_PM_STATE_UNDEFINED = 4,
};

struct uart_state {
	struct tty_port port;
	enum uart_pm_state pm_state;
	struct circ_buf xmit;
	atomic_t refcount;
	wait_queue_head_t remove_wait;
	struct uart_port *uart_port;
};

struct uart_driver {
	struct module *owner;
	const char *driver_name;
	const char *dev_name;
	int major;
	int minor;
	int nr;
	struct console *cons;
	struct uart_state *state;
	struct tty_driver *tty_driver;
};

struct uart_match {
	struct uart_port *port;
	struct uart_driver *driver;
};

struct earlycon_device {
	struct console *con;
	struct uart_port port;
	char options[16];
	unsigned int baud;
};

struct earlycon_id {
	char name[15];
	char name_term;
	char compatible[128];
	int (*setup)(struct earlycon_device *, const char *);
};

enum hwparam_type {
	hwparam_ioport = 0,
	hwparam_iomem = 1,
	hwparam_ioport_or_iomem = 2,
	hwparam_irq = 3,
	hwparam_dma = 4,
	hwparam_dma_addr = 5,
	hwparam_other = 6,
};

struct plat_serial8250_port {
	long unsigned int iobase;
	void *membase;
	resource_size_t mapbase;
	unsigned int irq;
	long unsigned int irqflags;
	unsigned int uartclk;
	void *private_data;
	unsigned char regshift;
	unsigned char iotype;
	unsigned char hub6;
	unsigned char has_sysrq;
	upf_t flags;
	unsigned int type;
	unsigned int (*serial_in)(struct uart_port *, int);
	void (*serial_out)(struct uart_port *, int, int);
	void (*set_termios)(struct uart_port *, struct ktermios *, struct ktermios *);
	void (*set_ldisc)(struct uart_port *, struct ktermios *);
	unsigned int (*get_mctrl)(struct uart_port *);
	int (*handle_irq)(struct uart_port *);
	void (*pm)(struct uart_port *, unsigned int, unsigned int);
	void (*handle_break)(struct uart_port *);
};

enum {
	PLAT8250_DEV_LEGACY = 4294967295,
	PLAT8250_DEV_PLATFORM = 0,
	PLAT8250_DEV_PLATFORM1 = 1,
	PLAT8250_DEV_PLATFORM2 = 2,
	PLAT8250_DEV_FOURPORT = 3,
	PLAT8250_DEV_ACCENT = 4,
	PLAT8250_DEV_BOCA = 5,
	PLAT8250_DEV_EXAR_ST16C554 = 6,
	PLAT8250_DEV_HUB6 = 7,
	PLAT8250_DEV_AU1X00 = 8,
	PLAT8250_DEV_SM501 = 9,
};

struct uart_8250_port;

struct uart_8250_ops {
	int (*setup_irq)(struct uart_8250_port *);
	void (*release_irq)(struct uart_8250_port *);
};

struct mctrl_gpios;

struct uart_8250_dma;

struct uart_8250_em485;

struct uart_8250_port {
	struct uart_port port;
	struct timer_list timer;
	struct list_head list;
	u32 capabilities;
	short unsigned int bugs;
	bool fifo_bug;
	unsigned int tx_loadsz;
	unsigned char acr;
	unsigned char fcr;
	unsigned char ier;
	unsigned char lcr;
	unsigned char mcr;
	unsigned char cur_iotype;
	unsigned int rpm_tx_active;
	unsigned char canary;
	unsigned char probe;
	struct mctrl_gpios *gpios;
	unsigned char lsr_saved_flags;
	unsigned char msr_saved_flags;
	struct uart_8250_dma *dma;
	const struct uart_8250_ops *ops;
	int (*dl_read)(struct uart_8250_port *);
	void (*dl_write)(struct uart_8250_port *, int);
	struct uart_8250_em485 *em485;
	void (*rs485_start_tx)(struct uart_8250_port *);
	void (*rs485_stop_tx)(struct uart_8250_port *);
	struct delayed_work overrun_backoff;
	u32 overrun_backoff_time_ms;
};

struct uart_8250_em485 {
	struct hrtimer start_tx_timer;
	struct hrtimer stop_tx_timer;
	struct hrtimer *active_timer;
	struct uart_8250_port *port;
	unsigned int tx_stopped: 1;
};

struct dma_chan;

typedef bool (*dma_filter_fn)(struct dma_chan *, void *);

enum dma_transfer_direction {
	DMA_MEM_TO_MEM = 0,
	DMA_MEM_TO_DEV = 1,
	DMA_DEV_TO_MEM = 2,
	DMA_DEV_TO_DEV = 3,
	DMA_TRANS_NONE = 4,
};

enum dma_slave_buswidth {
	DMA_SLAVE_BUSWIDTH_UNDEFINED = 0,
	DMA_SLAVE_BUSWIDTH_1_BYTE = 1,
	DMA_SLAVE_BUSWIDTH_2_BYTES = 2,
	DMA_SLAVE_BUSWIDTH_3_BYTES = 3,
	DMA_SLAVE_BUSWIDTH_4_BYTES = 4,
	DMA_SLAVE_BUSWIDTH_8_BYTES = 8,
	DMA_SLAVE_BUSWIDTH_16_BYTES = 16,
	DMA_SLAVE_BUSWIDTH_32_BYTES = 32,
	DMA_SLAVE_BUSWIDTH_64_BYTES = 64,
	DMA_SLAVE_BUSWIDTH_128_BYTES = 128,
};

struct dma_slave_config {
	enum dma_transfer_direction direction;
	phys_addr_t src_addr;
	phys_addr_t dst_addr;
	enum dma_slave_buswidth src_addr_width;
	enum dma_slave_buswidth dst_addr_width;
	u32 src_maxburst;
	u32 dst_maxburst;
	u32 src_port_window_size;
	u32 dst_port_window_size;
	bool device_fc;
	void *peripheral_config;
	size_t peripheral_size;
};

typedef s32 dma_cookie_t;

struct uart_8250_dma {
	int (*tx_dma)(struct uart_8250_port *);
	int (*rx_dma)(struct uart_8250_port *);
	dma_filter_fn fn;
	void *rx_param;
	void *tx_param;
	struct dma_slave_config rxconf;
	struct dma_slave_config txconf;
	struct dma_chan *rxchan;
	struct dma_chan *txchan;
	phys_addr_t rx_dma_addr;
	phys_addr_t tx_dma_addr;
	dma_addr_t rx_addr;
	dma_addr_t tx_addr;
	dma_cookie_t rx_cookie;
	dma_cookie_t tx_cookie;
	void *rx_buf;
	size_t rx_size;
	size_t tx_size;
	unsigned char tx_running;
	unsigned char tx_err;
	unsigned char rx_running;
};

enum dma_status {
	DMA_COMPLETE = 0,
	DMA_IN_PROGRESS = 1,
	DMA_PAUSED = 2,
	DMA_ERROR = 3,
	DMA_OUT_OF_ORDER = 4,
};

enum dma_transaction_type {
	DMA_MEMCPY = 0,
	DMA_MEMCPY_SG = 1,
	DMA_XOR = 2,
	DMA_PQ = 3,
	DMA_XOR_VAL = 4,
	DMA_PQ_VAL = 5,
	DMA_MEMSET = 6,
	DMA_MEMSET_SG = 7,
	DMA_INTERRUPT = 8,
	DMA_PRIVATE = 9,
	DMA_ASYNC_TX = 10,
	DMA_SLAVE = 11,
	DMA_CYCLIC = 12,
	DMA_INTERLEAVE = 13,
	DMA_COMPLETION_NO_ORDER = 14,
	DMA_REPEAT = 15,
	DMA_LOAD_EOT = 16,
	DMA_TX_TYPE_END = 17,
};

struct data_chunk {
	size_t size;
	size_t icg;
	size_t dst_icg;
	size_t src_icg;
};

struct dma_interleaved_template {
	dma_addr_t src_start;
	dma_addr_t dst_start;
	enum dma_transfer_direction dir;
	bool src_inc;
	bool dst_inc;
	bool src_sgl;
	bool dst_sgl;
	size_t numf;
	size_t frame_size;
	struct data_chunk sgl[0];
};

enum dma_ctrl_flags {
	DMA_PREP_INTERRUPT = 1,
	DMA_CTRL_ACK = 2,
	DMA_PREP_PQ_DISABLE_P = 4,
	DMA_PREP_PQ_DISABLE_Q = 8,
	DMA_PREP_CONTINUE = 16,
	DMA_PREP_FENCE = 32,
	DMA_CTRL_REUSE = 64,
	DMA_PREP_CMD = 128,
	DMA_PREP_REPEAT = 256,
	DMA_PREP_LOAD_EOT = 512,
};

enum sum_check_bits {
	SUM_CHECK_P = 0,
	SUM_CHECK_Q = 1,
};

enum sum_check_flags {
	SUM_CHECK_P_RESULT = 1,
	SUM_CHECK_Q_RESULT = 2,
};

typedef struct {
	long unsigned int bits[1];
} dma_cap_mask_t;

enum dma_desc_metadata_mode {
	DESC_METADATA_NONE = 0,
	DESC_METADATA_CLIENT = 1,
	DESC_METADATA_ENGINE = 2,
};

struct dma_chan_percpu {
	long unsigned int memcpy_count;
	long unsigned int bytes_transferred;
};

struct dma_router {
	struct device *dev;
	void (*route_free)(struct device *, void *);
};

struct dma_device;

struct dma_chan_dev;

struct dma_chan {
	struct dma_device *device;
	struct device *slave;
	dma_cookie_t cookie;
	dma_cookie_t completed_cookie;
	int chan_id;
	struct dma_chan_dev *dev;
	const char *name;
	char *dbg_client_name;
	struct list_head device_node;
	struct dma_chan_percpu *local;
	int client_count;
	int table_count;
	struct dma_router *router;
	void *route_data;
	void *private;
};

struct dma_slave_map;

struct dma_filter {
	dma_filter_fn fn;
	int mapcnt;
	const struct dma_slave_map *map;
};

enum dmaengine_alignment {
	DMAENGINE_ALIGN_1_BYTE = 0,
	DMAENGINE_ALIGN_2_BYTES = 1,
	DMAENGINE_ALIGN_4_BYTES = 2,
	DMAENGINE_ALIGN_8_BYTES = 3,
	DMAENGINE_ALIGN_16_BYTES = 4,
	DMAENGINE_ALIGN_32_BYTES = 5,
	DMAENGINE_ALIGN_64_BYTES = 6,
	DMAENGINE_ALIGN_128_BYTES = 7,
	DMAENGINE_ALIGN_256_BYTES = 8,
};

enum dma_residue_granularity {
	DMA_RESIDUE_GRANULARITY_DESCRIPTOR = 0,
	DMA_RESIDUE_GRANULARITY_SEGMENT = 1,
	DMA_RESIDUE_GRANULARITY_BURST = 2,
};

struct dma_async_tx_descriptor;

struct dma_slave_caps;

struct dma_tx_state;

struct dma_device {
	struct kref ref;
	unsigned int chancnt;
	unsigned int privatecnt;
	struct list_head channels;
	struct list_head global_node;
	struct dma_filter filter;
	dma_cap_mask_t cap_mask;
	enum dma_desc_metadata_mode desc_metadata_modes;
	short unsigned int max_xor;
	short unsigned int max_pq;
	enum dmaengine_alignment copy_align;
	enum dmaengine_alignment xor_align;
	enum dmaengine_alignment pq_align;
	enum dmaengine_alignment fill_align;
	int dev_id;
	struct device *dev;
	struct module *owner;
	struct ida chan_ida;
	struct mutex chan_mutex;
	u32 src_addr_widths;
	u32 dst_addr_widths;
	u32 directions;
	u32 min_burst;
	u32 max_burst;
	u32 max_sg_burst;
	bool descriptor_reuse;
	enum dma_residue_granularity residue_granularity;
	int (*device_alloc_chan_resources)(struct dma_chan *);
	int (*device_router_config)(struct dma_chan *);
	void (*device_free_chan_resources)(struct dma_chan *);
	struct dma_async_tx_descriptor * (*device_prep_dma_memcpy)(struct dma_chan *, dma_addr_t, dma_addr_t, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memcpy_sg)(struct dma_chan *, struct scatterlist *, unsigned int, struct scatterlist *, unsigned int, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_xor)(struct dma_chan *, dma_addr_t, dma_addr_t *, unsigned int, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_xor_val)(struct dma_chan *, dma_addr_t *, unsigned int, size_t, enum sum_check_flags *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_pq)(struct dma_chan *, dma_addr_t *, dma_addr_t *, unsigned int, const unsigned char *, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_pq_val)(struct dma_chan *, dma_addr_t *, dma_addr_t *, unsigned int, const unsigned char *, size_t, enum sum_check_flags *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memset)(struct dma_chan *, dma_addr_t, int, size_t, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_memset_sg)(struct dma_chan *, struct scatterlist *, unsigned int, int, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_interrupt)(struct dma_chan *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_slave_sg)(struct dma_chan *, struct scatterlist *, unsigned int, enum dma_transfer_direction, long unsigned int, void *);
	struct dma_async_tx_descriptor * (*device_prep_dma_cyclic)(struct dma_chan *, dma_addr_t, size_t, size_t, enum dma_transfer_direction, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_interleaved_dma)(struct dma_chan *, struct dma_interleaved_template *, long unsigned int);
	struct dma_async_tx_descriptor * (*device_prep_dma_imm_data)(struct dma_chan *, dma_addr_t, u64, long unsigned int);
	void (*device_caps)(struct dma_chan *, struct dma_slave_caps *);
	int (*device_config)(struct dma_chan *, struct dma_slave_config *);
	int (*device_pause)(struct dma_chan *);
	int (*device_resume)(struct dma_chan *);
	int (*device_terminate_all)(struct dma_chan *);
	void (*device_synchronize)(struct dma_chan *);
	enum dma_status (*device_tx_status)(struct dma_chan *, dma_cookie_t, struct dma_tx_state *);
	void (*device_issue_pending)(struct dma_chan *);
	void (*device_release)(struct dma_device *);
	void (*dbg_summary_show)(struct seq_file *, struct dma_device *);
	struct dentry *dbg_dev_root;
};

struct dma_chan_dev {
	struct dma_chan *chan;
	struct device device;
	int dev_id;
	bool chan_dma_dev;
};

struct dma_slave_caps {
	u32 src_addr_widths;
	u32 dst_addr_widths;
	u32 directions;
	u32 min_burst;
	u32 max_burst;
	u32 max_sg_burst;
	bool cmd_pause;
	bool cmd_resume;
	bool cmd_terminate;
	enum dma_residue_granularity residue_granularity;
	bool descriptor_reuse;
};

typedef void (*dma_async_tx_callback)(void *);

enum dmaengine_tx_result {
	DMA_TRANS_NOERROR = 0,
	DMA_TRANS_READ_FAILED = 1,
	DMA_TRANS_WRITE_FAILED = 2,
	DMA_TRANS_ABORTED = 3,
};

struct dmaengine_result {
	enum dmaengine_tx_result result;
	u32 residue;
};

typedef void (*dma_async_tx_callback_result)(void *, const struct dmaengine_result *);

struct dmaengine_unmap_data {
	u8 map_cnt;
	u8 to_cnt;
	u8 from_cnt;
	u8 bidi_cnt;
	struct device *dev;
	struct kref kref;
	size_t len;
	dma_addr_t addr[0];
};

struct dma_descriptor_metadata_ops {
	int (*attach)(struct dma_async_tx_descriptor *, void *, size_t);
	void * (*get_ptr)(struct dma_async_tx_descriptor *, size_t *, size_t *);
	int (*set_len)(struct dma_async_tx_descriptor *, size_t);
};

struct dma_async_tx_descriptor {
	dma_cookie_t cookie;
	enum dma_ctrl_flags flags;
	dma_addr_t phys;
	struct dma_chan *chan;
	dma_cookie_t (*tx_submit)(struct dma_async_tx_descriptor *);
	int (*desc_free)(struct dma_async_tx_descriptor *);
	dma_async_tx_callback callback;
	dma_async_tx_callback_result callback_result;
	void *callback_param;
	struct dmaengine_unmap_data *unmap;
	enum dma_desc_metadata_mode desc_metadata_mode;
	struct dma_descriptor_metadata_ops *metadata_ops;
};

struct dma_tx_state {
	dma_cookie_t last;
	dma_cookie_t used;
	u32 residue;
	u32 in_flight_bytes;
};

struct dma_slave_map {
	const char *devname;
	const char *slave;
	void *param;
};

struct old_serial_port {
	unsigned int uart;
	unsigned int baud_base;
	unsigned int port;
	unsigned int irq;
	upf_t flags;
	unsigned char io_type;
	unsigned char *iomem_base;
	short unsigned int iomem_reg_shift;
};

struct irq_info {
	struct hlist_node node;
	int irq;
	spinlock_t lock;
	struct list_head *head;
};

struct serial8250_config {
	const char *name;
	short unsigned int fifo_size;
	short unsigned int tx_loadsz;
	unsigned char fcr;
	unsigned char rxtrig_bytes[4];
	unsigned int flags;
};

struct dw8250_port_data {
	int line;
	struct uart_8250_dma dma;
	u8 dlf_size;
};

struct reset_control;

struct dw8250_data {
	struct dw8250_port_data data;
	u8 usr_reg;
	int msr_mask_on;
	int msr_mask_off;
	struct clk *clk;
	struct clk *pclk;
	struct notifier_block clk_notifier;
	struct work_struct clk_work;
	struct reset_control *rst;
	unsigned int skip_autocfg: 1;
	unsigned int uart_16550_compatible: 1;
};

struct of_serial_info {
	struct clk *clk;
	struct reset_control *rst;
	int type;
	int line;
};

struct memdev {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
	fmode_t fmode;
};

struct timer_rand_state {
	long unsigned int last_time;
	long int last_delta;
	long int last_delta2;
};

enum chacha_constants {
	CHACHA_CONSTANT_EXPA = 1634760805,
	CHACHA_CONSTANT_ND_3 = 857760878,
	CHACHA_CONSTANT_2_BY = 2036477234,
	CHACHA_CONSTANT_TE_K = 1797285236,
};

enum {
	CRNG_RESEED_INTERVAL = 30000,
	CRNG_INIT_CNT_THRESH = 64,
};

struct crng {
	u8 key[32];
	long unsigned int generation;
	local_lock_t lock;
};

struct batched_entropy {
	union {
		u64 entropy_u64[12];
		u32 entropy_u32[24];
	};
	local_lock_t lock;
	long unsigned int generation;
	unsigned int position;
};

enum {
	POOL_BITS = 256,
	POOL_MIN_BITS = 256,
};

struct fast_pool {
	struct work_struct mix;
	long unsigned int pool[4];
	long unsigned int last;
	unsigned int count;
	u16 reg_idx;
};

enum {
	MIX_INFLIGHT = 2147483648,
};

struct miscdevice {
	int minor;
	const char *name;
	const struct file_operations *fops;
	struct list_head list;
	struct device *parent;
	struct device *this_device;
	const struct attribute_group **groups;
	const char *nodename;
	umode_t mode;
};

struct component_ops {
	int (*bind)(struct device *, struct device *, void *);
	void (*unbind)(struct device *, struct device *, void *);
};

struct component_master_ops {
	int (*bind)(struct device *);
	void (*unbind)(struct device *);
};

struct component;

struct component_match_array {
	void *data;
	int (*compare)(struct device *, void *);
	int (*compare_typed)(struct device *, int, void *);
	void (*release)(struct device *, void *);
	struct component *component;
	bool duplicate;
};

struct aggregate_device;

struct component {
	struct list_head node;
	struct aggregate_device *adev;
	bool bound;
	const struct component_ops *ops;
	int subcomponent;
	struct device *dev;
};

struct component_match {
	size_t alloc;
	size_t num;
	struct component_match_array *compare;
};

struct aggregate_device {
	struct list_head node;
	bool bound;
	const struct component_master_ops *ops;
	struct device *parent;
	struct component_match *match;
};

struct subsys_private {
	struct kset subsys;
	struct kset *devices_kset;
	struct list_head interfaces;
	struct mutex mutex;
	struct kset *drivers_kset;
	struct klist klist_devices;
	struct klist klist_drivers;
	struct blocking_notifier_head bus_notifier;
	unsigned int drivers_autoprobe: 1;
	struct bus_type *bus;
	struct kset glue_dirs;
	struct class *class;
};

struct bus_attribute {
	struct attribute attr;
	ssize_t (*show)(struct bus_type *, char *);
	ssize_t (*store)(struct bus_type *, const char *, size_t);
};

struct subsys_dev_iter {
	struct klist_iter ki;
	const struct device_type *type;
};

struct driver_private {
	struct kobject kobj;
	struct klist klist_devices;
	struct klist_node knode_bus;
	struct module_kobject *mkobj;
	struct device_driver *driver;
};

struct driver_attribute {
	struct attribute attr;
	ssize_t (*show)(struct device_driver *, char *);
	ssize_t (*store)(struct device_driver *, const char *, size_t);
};

struct subsys_interface {
	const char *name;
	struct bus_type *subsys;
	struct list_head node;
	int (*add_dev)(struct device *, struct subsys_interface *);
	void (*remove_dev)(struct device *, struct subsys_interface *);
};

struct device_private {
	struct klist klist_children;
	struct klist_node knode_parent;
	struct klist_node knode_driver;
	struct klist_node knode_bus;
	struct klist_node knode_class;
	struct list_head deferred_probe;
	struct device_driver *async_driver;
	char *deferred_probe_reason;
	struct device *device;
	u8 dead: 1;
};

struct fwnode_link {
	struct fwnode_handle *supplier;
	struct list_head s_hook;
	struct fwnode_handle *consumer;
	struct list_head c_hook;
};

enum dpm_order {
	DPM_ORDER_NONE = 0,
	DPM_ORDER_DEV_AFTER_PARENT = 1,
	DPM_ORDER_PARENT_BEFORE_DEV = 2,
	DPM_ORDER_DEV_LAST = 3,
};

struct class_interface {
	struct list_head node;
	struct class *class;
	int (*add_dev)(struct device *, struct class_interface *);
	void (*remove_dev)(struct device *, struct class_interface *);
};

struct dev_ext_attribute {
	struct device_attribute attr;
	void *var;
};

enum device_link_state {
	DL_STATE_NONE = 4294967295,
	DL_STATE_DORMANT = 0,
	DL_STATE_AVAILABLE = 1,
	DL_STATE_CONSUMER_PROBE = 2,
	DL_STATE_ACTIVE = 3,
	DL_STATE_SUPPLIER_UNBIND = 4,
};

struct device_link {
	struct device *supplier;
	struct list_head s_node;
	struct device *consumer;
	struct list_head c_node;
	struct device link_dev;
	enum device_link_state status;
	u32 flags;
	refcount_t rpm_active;
	struct kref kref;
	struct work_struct rm_work;
	bool supplier_preactivated;
};

union device_attr_group_devres {
	const struct attribute_group *group;
	const struct attribute_group **groups;
};

struct class_dir {
	struct kobject kobj;
	struct class *class;
};

struct root_device {
	struct device dev;
	struct module *owner;
};

struct device_attach_data {
	struct device *dev;
	bool check_async;
	bool want_async;
	bool have_async;
};

struct class_attribute {
	struct attribute attr;
	ssize_t (*show)(struct class *, struct class_attribute *, char *);
	ssize_t (*store)(struct class *, struct class_attribute *, const char *, size_t);
};

struct class_attribute_string {
	struct class_attribute attr;
	char *str;
};

struct class_compat {
	struct kobject *kobj;
};

struct property_entry;

struct platform_device_info {
	struct device *parent;
	struct fwnode_handle *fwnode;
	bool of_node_reused;
	const char *name;
	int id;
	const struct resource *res;
	unsigned int num_res;
	const void *data;
	size_t size_data;
	u64 dma_mask;
	const struct property_entry *properties;
};

enum dev_prop_type {
	DEV_PROP_U8 = 0,
	DEV_PROP_U16 = 1,
	DEV_PROP_U32 = 2,
	DEV_PROP_U64 = 3,
	DEV_PROP_STRING = 4,
	DEV_PROP_REF = 5,
};

struct property_entry {
	const char *name;
	size_t length;
	bool is_inline;
	enum dev_prop_type type;
	union {
		const void *pointer;
		union {
			u8 u8_data[8];
			u16 u16_data[4];
			u32 u32_data[2];
			u64 u64_data[1];
			const char *str[2];
		} value;
	};
};

enum dev_dma_attr {
	DEV_DMA_NOT_SUPPORTED = 0,
	DEV_DMA_NON_COHERENT = 1,
	DEV_DMA_COHERENT = 2,
};

struct software_node {
	const char *name;
	const struct software_node *parent;
	const struct property_entry *properties;
};

typedef void *acpi_handle;

struct irq_affinity_devres {
	unsigned int count;
	unsigned int irq[0];
};

struct platform_object {
	struct platform_device pdev;
	char name[0];
};

struct acpi_device;

struct cpu_attr {
	struct device_attribute attr;
	const struct cpumask * const map;
};

struct probe {
	struct probe *next;
	dev_t dev;
	long unsigned int range;
	struct module *owner;
	kobj_probe_t *get;
	int (*lock)(dev_t, void *);
	void *data;
};

struct kobj_map {
	struct probe *probes[255];
	struct mutex *lock;
};

struct attribute_container {
	struct list_head node;
	struct klist containers;
	struct class *class;
	const struct attribute_group *grp;
	struct device_attribute **attrs;
	int (*match)(struct attribute_container *, struct device *);
	long unsigned int flags;
};

struct internal_container {
	struct klist_node node;
	struct attribute_container *cont;
	struct device classdev;
};

struct devres_node {
	struct list_head entry;
	dr_release_t release;
	const char *name;
	size_t size;
};

struct devres {
	struct devres_node node;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	u8 data[0];
};

struct devres_group {
	struct devres_node node[2];
	void *id;
	int color;
};

struct action_devres {
	void *data;
	void (*action)(void *);
};

struct pages_devres {
	long unsigned int addr;
	unsigned int order;
};

struct transport_container;

struct transport_class {
	struct class class;
	int (*setup)(struct transport_container *, struct device *, struct device *);
	int (*configure)(struct transport_container *, struct device *, struct device *);
	int (*remove)(struct transport_container *, struct device *, struct device *);
};

struct transport_container {
	struct attribute_container ac;
	const struct attribute_group *statistics;
};

struct anon_transport_class {
	struct transport_class tclass;
	struct attribute_container container;
};

struct container_dev {
	struct device dev;
	int (*offline)(struct container_dev *);
};

enum cache_type {
	CACHE_TYPE_NOCACHE = 0,
	CACHE_TYPE_INST = 1,
	CACHE_TYPE_DATA = 2,
	CACHE_TYPE_SEPARATE = 3,
	CACHE_TYPE_UNIFIED = 4,
};

struct cacheinfo {
	unsigned int id;
	enum cache_type type;
	unsigned int level;
	unsigned int coherency_line_size;
	unsigned int number_of_sets;
	unsigned int ways_of_associativity;
	unsigned int physical_line_partition;
	unsigned int size;
	cpumask_t shared_cpu_map;
	unsigned int attributes;
	void *fw_token;
	bool disable_sysfs;
	void *priv;
};

struct cpu_cacheinfo {
	struct cacheinfo *info_list;
	unsigned int num_levels;
	unsigned int num_leaves;
	bool cpu_map_populated;
};

struct cache_type_info {
	const char *size_prop;
	const char *line_size_props[2];
	const char *nr_sets_prop;
};

typedef void * (*devcon_match_fn_t)(struct fwnode_handle *, const char *, void *);

enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT = 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT = 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT = 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT = 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT = 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT = 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT = 6,
	ETHTOOL_LINK_MODE_TP_BIT = 7,
	ETHTOOL_LINK_MODE_AUI_BIT = 8,
	ETHTOOL_LINK_MODE_MII_BIT = 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT = 10,
	ETHTOOL_LINK_MODE_BNC_BIT = 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT = 12,
	ETHTOOL_LINK_MODE_Pause_BIT = 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT = 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT = 15,
	ETHTOOL_LINK_MODE_Backplane_BIT = 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT = 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT = 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT = 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT = 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT = 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT = 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT = 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT = 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT = 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT = 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT = 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT = 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT = 30,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT = 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT = 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT = 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT = 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT = 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT = 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT = 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT = 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT = 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT = 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT = 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT = 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT = 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT = 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT = 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT = 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT = 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT = 48,
	ETHTOOL_LINK_MODE_FEC_NONE_BIT = 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT = 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT = 51,
	ETHTOOL_LINK_MODE_50000baseKR_Full_BIT = 52,
	ETHTOOL_LINK_MODE_50000baseSR_Full_BIT = 53,
	ETHTOOL_LINK_MODE_50000baseCR_Full_BIT = 54,
	ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT = 55,
	ETHTOOL_LINK_MODE_50000baseDR_Full_BIT = 56,
	ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT = 57,
	ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT = 58,
	ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT = 59,
	ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT = 60,
	ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT = 61,
	ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT = 62,
	ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT = 63,
	ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT = 64,
	ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT = 65,
	ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT = 66,
	ETHTOOL_LINK_MODE_100baseT1_Full_BIT = 67,
	ETHTOOL_LINK_MODE_1000baseT1_Full_BIT = 68,
	ETHTOOL_LINK_MODE_400000baseKR8_Full_BIT = 69,
	ETHTOOL_LINK_MODE_400000baseSR8_Full_BIT = 70,
	ETHTOOL_LINK_MODE_400000baseLR8_ER8_FR8_Full_BIT = 71,
	ETHTOOL_LINK_MODE_400000baseDR8_Full_BIT = 72,
	ETHTOOL_LINK_MODE_400000baseCR8_Full_BIT = 73,
	ETHTOOL_LINK_MODE_FEC_LLRS_BIT = 74,
	ETHTOOL_LINK_MODE_100000baseKR_Full_BIT = 75,
	ETHTOOL_LINK_MODE_100000baseSR_Full_BIT = 76,
	ETHTOOL_LINK_MODE_100000baseLR_ER_FR_Full_BIT = 77,
	ETHTOOL_LINK_MODE_100000baseCR_Full_BIT = 78,
	ETHTOOL_LINK_MODE_100000baseDR_Full_BIT = 79,
	ETHTOOL_LINK_MODE_200000baseKR2_Full_BIT = 80,
	ETHTOOL_LINK_MODE_200000baseSR2_Full_BIT = 81,
	ETHTOOL_LINK_MODE_200000baseLR2_ER2_FR2_Full_BIT = 82,
	ETHTOOL_LINK_MODE_200000baseDR2_Full_BIT = 83,
	ETHTOOL_LINK_MODE_200000baseCR2_Full_BIT = 84,
	ETHTOOL_LINK_MODE_400000baseKR4_Full_BIT = 85,
	ETHTOOL_LINK_MODE_400000baseSR4_Full_BIT = 86,
	ETHTOOL_LINK_MODE_400000baseLR4_ER4_FR4_Full_BIT = 87,
	ETHTOOL_LINK_MODE_400000baseDR4_Full_BIT = 88,
	ETHTOOL_LINK_MODE_400000baseCR4_Full_BIT = 89,
	ETHTOOL_LINK_MODE_100baseFX_Half_BIT = 90,
	ETHTOOL_LINK_MODE_100baseFX_Full_BIT = 91,
	__ETHTOOL_LINK_MODE_MASK_NBITS = 92,
};

typedef enum {
	PHY_INTERFACE_MODE_NA = 0,
	PHY_INTERFACE_MODE_INTERNAL = 1,
	PHY_INTERFACE_MODE_MII = 2,
	PHY_INTERFACE_MODE_GMII = 3,
	PHY_INTERFACE_MODE_SGMII = 4,
	PHY_INTERFACE_MODE_TBI = 5,
	PHY_INTERFACE_MODE_REVMII = 6,
	PHY_INTERFACE_MODE_RMII = 7,
	PHY_INTERFACE_MODE_REVRMII = 8,
	PHY_INTERFACE_MODE_RGMII = 9,
	PHY_INTERFACE_MODE_RGMII_ID = 10,
	PHY_INTERFACE_MODE_RGMII_RXID = 11,
	PHY_INTERFACE_MODE_RGMII_TXID = 12,
	PHY_INTERFACE_MODE_RTBI = 13,
	PHY_INTERFACE_MODE_SMII = 14,
	PHY_INTERFACE_MODE_XGMII = 15,
	PHY_INTERFACE_MODE_XLGMII = 16,
	PHY_INTERFACE_MODE_MOCA = 17,
	PHY_INTERFACE_MODE_QSGMII = 18,
	PHY_INTERFACE_MODE_TRGMII = 19,
	PHY_INTERFACE_MODE_100BASEX = 20,
	PHY_INTERFACE_MODE_1000BASEX = 21,
	PHY_INTERFACE_MODE_2500BASEX = 22,
	PHY_INTERFACE_MODE_5GBASER = 23,
	PHY_INTERFACE_MODE_RXAUI = 24,
	PHY_INTERFACE_MODE_XAUI = 25,
	PHY_INTERFACE_MODE_10GBASER = 26,
	PHY_INTERFACE_MODE_25GBASER = 27,
	PHY_INTERFACE_MODE_USXGMII = 28,
	PHY_INTERFACE_MODE_10GKR = 29,
	PHY_INTERFACE_MODE_MAX = 30,
} phy_interface_t;

struct software_node_ref_args {
	const struct software_node *node;
	unsigned int nargs;
	u64 args[8];
};

struct swnode {
	struct kobject kobj;
	struct fwnode_handle fwnode;
	const struct software_node *node;
	int id;
	struct ida child_ids;
	struct list_head entry;
	struct list_head children;
	struct swnode *parent;
	unsigned int allocated: 1;
	unsigned int managed: 1;
};

struct pm_clk_notifier_block {
	struct notifier_block nb;
	struct dev_pm_domain *pm_domain;
	char *con_ids[0];
};

struct req {
	struct req *next;
	struct completion done;
	int err;
	const char *name;
	umode_t mode;
	kuid_t uid;
	kgid_t gid;
	struct device *dev;
};

struct firmware {
	size_t size;
	const u8 *data;
	void *priv;
};

struct builtin_fw {
	char *name;
	void *data;
	long unsigned int size;
};

enum fw_opt {
	FW_OPT_UEVENT = 1,
	FW_OPT_NOWAIT = 2,
	FW_OPT_USERHELPER = 4,
	FW_OPT_NO_WARN = 8,
	FW_OPT_NOCACHE = 16,
	FW_OPT_NOFALLBACK_SYSFS = 32,
	FW_OPT_FALLBACK_PLATFORM = 64,
	FW_OPT_PARTIAL = 128,
};

enum fw_status {
	FW_STATUS_UNKNOWN = 0,
	FW_STATUS_LOADING = 1,
	FW_STATUS_DONE = 2,
	FW_STATUS_ABORTED = 3,
};

struct fw_state {
	struct completion completion;
	enum fw_status status;
};

struct firmware_cache;

struct fw_priv {
	struct kref ref;
	struct list_head list;
	struct firmware_cache *fwc;
	struct fw_state fw_st;
	void *data;
	size_t size;
	size_t allocated_size;
	size_t offset;
	u32 opt_flags;
	const char *fw_name;
};

struct firmware_cache {
	spinlock_t lock;
	struct list_head head;
	int state;
};

struct firmware_work {
	struct work_struct work;
	struct module *module;
	const char *name;
	struct device *device;
	void *context;
	void (*cont)(const struct firmware *, void *);
	u32 opt_flags;
};

struct trace_event_raw_devres {
	struct trace_entry ent;
	u32 __data_loc_devname;
	struct device *dev;
	const char *op;
	void *node;
	const char *name;
	size_t size;
	char __data[0];
};

struct trace_event_data_offsets_devres {
	u32 devname;
};

typedef void (*btf_trace_devres_log)(void *, struct device *, const char *, void *, const char *, size_t);

struct virtio_blk_geometry {
	__virtio16 cylinders;
	__u8 heads;
	__u8 sectors;
};

struct virtio_blk_config {
	__virtio64 capacity;
	__virtio32 size_max;
	__virtio32 seg_max;
	struct virtio_blk_geometry geometry;
	__virtio32 blk_size;
	__u8 physical_block_exp;
	__u8 alignment_offset;
	__virtio16 min_io_size;
	__virtio32 opt_io_size;
	__u8 wce;
	__u8 unused;
	__virtio16 num_queues;
	__virtio32 max_discard_sectors;
	__virtio32 max_discard_seg;
	__virtio32 discard_sector_alignment;
	__virtio32 max_write_zeroes_sectors;
	__virtio32 max_write_zeroes_seg;
	__u8 write_zeroes_may_unmap;
	__u8 unused1[3];
};

struct virtio_blk_outhdr {
	__virtio32 type;
	__virtio32 ioprio;
	__virtio64 sector;
};

struct virtio_blk_discard_write_zeroes {
	__le64 sector;
	__le32 num_sectors;
	__le32 flags;
};

struct virtio_blk_vq {
	struct virtqueue *vq;
	spinlock_t lock;
	char name[16];
};

struct virtio_blk {
	struct mutex vdev_mutex;
	struct virtio_device *vdev;
	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;
	struct work_struct config_work;
	int index;
	int num_vqs;
	struct virtio_blk_vq *vqs;
};

struct virtblk_req {
	struct virtio_blk_outhdr out_hdr;
	u8 status;
	struct sg_table sg_table;
	struct scatterlist sg[0];
};

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

enum {
	NETIF_F_SG_BIT = 0,
	NETIF_F_IP_CSUM_BIT = 1,
	__UNUSED_NETIF_F_1 = 2,
	NETIF_F_HW_CSUM_BIT = 3,
	NETIF_F_IPV6_CSUM_BIT = 4,
	NETIF_F_HIGHDMA_BIT = 5,
	NETIF_F_FRAGLIST_BIT = 6,
	NETIF_F_HW_VLAN_CTAG_TX_BIT = 7,
	NETIF_F_HW_VLAN_CTAG_RX_BIT = 8,
	NETIF_F_HW_VLAN_CTAG_FILTER_BIT = 9,
	NETIF_F_VLAN_CHALLENGED_BIT = 10,
	NETIF_F_GSO_BIT = 11,
	NETIF_F_LLTX_BIT = 12,
	NETIF_F_NETNS_LOCAL_BIT = 13,
	NETIF_F_GRO_BIT = 14,
	NETIF_F_LRO_BIT = 15,
	NETIF_F_GSO_SHIFT = 16,
	NETIF_F_TSO_BIT = 16,
	NETIF_F_GSO_ROBUST_BIT = 17,
	NETIF_F_TSO_ECN_BIT = 18,
	NETIF_F_TSO_MANGLEID_BIT = 19,
	NETIF_F_TSO6_BIT = 20,
	NETIF_F_FSO_BIT = 21,
	NETIF_F_GSO_GRE_BIT = 22,
	NETIF_F_GSO_GRE_CSUM_BIT = 23,
	NETIF_F_GSO_IPXIP4_BIT = 24,
	NETIF_F_GSO_IPXIP6_BIT = 25,
	NETIF_F_GSO_UDP_TUNNEL_BIT = 26,
	NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT = 27,
	NETIF_F_GSO_PARTIAL_BIT = 28,
	NETIF_F_GSO_TUNNEL_REMCSUM_BIT = 29,
	NETIF_F_GSO_SCTP_BIT = 30,
	NETIF_F_GSO_ESP_BIT = 31,
	NETIF_F_GSO_UDP_BIT = 32,
	NETIF_F_GSO_UDP_L4_BIT = 33,
	NETIF_F_GSO_FRAGLIST_BIT = 34,
	NETIF_F_GSO_LAST = 34,
	NETIF_F_FCOE_CRC_BIT = 35,
	NETIF_F_SCTP_CRC_BIT = 36,
	NETIF_F_FCOE_MTU_BIT = 37,
	NETIF_F_NTUPLE_BIT = 38,
	NETIF_F_RXHASH_BIT = 39,
	NETIF_F_RXCSUM_BIT = 40,
	NETIF_F_NOCACHE_COPY_BIT = 41,
	NETIF_F_LOOPBACK_BIT = 42,
	NETIF_F_RXFCS_BIT = 43,
	NETIF_F_RXALL_BIT = 44,
	NETIF_F_HW_VLAN_STAG_TX_BIT = 45,
	NETIF_F_HW_VLAN_STAG_RX_BIT = 46,
	NETIF_F_HW_VLAN_STAG_FILTER_BIT = 47,
	NETIF_F_HW_L2FW_DOFFLOAD_BIT = 48,
	NETIF_F_HW_TC_BIT = 49,
	NETIF_F_HW_ESP_BIT = 50,
	NETIF_F_HW_ESP_TX_CSUM_BIT = 51,
	NETIF_F_RX_UDP_TUNNEL_PORT_BIT = 52,
	NETIF_F_HW_TLS_TX_BIT = 53,
	NETIF_F_HW_TLS_RX_BIT = 54,
	NETIF_F_GRO_HW_BIT = 55,
	NETIF_F_HW_TLS_RECORD_BIT = 56,
	NETIF_F_GRO_FRAGLIST_BIT = 57,
	NETIF_F_HW_MACSEC_BIT = 58,
	NETIF_F_GRO_UDP_FWD_BIT = 59,
	NETIF_F_HW_HSR_TAG_INS_BIT = 60,
	NETIF_F_HW_HSR_TAG_RM_BIT = 61,
	NETIF_F_HW_HSR_FWD_BIT = 62,
	NETIF_F_HW_HSR_DUP_BIT = 63,
	NETDEV_FEATURE_COUNT = 64,
};

typedef struct bio_vec skb_frag_t;

struct skb_shared_hwtstamps {
	ktime_t hwtstamp;
};

enum {
	SKBTX_HW_TSTAMP = 1,
	SKBTX_SW_TSTAMP = 2,
	SKBTX_IN_PROGRESS = 4,
	SKBTX_WIFI_STATUS = 16,
	SKBTX_SCHED_TSTAMP = 64,
};

struct skb_shared_info {
	__u8 flags;
	__u8 meta_len;
	__u8 nr_frags;
	__u8 tx_flags;
	short unsigned int gso_size;
	short unsigned int gso_segs;
	struct sk_buff *frag_list;
	struct skb_shared_hwtstamps hwtstamps;
	unsigned int gso_type;
	u32 tskey;
	atomic_t dataref;
	unsigned int xdp_frags_size;
	void *destructor_arg;
	skb_frag_t frags[16];
};

struct ethtool_drvinfo {
	__u32 cmd;
	char driver[32];
	char version[32];
	char fw_version[32];
	char bus_info[32];
	char erom_version[32];
	char reserved2[12];
	__u32 n_priv_flags;
	__u32 n_stats;
	__u32 testinfo_len;
	__u32 eedump_len;
	__u32 regdump_len;
};

struct ethtool_wolinfo {
	__u32 cmd;
	__u32 supported;
	__u32 wolopts;
	__u8 sopass[6];
};

struct ethtool_tunable {
	__u32 cmd;
	__u32 id;
	__u32 type_id;
	__u32 len;
	void *data[0];
};

struct ethtool_regs {
	__u32 cmd;
	__u32 version;
	__u32 len;
	__u8 data[0];
};

struct ethtool_eeprom {
	__u32 cmd;
	__u32 magic;
	__u32 offset;
	__u32 len;
	__u8 data[0];
};

struct ethtool_eee {
	__u32 cmd;
	__u32 supported;
	__u32 advertised;
	__u32 lp_advertised;
	__u32 eee_active;
	__u32 eee_enabled;
	__u32 tx_lpi_enabled;
	__u32 tx_lpi_timer;
	__u32 reserved[2];
};

struct ethtool_modinfo {
	__u32 cmd;
	__u32 type;
	__u32 eeprom_len;
	__u32 reserved[8];
};

struct ethtool_coalesce {
	__u32 cmd;
	__u32 rx_coalesce_usecs;
	__u32 rx_max_coalesced_frames;
	__u32 rx_coalesce_usecs_irq;
	__u32 rx_max_coalesced_frames_irq;
	__u32 tx_coalesce_usecs;
	__u32 tx_max_coalesced_frames;
	__u32 tx_coalesce_usecs_irq;
	__u32 tx_max_coalesced_frames_irq;
	__u32 stats_block_coalesce_usecs;
	__u32 use_adaptive_rx_coalesce;
	__u32 use_adaptive_tx_coalesce;
	__u32 pkt_rate_low;
	__u32 rx_coalesce_usecs_low;
	__u32 rx_max_coalesced_frames_low;
	__u32 tx_coalesce_usecs_low;
	__u32 tx_max_coalesced_frames_low;
	__u32 pkt_rate_high;
	__u32 rx_coalesce_usecs_high;
	__u32 rx_max_coalesced_frames_high;
	__u32 tx_coalesce_usecs_high;
	__u32 tx_max_coalesced_frames_high;
	__u32 rate_sample_interval;
};

struct ethtool_ringparam {
	__u32 cmd;
	__u32 rx_max_pending;
	__u32 rx_mini_max_pending;
	__u32 rx_jumbo_max_pending;
	__u32 tx_max_pending;
	__u32 rx_pending;
	__u32 rx_mini_pending;
	__u32 rx_jumbo_pending;
	__u32 tx_pending;
};

struct ethtool_channels {
	__u32 cmd;
	__u32 max_rx;
	__u32 max_tx;
	__u32 max_other;
	__u32 max_combined;
	__u32 rx_count;
	__u32 tx_count;
	__u32 other_count;
	__u32 combined_count;
};

struct ethtool_pauseparam {
	__u32 cmd;
	__u32 autoneg;
	__u32 rx_pause;
	__u32 tx_pause;
};

enum ethtool_link_ext_state {
	ETHTOOL_LINK_EXT_STATE_AUTONEG = 0,
	ETHTOOL_LINK_EXT_STATE_LINK_TRAINING_FAILURE = 1,
	ETHTOOL_LINK_EXT_STATE_LINK_LOGICAL_MISMATCH = 2,
	ETHTOOL_LINK_EXT_STATE_BAD_SIGNAL_INTEGRITY = 3,
	ETHTOOL_LINK_EXT_STATE_NO_CABLE = 4,
	ETHTOOL_LINK_EXT_STATE_CABLE_ISSUE = 5,
	ETHTOOL_LINK_EXT_STATE_EEPROM_ISSUE = 6,
	ETHTOOL_LINK_EXT_STATE_CALIBRATION_FAILURE = 7,
	ETHTOOL_LINK_EXT_STATE_POWER_BUDGET_EXCEEDED = 8,
	ETHTOOL_LINK_EXT_STATE_OVERHEAT = 9,
	ETHTOOL_LINK_EXT_STATE_MODULE = 10,
};

enum ethtool_link_ext_substate_autoneg {
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_ACK_NOT_RECEIVED = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NEXT_PAGE_EXCHANGE_FAILED = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_PARTNER_DETECTED_FORCE_MODE = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_FEC_MISMATCH_DURING_OVERRIDE = 5,
	ETHTOOL_LINK_EXT_SUBSTATE_AN_NO_HCD = 6,
};

enum ethtool_link_ext_substate_link_training {
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_FRAME_LOCK_NOT_ACQUIRED = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_INHIBIT_TIMEOUT = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_KR_LINK_PARTNER_DID_NOT_SET_RECEIVER_READY = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LT_REMOTE_FAULT = 4,
};

enum ethtool_link_ext_substate_link_logical_mismatch {
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_BLOCK_LOCK = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_ACQUIRE_AM_LOCK = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_PCS_DID_NOT_GET_ALIGN_STATUS = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_FC_FEC_IS_NOT_LOCKED = 4,
	ETHTOOL_LINK_EXT_SUBSTATE_LLM_RS_FEC_IS_NOT_LOCKED = 5,
};

enum ethtool_link_ext_substate_bad_signal_integrity {
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_LARGE_NUMBER_OF_PHYSICAL_ERRORS = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_UNSUPPORTED_RATE = 2,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_REFERENCE_CLOCK_LOST = 3,
	ETHTOOL_LINK_EXT_SUBSTATE_BSI_SERDES_ALOS = 4,
};

enum ethtool_link_ext_substate_cable_issue {
	ETHTOOL_LINK_EXT_SUBSTATE_CI_UNSUPPORTED_CABLE = 1,
	ETHTOOL_LINK_EXT_SUBSTATE_CI_CABLE_TEST_FAILURE = 2,
};

enum ethtool_link_ext_substate_module {
	ETHTOOL_LINK_EXT_SUBSTATE_MODULE_CMIS_NOT_READY = 1,
};

enum ethtool_module_power_mode_policy {
	ETHTOOL_MODULE_POWER_MODE_POLICY_HIGH = 1,
	ETHTOOL_MODULE_POWER_MODE_POLICY_AUTO = 2,
};

enum ethtool_module_power_mode {
	ETHTOOL_MODULE_POWER_MODE_LOW = 1,
	ETHTOOL_MODULE_POWER_MODE_HIGH = 2,
};

struct ethtool_test {
	__u32 cmd;
	__u32 flags;
	__u32 reserved;
	__u32 len;
	__u64 data[0];
};

struct ethtool_stats {
	__u32 cmd;
	__u32 n_stats;
	__u64 data[0];
};

struct ethtool_tcpip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be16 psrc;
	__be16 pdst;
	__u8 tos;
};

struct ethtool_ah_espip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 spi;
	__u8 tos;
};

struct ethtool_usrip4_spec {
	__be32 ip4src;
	__be32 ip4dst;
	__be32 l4_4_bytes;
	__u8 tos;
	__u8 ip_ver;
	__u8 proto;
};

struct ethtool_tcpip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be16 psrc;
	__be16 pdst;
	__u8 tclass;
};

struct ethtool_ah_espip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 spi;
	__u8 tclass;
};

struct ethtool_usrip6_spec {
	__be32 ip6src[4];
	__be32 ip6dst[4];
	__be32 l4_4_bytes;
	__u8 tclass;
	__u8 l4_proto;
};

union ethtool_flow_union {
	struct ethtool_tcpip4_spec tcp_ip4_spec;
	struct ethtool_tcpip4_spec udp_ip4_spec;
	struct ethtool_tcpip4_spec sctp_ip4_spec;
	struct ethtool_ah_espip4_spec ah_ip4_spec;
	struct ethtool_ah_espip4_spec esp_ip4_spec;
	struct ethtool_usrip4_spec usr_ip4_spec;
	struct ethtool_tcpip6_spec tcp_ip6_spec;
	struct ethtool_tcpip6_spec udp_ip6_spec;
	struct ethtool_tcpip6_spec sctp_ip6_spec;
	struct ethtool_ah_espip6_spec ah_ip6_spec;
	struct ethtool_ah_espip6_spec esp_ip6_spec;
	struct ethtool_usrip6_spec usr_ip6_spec;
	struct ethhdr ether_spec;
	__u8 hdata[52];
};

struct ethtool_flow_ext {
	__u8 padding[2];
	unsigned char h_dest[6];
	__be16 vlan_etype;
	__be16 vlan_tci;
	__be32 data[2];
};

struct ethtool_rx_flow_spec {
	__u32 flow_type;
	union ethtool_flow_union h_u;
	struct ethtool_flow_ext h_ext;
	union ethtool_flow_union m_u;
	struct ethtool_flow_ext m_ext;
	__u64 ring_cookie;
	__u32 location;
};

struct ethtool_rxnfc {
	__u32 cmd;
	__u32 flow_type;
	__u64 data;
	struct ethtool_rx_flow_spec fs;
	union {
		__u32 rule_cnt;
		__u32 rss_context;
	};
	__u32 rule_locs[0];
};

struct ethtool_flash {
	__u32 cmd;
	__u32 region;
	char data[128];
};

struct ethtool_dump {
	__u32 cmd;
	__u32 version;
	__u32 flag;
	__u32 len;
	__u8 data[0];
};

struct ethtool_ts_info {
	__u32 cmd;
	__u32 so_timestamping;
	__s32 phc_index;
	__u32 tx_types;
	__u32 tx_reserved[3];
	__u32 rx_filters;
	__u32 rx_reserved[3];
};

struct ethtool_fecparam {
	__u32 cmd;
	__u32 active_fec;
	__u32 fec;
	__u32 reserved;
};

struct ethtool_link_settings {
	__u32 cmd;
	__u32 speed;
	__u8 duplex;
	__u8 port;
	__u8 phy_address;
	__u8 autoneg;
	__u8 mdio_support;
	__u8 eth_tp_mdix;
	__u8 eth_tp_mdix_ctrl;
	__s8 link_mode_masks_nwords;
	__u8 transceiver;
	__u8 master_slave_cfg;
	__u8 master_slave_state;
	__u8 reserved1[1];
	__u32 reserved[7];
	__u32 link_mode_masks[0];
};

struct kernel_ethtool_ringparam {
	u32 rx_buf_len;
	u8 tcp_data_split;
	u32 cqe_size;
};

struct ethtool_link_ext_state_info {
	enum ethtool_link_ext_state link_ext_state;
	union {
		enum ethtool_link_ext_substate_autoneg autoneg;
		enum ethtool_link_ext_substate_link_training link_training;
		enum ethtool_link_ext_substate_link_logical_mismatch link_logical_mismatch;
		enum ethtool_link_ext_substate_bad_signal_integrity bad_signal_integrity;
		enum ethtool_link_ext_substate_cable_issue cable_issue;
		enum ethtool_link_ext_substate_module module;
		u32 __link_ext_substate;
	};
};

struct ethtool_link_ksettings {
	struct ethtool_link_settings base;
	struct {
		long unsigned int supported[3];
		long unsigned int advertising[3];
		long unsigned int lp_advertising[3];
	} link_modes;
	u32 lanes;
};

struct kernel_ethtool_coalesce {
	u8 use_cqe_mode_tx;
	u8 use_cqe_mode_rx;
};

struct ethtool_eth_mac_stats {
	u64 FramesTransmittedOK;
	u64 SingleCollisionFrames;
	u64 MultipleCollisionFrames;
	u64 FramesReceivedOK;
	u64 FrameCheckSequenceErrors;
	u64 AlignmentErrors;
	u64 OctetsTransmittedOK;
	u64 FramesWithDeferredXmissions;
	u64 LateCollisions;
	u64 FramesAbortedDueToXSColls;
	u64 FramesLostDueToIntMACXmitError;
	u64 CarrierSenseErrors;
	u64 OctetsReceivedOK;
	u64 FramesLostDueToIntMACRcvError;
	u64 MulticastFramesXmittedOK;
	u64 BroadcastFramesXmittedOK;
	u64 FramesWithExcessiveDeferral;
	u64 MulticastFramesReceivedOK;
	u64 BroadcastFramesReceivedOK;
	u64 InRangeLengthErrors;
	u64 OutOfRangeLengthField;
	u64 FrameTooLongErrors;
};

struct ethtool_eth_phy_stats {
	u64 SymbolErrorDuringCarrier;
};

struct ethtool_eth_ctrl_stats {
	u64 MACControlFramesTransmitted;
	u64 MACControlFramesReceived;
	u64 UnsupportedOpcodesReceived;
};

struct ethtool_pause_stats {
	u64 tx_pause_frames;
	u64 rx_pause_frames;
};

struct ethtool_fec_stat {
	u64 total;
	u64 lanes[8];
};

struct ethtool_fec_stats {
	struct ethtool_fec_stat corrected_blocks;
	struct ethtool_fec_stat uncorrectable_blocks;
	struct ethtool_fec_stat corrected_bits;
};

struct ethtool_rmon_hist_range {
	u16 low;
	u16 high;
};

struct ethtool_rmon_stats {
	u64 undersize_pkts;
	u64 oversize_pkts;
	u64 fragments;
	u64 jabbers;
	u64 hist[10];
	u64 hist_tx[10];
};

struct ethtool_module_eeprom {
	u32 offset;
	u32 length;
	u8 page;
	u8 bank;
	u8 i2c_address;
	u8 *data;
};

struct ethtool_module_power_mode_params {
	enum ethtool_module_power_mode_policy policy;
	enum ethtool_module_power_mode mode;
};

struct flow_dissector_key_control {
	u16 thoff;
	u16 addr_type;
	u32 flags;
};

struct flow_dissector_key_basic {
	__be16 n_proto;
	u8 ip_proto;
	u8 padding;
};

struct flow_dissector {
	unsigned int used_keys;
	short unsigned int offset[28];
};

struct flow_keys_basic {
	struct flow_dissector_key_control control;
	struct flow_dissector_key_basic basic;
};

enum {
	SKBFL_ZEROCOPY_ENABLE = 1,
	SKBFL_SHARED_FRAG = 2,
	SKBFL_PURE_ZEROCOPY = 4,
};

struct mmpin {
	struct user_struct *user;
	unsigned int num_pg;
};

struct ubuf_info {
	void (*callback)(struct sk_buff *, struct ubuf_info *, bool);
	union {
		struct {
			long unsigned int desc;
			void *ctx;
		};
		struct {
			u32 id;
			u16 len;
			u16 zerocopy: 1;
			u32 bytelen;
		};
	};
	refcount_t refcnt;
	u8 flags;
	struct mmpin mmp;
};

enum {
	SKB_GSO_TCPV4 = 1,
	SKB_GSO_DODGY = 2,
	SKB_GSO_TCP_ECN = 4,
	SKB_GSO_TCP_FIXEDID = 8,
	SKB_GSO_TCPV6 = 16,
	SKB_GSO_FCOE = 32,
	SKB_GSO_GRE = 64,
	SKB_GSO_GRE_CSUM = 128,
	SKB_GSO_IPXIP4 = 256,
	SKB_GSO_IPXIP6 = 512,
	SKB_GSO_UDP_TUNNEL = 1024,
	SKB_GSO_UDP_TUNNEL_CSUM = 2048,
	SKB_GSO_PARTIAL = 4096,
	SKB_GSO_TUNNEL_REMCSUM = 8192,
	SKB_GSO_SCTP = 16384,
	SKB_GSO_ESP = 32768,
	SKB_GSO_UDP = 65536,
	SKB_GSO_UDP_L4 = 131072,
	SKB_GSO_FRAGLIST = 262144,
};

enum pkt_hash_types {
	PKT_HASH_TYPE_NONE = 0,
	PKT_HASH_TYPE_L2 = 1,
	PKT_HASH_TYPE_L3 = 2,
	PKT_HASH_TYPE_L4 = 3,
};

struct netdev_hw_addr {
	struct list_head list;
	struct rb_node node;
	unsigned char addr[32];
	unsigned char type;
	bool global_use;
	int sync_cnt;
	int refcount;
	int synced;
	struct callback_head callback_head;
};

enum netdev_state_t {
	__LINK_STATE_START = 0,
	__LINK_STATE_PRESENT = 1,
	__LINK_STATE_NOCARRIER = 2,
	__LINK_STATE_LINKWATCH_PENDING = 3,
	__LINK_STATE_DORMANT = 4,
	__LINK_STATE_TESTING = 5,
};

struct gro_list {
	struct list_head list;
	int count;
};

struct napi_struct {
	struct list_head poll_list;
	long unsigned int state;
	int weight;
	int defer_hard_irqs_count;
	long unsigned int gro_bitmask;
	int (*poll)(struct napi_struct *, int);
	struct net_device *dev;
	struct gro_list gro_hash[8];
	struct sk_buff *skb;
	struct list_head rx_list;
	int rx_count;
	struct hrtimer timer;
	struct list_head dev_list;
	struct hlist_node napi_hash_node;
	unsigned int napi_id;
	struct task_struct *thread;
};

enum gro_result {
	GRO_MERGED = 0,
	GRO_MERGED_FREE = 1,
	GRO_HELD = 2,
	GRO_NORMAL = 3,
	GRO_CONSUMED = 4,
};

typedef enum gro_result gro_result_t;

enum netdev_queue_state_t {
	__QUEUE_STATE_DRV_XOFF = 0,
	__QUEUE_STATE_STACK_XOFF = 1,
	__QUEUE_STATE_FROZEN = 2,
};

struct rx_queue_attribute {
	struct attribute attr;
	ssize_t (*show)(struct netdev_rx_queue *, char *);
	ssize_t (*store)(struct netdev_rx_queue *, const char *, size_t);
};

enum xps_map_type {
	XPS_CPUS = 0,
	XPS_RXQS = 1,
	XPS_MAPS_MAX = 2,
};

struct softnet_data {
	struct list_head poll_list;
	struct sk_buff_head process_queue;
	unsigned int processed;
	unsigned int time_squeeze;
	unsigned int received_rps;
	struct Qdisc *output_queue;
	struct Qdisc **output_queue_tailp;
	struct sk_buff *completion_queue;
	struct {
		u16 recursion;
		u8 more;
	} xmit;
	unsigned int dropped;
	struct sk_buff_head input_pkt_queue;
	struct napi_struct backlog;
};

enum skb_free_reason {
	SKB_REASON_CONSUMED = 0,
	SKB_REASON_DROPPED = 1,
};

enum ethtool_stringset {
	ETH_SS_TEST = 0,
	ETH_SS_STATS = 1,
	ETH_SS_PRIV_FLAGS = 2,
	ETH_SS_NTUPLE_FILTERS = 3,
	ETH_SS_FEATURES = 4,
	ETH_SS_RSS_HASH_FUNCS = 5,
	ETH_SS_TUNABLES = 6,
	ETH_SS_PHY_STATS = 7,
	ETH_SS_PHY_TUNABLES = 8,
	ETH_SS_LINK_MODES = 9,
	ETH_SS_MSG_CLASSES = 10,
	ETH_SS_WOL_MODES = 11,
	ETH_SS_SOF_TIMESTAMPING = 12,
	ETH_SS_TS_TX_TYPES = 13,
	ETH_SS_TS_RX_FILTERS = 14,
	ETH_SS_UDP_TUNNEL_TYPES = 15,
	ETH_SS_STATS_STD = 16,
	ETH_SS_STATS_ETH_PHY = 17,
	ETH_SS_STATS_ETH_MAC = 18,
	ETH_SS_STATS_ETH_CTRL = 19,
	ETH_SS_STATS_RMON = 20,
	ETH_SS_COUNT = 21,
};

enum {
	ETH_RSS_HASH_TOP_BIT = 0,
	ETH_RSS_HASH_XOR_BIT = 1,
	ETH_RSS_HASH_CRC32_BIT = 2,
	ETH_RSS_HASH_FUNCS_COUNT = 3,
};

struct virtio_net_config {
	__u8 mac[6];
	__virtio16 status;
	__virtio16 max_virtqueue_pairs;
	__virtio16 mtu;
	__le32 speed;
	__u8 duplex;
	__u8 rss_max_key_size;
	__le16 rss_max_indirection_table_length;
	__le32 supported_hash_types;
};

struct virtio_net_hdr_v1 {
	__u8 flags;
	__u8 gso_type;
	__virtio16 hdr_len;
	__virtio16 gso_size;
	union {
		struct {
			__virtio16 csum_start;
			__virtio16 csum_offset;
		};
		struct {
			__virtio16 start;
			__virtio16 offset;
		} csum;
		struct {
			__le16 segments;
			__le16 dup_acks;
		} rsc;
	};
	__virtio16 num_buffers;
};

struct virtio_net_hdr_v1_hash {
	struct virtio_net_hdr_v1 hdr;
	__le32 hash_value;
	__le16 hash_report;
	__le16 padding;
};

struct virtio_net_hdr {
	__u8 flags;
	__u8 gso_type;
	__virtio16 hdr_len;
	__virtio16 gso_size;
	__virtio16 csum_start;
	__virtio16 csum_offset;
};

struct virtio_net_hdr_mrg_rxbuf {
	struct virtio_net_hdr hdr;
	__virtio16 num_buffers;
};

struct virtio_net_ctrl_hdr {
	__u8 class;
	__u8 cmd;
};

typedef __u8 virtio_net_ctrl_ack;

struct virtio_net_ctrl_mac {
	__virtio32 entries;
	__u8 macs[0];
};

struct virtio_net_ctrl_mq {
	__virtio16 virtqueue_pairs;
};

struct failover_ops {
	int (*slave_pre_register)(struct net_device *, struct net_device *);
	int (*slave_register)(struct net_device *, struct net_device *);
	int (*slave_pre_unregister)(struct net_device *, struct net_device *);
	int (*slave_unregister)(struct net_device *, struct net_device *);
	int (*slave_link_change)(struct net_device *, struct net_device *);
	int (*slave_name_change)(struct net_device *, struct net_device *);
	rx_handler_result_t (*slave_handle_frame)(struct sk_buff **);
};

struct failover {
	struct list_head list;
	struct net_device *failover_dev;
	netdevice_tracker dev_tracker;
	struct failover_ops *ops;
};

struct ewma_pkt_len {
	long unsigned int internal;
};

struct virtnet_stat_desc {
	char desc[32];
	size_t offset;
};

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 xdp_tx;
	u64 xdp_tx_drops;
	u64 kicks;
	u64 tx_timeouts;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 xdp_packets;
	u64 xdp_tx;
	u64 xdp_redirects;
	u64 xdp_drops;
	u64 kicks;
};

struct send_queue {
	struct virtqueue *vq;
	struct scatterlist sg[18];
	char name[40];
	struct virtnet_sq_stats stats;
	struct napi_struct napi;
};

struct receive_queue {
	struct virtqueue *vq;
	struct napi_struct napi;
	struct bpf_prog *xdp_prog;
	struct virtnet_rq_stats stats;
	struct page *pages;
	struct ewma_pkt_len mrg_avg_pkt_len;
	struct page_frag alloc_frag;
	struct scatterlist sg[18];
	unsigned int min_buf_len;
	char name[40];
	int: 32;
	int: 32;
	int: 32;
	struct xdp_rxq_info xdp_rxq;
};

struct virtio_net_ctrl_rss {
	u32 hash_types;
	u16 indirection_table_mask;
	u16 unclassified_queue;
	u16 indirection_table[128];
	u16 max_tx_vq;
	u8 hash_key_length;
	u8 key[40];
};

struct control_buf {
	struct virtio_net_ctrl_hdr hdr;
	virtio_net_ctrl_ack status;
	struct virtio_net_ctrl_mq mq;
	u8 promisc;
	u8 allmulti;
	__virtio16 vid;
	__virtio64 offloads;
	struct virtio_net_ctrl_rss rss;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;
	u16 max_queue_pairs;
	u16 curr_queue_pairs;
	u16 xdp_queue_pairs;
	bool xdp_enabled;
	bool big_packets;
	bool mergeable_rx_bufs;
	bool has_rss;
	bool has_rss_hash_report;
	u8 rss_key_size;
	u16 rss_indir_table_size;
	u32 rss_hash_types_supported;
	u32 rss_hash_types_saved;
	bool has_cvq;
	bool any_header_sg;
	u8 hdr_len;
	struct delayed_work refill;
	struct work_struct config_work;
	bool affinity_hint_set;
	struct hlist_node node;
	struct hlist_node node_dead;
	struct control_buf *ctrl;
	u8 duplex;
	u32 speed;
	long unsigned int guest_offloads;
	long unsigned int guest_offloads_capable;
	struct failover *failover;
};

struct netdev_lag_lower_state_info {
	u8 link_up: 1;
	u8 tx_enabled: 1;
};

struct qdisc_skb_cb {
	struct {
		unsigned int pkt_len;
		u16 slave_dev_queue_mapping;
		u16 tc_classid;
	};
	unsigned char data[20];
};

struct net_failover_info {
	struct net_device *primary_dev;
	struct net_device *standby_dev;
	struct rtnl_link_stats64 primary_stats;
	struct rtnl_link_stats64 standby_stats;
	struct rtnl_link_stats64 failover_stats;
	spinlock_t stats_lock;
};

struct input_event {
	__kernel_ulong_t __sec;
	__kernel_ulong_t __usec;
	__u16 type;
	__u16 code;
	__s32 value;
};

struct input_mt_slot {
	int abs[14];
	unsigned int frame;
	unsigned int key;
};

struct input_mt {
	int trkid;
	int num_slots;
	int slot;
	unsigned int flags;
	unsigned int frame;
	int *red;
	struct input_mt_slot slots[0];
};

union input_seq_state {
	struct {
		short unsigned int pos;
		bool mutex_acquired;
	};
	void *p;
};

struct input_devres {
	struct input_dev *input;
};

struct input_mt_pos {
	s16 x;
	s16 y;
};

struct input_dev_poller {
	void (*poll)(struct input_dev *);
	unsigned int poll_interval;
	unsigned int poll_interval_max;
	unsigned int poll_interval_min;
	struct input_dev *input;
	struct delayed_work work;
};

struct touchscreen_properties {
	unsigned int max_x;
	unsigned int max_y;
	bool invert_x;
	bool invert_y;
	bool swap_x_y;
};

struct of_timer_irq {
	int irq;
	int index;
	int percpu;
	const char *name;
	long unsigned int flags;
	irq_handler_t handler;
};

struct of_timer_base {
	void *base;
	const char *name;
	int index;
};

struct of_timer_clk {
	struct clk *clk;
	const char *name;
	int index;
	long unsigned int rate;
	long unsigned int period;
};

struct timer_of {
	unsigned int flags;
	struct device_node *np;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	struct clock_event_device clkevt;
	struct of_timer_base of_base;
	struct of_timer_irq of_irq;
	struct of_timer_clk of_clk;
	void *private_data;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
	int: 32;
};

typedef int (*of_init_fn_1_ret)(struct device_node *);

struct input_mask {
	__u32 type;
	__u32 codes_size;
	__u64 codes_ptr;
};

struct evdev_client;

struct evdev {
	int open;
	struct input_handle handle;
	struct evdev_client *grab;
	struct list_head client_list;
	spinlock_t client_lock;
	struct mutex mutex;
	struct device dev;
	struct cdev cdev;
	bool exist;
};

struct evdev_client {
	unsigned int head;
	unsigned int tail;
	unsigned int packet_head;
	spinlock_t buffer_lock;
	wait_queue_head_t wait;
	struct fasync_struct *fasync;
	struct evdev *evdev;
	struct list_head node;
	enum input_clock_type clk_type;
	bool revoked;
	long unsigned int *evmasks[32];
	unsigned int bufsize;
	struct input_event buffer[0];
};

struct mcip_cmd {
	unsigned int cmd: 8;
	unsigned int param: 16;
	unsigned int pad: 8;
};

struct mcip_bcr {
	unsigned int ver: 8;
	unsigned int slv: 1;
	unsigned int ipi: 1;
	unsigned int sem: 1;
	unsigned int msg: 1;
	unsigned int pw: 1;
	unsigned int dbg: 1;
	unsigned int gfrc: 1;
	unsigned int pad: 1;
	unsigned int num_cores: 6;
	unsigned int pad2: 1;
	unsigned int idu: 1;
	unsigned int pad3: 1;
	unsigned int pw_dom: 1;
	unsigned int pad4: 6;
};

struct of_phandle_iterator {
	const char *cells_name;
	int cell_count;
	const struct device_node *parent;
	const __be32 *list_end;
	const __be32 *phandle_end;
	const __be32 *cur;
	uint32_t cur_count;
	phandle phandle;
	struct device_node *node;
};

struct alias_prop {
	struct list_head link;
	const char *alias;
	struct device_node *np;
	int id;
	char stem[0];
};

struct amba_cs_uci_id {
	unsigned int devarch;
	unsigned int devarch_mask;
	unsigned int devtype;
	void *data;
};

struct amba_device {
	struct device dev;
	struct resource res;
	struct clk *pclk;
	struct device_dma_parameters dma_parms;
	unsigned int periphid;
	unsigned int cid;
	struct amba_cs_uci_id uci;
	unsigned int irq[9];
	char *driver_override;
};

struct of_endpoint {
	unsigned int port;
	unsigned int id;
	const struct device_node *local_node;
};

struct supplier_bindings {
	struct device_node * (*parse_prop)(struct device_node *, const char *, int);
	bool optional;
	bool node_not_dev;
};

struct of_bus {
	void (*count_cells)(const void *, int, int *, int *);
	u64 (*map)(__be32 *, const __be32 *, int, int, int);
	int (*translate)(__be32 *, u64, int);
};

struct of_bus___2;

struct of_pci_range_parser {
	struct device_node *node;
	struct of_bus___2 *bus;
	const __be32 *range;
	const __be32 *end;
	int na;
	int ns;
	int pna;
	bool dma;
};

struct of_bus___2 {
	const char *name;
	const char *addresses;
	int (*match)(struct device_node *);
	void (*count_cells)(struct device_node *, int *, int *);
	u64 (*map)(__be32 *, const __be32 *, int, int, int);
	int (*translate)(__be32 *, u64, int);
	bool has_flags;
	unsigned int (*get_flags)(const __be32 *);
};

struct of_pci_range {
	union {
		u64 pci_addr;
		u64 bus_addr;
	};
	u64 cpu_addr;
	u64 size;
	u32 flags;
};

struct of_intc_desc {
	struct list_head list;
	of_irq_init_cb_t irq_init_cb;
	struct device_node *dev;
	struct device_node *interrupt_parent;
};

struct rmem_assigned_device {
	struct device *dev;
	struct reserved_mem *rmem;
	struct list_head list;
};

struct net_device_devres {
	struct net_device *ndev;
};

struct __kernel_old_timespec {
	__kernel_old_time_t tv_sec;
	long int tv_nsec;
};

struct __kernel_sock_timeval {
	__s64 tv_sec;
	__s64 tv_usec;
};

struct mmsghdr {
	struct user_msghdr msg_hdr;
	unsigned int msg_len;
};

struct scm_timestamping_internal {
	struct timespec64 ts[3];
};

struct flowi_tunnel {
	__be64 tun_id;
};

struct flowi_common {
	int flowic_oif;
	int flowic_iif;
	int flowic_l3mdev;
	__u32 flowic_mark;
	__u8 flowic_tos;
	__u8 flowic_scope;
	__u8 flowic_proto;
	__u8 flowic_flags;
	__u32 flowic_secid;
	kuid_t flowic_uid;
	struct flowi_tunnel flowic_tun_key;
	__u32 flowic_multipath_hash;
};

union flowi_uli {
	struct {
		__be16 dport;
		__be16 sport;
	} ports;
	struct {
		__u8 type;
		__u8 code;
	} icmpt;
	struct {
		__le16 dport;
		__le16 sport;
	} dnports;
	__be32 gre_key;
	struct {
		__u8 type;
	} mht;
};

struct flowi4 {
	struct flowi_common __fl_common;
	__be32 saddr;
	__be32 daddr;
	union flowi_uli uli;
};

struct flowi6 {
	struct flowi_common __fl_common;
	struct in6_addr daddr;
	struct in6_addr saddr;
	__be32 flowlabel;
	union flowi_uli uli;
	__u32 mp_hash;
};

struct flowidn {
	struct flowi_common __fl_common;
	__le16 daddr;
	__le16 saddr;
	union flowi_uli uli;
};

struct flowi {
	union {
		struct flowi_common __fl_common;
		struct flowi4 ip4;
		struct flowi6 ip6;
		struct flowidn dn;
	} u;
};

enum sock_shutdown_cmd {
	SHUT_RD = 0,
	SHUT_WR = 1,
	SHUT_RDWR = 2,
};

struct net_proto_family {
	int family;
	int (*create)(struct net *, struct socket *, int, int);
	struct module *owner;
};

enum {
	SOCK_WAKE_IO = 0,
	SOCK_WAKE_WAITD = 1,
	SOCK_WAKE_SPACE = 2,
	SOCK_WAKE_URG = 3,
};

struct ifconf {
	int ifc_len;
	union {
		char *ifcu_buf;
		struct ifreq *ifcu_req;
	} ifc_ifcu;
};

enum {
	SOF_TIMESTAMPING_TX_HARDWARE = 1,
	SOF_TIMESTAMPING_TX_SOFTWARE = 2,
	SOF_TIMESTAMPING_RX_HARDWARE = 4,
	SOF_TIMESTAMPING_RX_SOFTWARE = 8,
	SOF_TIMESTAMPING_SOFTWARE = 16,
	SOF_TIMESTAMPING_SYS_HARDWARE = 32,
	SOF_TIMESTAMPING_RAW_HARDWARE = 64,
	SOF_TIMESTAMPING_OPT_ID = 128,
	SOF_TIMESTAMPING_TX_SCHED = 256,
	SOF_TIMESTAMPING_TX_ACK = 512,
	SOF_TIMESTAMPING_OPT_CMSG = 1024,
	SOF_TIMESTAMPING_OPT_TSONLY = 2048,
	SOF_TIMESTAMPING_OPT_STATS = 4096,
	SOF_TIMESTAMPING_OPT_PKTINFO = 8192,
	SOF_TIMESTAMPING_OPT_TX_SWHW = 16384,
	SOF_TIMESTAMPING_BIND_PHC = 32768,
	SOF_TIMESTAMPING_LAST = 32768,
	SOF_TIMESTAMPING_MASK = 65535,
};

struct scm_ts_pktinfo {
	__u32 if_index;
	__u32 pkt_length;
	__u32 reserved[2];
};

struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};

struct sock_skb_cb {
	u32 dropcount;
};

typedef u32 compat_caddr_t;

struct compat_ifmap {
	compat_ulong_t mem_start;
	compat_ulong_t mem_end;
	short unsigned int base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct compat_if_settings {
	unsigned int type;
	unsigned int size;
	compat_uptr_t ifs_ifsu;
};

struct compat_ifreq {
	union {
		char ifrn_name[16];
	} ifr_ifrn;
	union {
		struct sockaddr ifru_addr;
		struct sockaddr ifru_dstaddr;
		struct sockaddr ifru_broadaddr;
		struct sockaddr ifru_netmask;
		struct sockaddr ifru_hwaddr;
		short int ifru_flags;
		compat_int_t ifru_ivalue;
		compat_int_t ifru_mtu;
		struct compat_ifmap ifru_map;
		char ifru_slave[16];
		char ifru_newname[16];
		compat_caddr_t ifru_data;
		struct compat_if_settings ifru_settings;
	} ifr_ifru;
};

struct compat_mmsghdr {
	struct compat_msghdr msg_hdr;
	compat_uint_t msg_len;
};

struct ip_options {
	__be32 faddr;
	__be32 nexthop;
	unsigned char optlen;
	unsigned char srr;
	unsigned char rr;
	unsigned char ts;
	unsigned char is_strictroute: 1;
	unsigned char srr_is_hit: 1;
	unsigned char is_changed: 1;
	unsigned char rr_needaddr: 1;
	unsigned char ts_needtime: 1;
	unsigned char ts_needaddr: 1;
	unsigned char router_alert;
	unsigned char cipso;
	unsigned char __pad2;
	unsigned char __data[0];
};

struct ip_options_rcu {
	struct callback_head rcu;
	struct ip_options opt;
};

struct inet_cork {
	unsigned int flags;
	__be32 addr;
	struct ip_options *opt;
	unsigned int fragsize;
	int length;
	struct dst_entry *dst;
	u8 tx_flags;
	__u8 ttl;
	__s16 tos;
	char priority;
	__u16 gso_size;
	u64 transmit_time;
	u32 mark;
};

struct inet_cork_full {
	struct inet_cork base;
	struct flowi fl;
};

struct ip_mc_socklist;

struct inet_sock {
	struct sock sk;
	__be32 inet_saddr;
	__s16 uc_ttl;
	__u16 cmsg_flags;
	struct ip_options_rcu *inet_opt;
	__be16 inet_sport;
	__u16 inet_id;
	__u8 tos;
	__u8 min_ttl;
	__u8 mc_ttl;
	__u8 pmtudisc;
	__u8 recverr: 1;
	__u8 is_icsk: 1;
	__u8 freebind: 1;
	__u8 hdrincl: 1;
	__u8 mc_loop: 1;
	__u8 transparent: 1;
	__u8 mc_all: 1;
	__u8 nodefrag: 1;
	__u8 bind_address_no_port: 1;
	__u8 recverr_rfc4884: 1;
	__u8 defer_connect: 1;
	__u8 rcv_tos;
	__u8 convert_csum;
	int uc_index;
	int mc_index;
	__be32 mc_addr;
	struct ip_mc_socklist *mc_list;
	struct inet_cork_full cork;
};

struct inet_skb_parm {
	int iif;
	struct ip_options opt;
	u16 flags;
	u16 frag_max_size;
};

struct sock_ee_data_rfc4884 {
	__u16 len;
	__u8 flags;
	__u8 reserved;
};

struct sock_extended_err {
	__u32 ee_errno;
	__u8 ee_origin;
	__u8 ee_type;
	__u8 ee_code;
	__u8 ee_pad;
	__u32 ee_info;
	union {
		__u32 ee_data;
		struct sock_ee_data_rfc4884 ee_rfc4884;
	};
};

struct sock_exterr_skb {
	union {
		struct inet_skb_parm h4;
	} header;
	struct sock_extended_err ee;
	u16 addr_offset;
	__be16 port;
	u8 opt_stats: 1;
	u8 unused: 7;
};

struct net_bridge;

struct used_address {
	struct __kernel_sockaddr_storage name;
	unsigned int name_len;
};

struct linger {
	int l_onoff;
	int l_linger;
};

struct cmsghdr {
	__kernel_size_t cmsg_len;
	int cmsg_level;
	int cmsg_type;
};

struct ucred {
	__u32 pid;
	__u32 uid;
	__u32 gid;
};

struct rt6key {
	struct in6_addr addr;
	int plen;
};

struct rtable;

struct fnhe_hash_bucket;

struct fib_nh_common {
	struct net_device *nhc_dev;
	netdevice_tracker nhc_dev_tracker;
	int nhc_oif;
	unsigned char nhc_scope;
	u8 nhc_family;
	u8 nhc_gw_family;
	unsigned char nhc_flags;
	struct lwtunnel_state *nhc_lwtstate;
	union {
		__be32 ipv4;
		struct in6_addr ipv6;
	} nhc_gw;
	int nhc_weight;
	atomic_t nhc_upper_bound;
	struct rtable **nhc_pcpu_rth_output;
	struct rtable *nhc_rth_input;
	struct fnhe_hash_bucket *nhc_exceptions;
};

struct rt6_info;

struct rt6_exception_bucket;

struct fib6_nh {
	struct fib_nh_common nh_common;
	struct rt6_info **rt6i_pcpu;
	struct rt6_exception_bucket *rt6i_exception_bucket;
};

struct fib6_table;

struct fib6_node;

struct dst_metrics;

struct nexthop;

struct fib6_info {
	struct fib6_table *fib6_table;
	struct fib6_info *fib6_next;
	struct fib6_node *fib6_node;
	union {
		struct list_head fib6_siblings;
		struct list_head nh_list;
	};
	unsigned int fib6_nsiblings;
	refcount_t fib6_ref;
	long unsigned int expires;
	struct dst_metrics *fib6_metrics;
	struct rt6key fib6_dst;
	u32 fib6_flags;
	struct rt6key fib6_src;
	struct rt6key fib6_prefsrc;
	u32 fib6_metric;
	u8 fib6_protocol;
	u8 fib6_type;
	u8 offload;
	u8 trap;
	u8 offload_failed;
	u8 should_flush: 1;
	u8 dst_nocount: 1;
	u8 dst_nopolicy: 1;
	u8 fib6_destroying: 1;
	u8 unused: 4;
	struct callback_head rcu;
	struct nexthop *nh;
	struct fib6_nh fib6_nh[0];
};

struct uncached_list;

struct rt6_info {
	struct dst_entry dst;
	struct fib6_info *from;
	int sernum;
	struct rt6key rt6i_dst;
	struct rt6key rt6i_src;
	struct in6_addr rt6i_gateway;
	struct inet6_dev *rt6i_idev;
	u32 rt6i_flags;
	struct list_head rt6i_uncached;
	struct uncached_list *rt6i_uncached_list;
	short unsigned int rt6i_nfheader_len;
};

struct fib6_node {
	struct fib6_node *parent;
	struct fib6_node *left;
	struct fib6_node *right;
	struct fib6_info *leaf;
	__u16 fn_bit;
	__u16 fn_flags;
	int fn_sernum;
	struct fib6_info *rr_ptr;
	struct callback_head rcu;
};

struct fib6_table {
	struct hlist_node tb6_hlist;
	u32 tb6_id;
	spinlock_t tb6_lock;
	struct fib6_node tb6_root;
	struct inet_peer_base tb6_peers;
	unsigned int flags;
	unsigned int fib_seq;
};

typedef union {
	__be32 a4;
	__be32 a6[4];
	struct in6_addr in6;
} xfrm_address_t;

struct xfrm_id {
	xfrm_address_t daddr;
	__be32 spi;
	__u8 proto;
};

struct xfrm_sec_ctx {
	__u8 ctx_doi;
	__u8 ctx_alg;
	__u16 ctx_len;
	__u32 ctx_sid;
	char ctx_str[0];
};

struct xfrm_selector {
	xfrm_address_t daddr;
	xfrm_address_t saddr;
	__be16 dport;
	__be16 dport_mask;
	__be16 sport;
	__be16 sport_mask;
	__u16 family;
	__u8 prefixlen_d;
	__u8 prefixlen_s;
	__u8 proto;
	int ifindex;
	__kernel_uid32_t user;
};

struct xfrm_lifetime_cfg {
	__u64 soft_byte_limit;
	__u64 hard_byte_limit;
	__u64 soft_packet_limit;
	__u64 hard_packet_limit;
	__u64 soft_add_expires_seconds;
	__u64 hard_add_expires_seconds;
	__u64 soft_use_expires_seconds;
	__u64 hard_use_expires_seconds;
};

struct xfrm_lifetime_cur {
	__u64 bytes;
	__u64 packets;
	__u64 add_time;
	__u64 use_time;
};

struct xfrm_replay_state {
	__u32 oseq;
	__u32 seq;
	__u32 bitmap;
};

struct xfrm_replay_state_esn {
	unsigned int bmp_len;
	__u32 oseq;
	__u32 seq;
	__u32 oseq_hi;
	__u32 seq_hi;
	__u32 replay_window;
	__u32 bmp[0];
};

struct xfrm_algo {
	char alg_name[64];
	unsigned int alg_key_len;
	char alg_key[0];
};

struct xfrm_algo_auth {
	char alg_name[64];
	unsigned int alg_key_len;
	unsigned int alg_trunc_len;
	char alg_key[0];
};

struct xfrm_algo_aead {
	char alg_name[64];
	unsigned int alg_key_len;
	unsigned int alg_icv_len;
	char alg_key[0];
};

struct xfrm_stats {
	__u32 replay_window;
	__u32 replay;
	__u32 integrity_failed;
};

struct xfrm_encap_tmpl {
	__u16 encap_type;
	__be16 encap_sport;
	__be16 encap_dport;
	xfrm_address_t encap_oa;
};

struct xfrm_mark {
	__u32 v;
	__u32 m;
};

struct xfrm_address_filter {
	xfrm_address_t saddr;
	xfrm_address_t daddr;
	__u16 family;
	__u8 splen;
	__u8 dplen;
};

struct xfrm_state_walk {
	struct list_head all;
	u8 state;
	u8 dying;
	u8 proto;
	u32 seq;
	struct xfrm_address_filter *filter;
};

enum xfrm_replay_mode {
	XFRM_REPLAY_MODE_LEGACY = 0,
	XFRM_REPLAY_MODE_BMP = 1,
	XFRM_REPLAY_MODE_ESN = 2,
};

struct xfrm_state_offload {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	struct net_device *real_dev;
	long unsigned int offload_handle;
	unsigned int num_exthdrs;
	u8 flags;
};

struct xfrm_mode {
	u8 encap;
	u8 family;
	u8 flags;
};

struct xfrm_type;

struct xfrm_type_offload;

struct xfrm_state {
	possible_net_t xs_net;
	union {
		struct hlist_node gclist;
		struct hlist_node bydst;
	};
	struct hlist_node bysrc;
	struct hlist_node byspi;
	struct hlist_node byseq;
	refcount_t refcnt;
	spinlock_t lock;
	struct xfrm_id id;
	struct xfrm_selector sel;
	struct xfrm_mark mark;
	u32 if_id;
	u32 tfcpad;
	u32 genid;
	struct xfrm_state_walk km;
	struct {
		u32 reqid;
		u8 mode;
		u8 replay_window;
		u8 aalgo;
		u8 ealgo;
		u8 calgo;
		u8 flags;
		u16 family;
		xfrm_address_t saddr;
		int header_len;
		int trailer_len;
		u32 extra_flags;
		struct xfrm_mark smark;
	} props;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_algo_auth *aalg;
	struct xfrm_algo *ealg;
	struct xfrm_algo *calg;
	struct xfrm_algo_aead *aead;
	const char *geniv;
	__be16 new_mapping_sport;
	u32 new_mapping;
	u32 mapping_maxage;
	struct xfrm_encap_tmpl *encap;
	struct sock *encap_sk;
	xfrm_address_t *coaddr;
	struct xfrm_state *tunnel;
	atomic_t tunnel_users;
	struct xfrm_replay_state replay;
	struct xfrm_replay_state_esn *replay_esn;
	struct xfrm_replay_state preplay;
	struct xfrm_replay_state_esn *preplay_esn;
	enum xfrm_replay_mode repl_mode;
	u32 xflags;
	u32 replay_maxage;
	u32 replay_maxdiff;
	struct timer_list rtimer;
	struct xfrm_stats stats;
	struct xfrm_lifetime_cur curlft;
	struct hrtimer mtimer;
	struct xfrm_state_offload xso;
	long int saved_tmo;
	time64_t lastused;
	struct page_frag xfrag;
	const struct xfrm_type *type;
	struct xfrm_mode inner_mode;
	struct xfrm_mode inner_mode_iaf;
	struct xfrm_mode outer_mode;
	const struct xfrm_type_offload *type_offload;
	struct xfrm_sec_ctx *security;
	void *data;
};

struct dst_metrics {
	u32 metrics[17];
	refcount_t refcnt;
};

enum {
	TCPF_ESTABLISHED = 2,
	TCPF_SYN_SENT = 4,
	TCPF_SYN_RECV = 8,
	TCPF_FIN_WAIT1 = 16,
	TCPF_FIN_WAIT2 = 32,
	TCPF_TIME_WAIT = 64,
	TCPF_CLOSE = 128,
	TCPF_CLOSE_WAIT = 256,
	TCPF_LAST_ACK = 512,
	TCPF_LISTEN = 1024,
	TCPF_CLOSING = 2048,
	TCPF_NEW_SYN_RECV = 4096,
};

struct so_timestamping {
	int flags;
	int bind_phc;
};

enum txtime_flags {
	SOF_TXTIME_DEADLINE_MODE = 1,
	SOF_TXTIME_REPORT_ERRORS = 2,
	SOF_TXTIME_FLAGS_LAST = 2,
	SOF_TXTIME_FLAGS_MASK = 3,
};

struct sock_txtime {
	__kernel_clockid_t clockid;
	__u32 flags;
};

struct xfrm_policy_walk_entry {
	struct list_head all;
	u8 dead;
};

struct xfrm_policy_queue {
	struct sk_buff_head hold_queue;
	struct timer_list hold_timer;
	long unsigned int timeout;
};

struct xfrm_tmpl {
	struct xfrm_id id;
	xfrm_address_t saddr;
	short unsigned int encap_family;
	u32 reqid;
	u8 mode;
	u8 share;
	u8 optional;
	u8 allalgs;
	u32 aalgos;
	u32 ealgos;
	u32 calgos;
};

struct xfrm_policy {
	possible_net_t xp_net;
	struct hlist_node bydst;
	struct hlist_node byidx;
	rwlock_t lock;
	refcount_t refcnt;
	u32 pos;
	struct timer_list timer;
	atomic_t genid;
	u32 priority;
	u32 index;
	u32 if_id;
	struct xfrm_mark mark;
	struct xfrm_selector selector;
	struct xfrm_lifetime_cfg lft;
	struct xfrm_lifetime_cur curlft;
	struct xfrm_policy_walk_entry walk;
	struct xfrm_policy_queue polq;
	bool bydst_reinsert;
	u8 type;
	u8 action;
	u8 flags;
	u8 xfrm_nr;
	u16 family;
	struct xfrm_sec_ctx *security;
	struct xfrm_tmpl xfrm_vec[6];
	struct hlist_node bydst_inexact_list;
	struct callback_head rcu;
};

enum sk_pacing {
	SK_PACING_NONE = 0,
	SK_PACING_NEEDED = 1,
	SK_PACING_FQ = 2,
};

struct sockcm_cookie {
	u64 transmit_time;
	u32 mark;
	u16 tsflags;
};

struct fastopen_queue {
	struct request_sock *rskq_rst_head;
	struct request_sock *rskq_rst_tail;
	spinlock_t lock;
	int qlen;
	int max_qlen;
	struct tcp_fastopen_context *ctx;
};

struct request_sock_queue {
	spinlock_t rskq_lock;
	u8 rskq_defer_accept;
	u32 synflood_warned;
	atomic_t qlen;
	atomic_t young;
	struct request_sock *rskq_accept_head;
	struct request_sock *rskq_accept_tail;
	struct fastopen_queue fastopenq;
};

struct inet_connection_sock_af_ops {
	int (*queue_xmit)(struct sock *, struct sk_buff *, struct flowi *);
	void (*send_check)(struct sock *, struct sk_buff *);
	int (*rebuild_header)(struct sock *);
	void (*sk_rx_dst_set)(struct sock *, const struct sk_buff *);
	int (*conn_request)(struct sock *, struct sk_buff *);
	struct sock * (*syn_recv_sock)(const struct sock *, struct sk_buff *, struct request_sock *, struct dst_entry *, struct request_sock *, bool *);
	u16 net_header_len;
	u16 net_frag_header_len;
	u16 sockaddr_len;
	int (*setsockopt)(struct sock *, int, int, sockptr_t, unsigned int);
	int (*getsockopt)(struct sock *, int, int, char *, int *);
	void (*addr2sockaddr)(struct sock *, struct sockaddr *);
	void (*mtu_reduced)(struct sock *);
};

struct inet_bind_bucket;

struct tcp_ulp_ops;

struct inet_connection_sock {
	struct inet_sock icsk_inet;
	struct request_sock_queue icsk_accept_queue;
	struct inet_bind_bucket *icsk_bind_hash;
	long unsigned int icsk_timeout;
	struct timer_list icsk_retransmit_timer;
	struct timer_list icsk_delack_timer;
	__u32 icsk_rto;
	__u32 icsk_rto_min;
	__u32 icsk_delack_max;
	__u32 icsk_pmtu_cookie;
	const struct tcp_congestion_ops *icsk_ca_ops;
	const struct inet_connection_sock_af_ops *icsk_af_ops;
	const struct tcp_ulp_ops *icsk_ulp_ops;
	void *icsk_ulp_data;
	void (*icsk_clean_acked)(struct sock *, u32);
	struct hlist_node icsk_listen_portaddr_node;
	unsigned int (*icsk_sync_mss)(struct sock *, u32);
	__u8 icsk_ca_state: 5;
	__u8 icsk_ca_initialized: 1;
	__u8 icsk_ca_setsockopt: 1;
	__u8 icsk_ca_dst_locked: 1;
	__u8 icsk_retransmits;
	__u8 icsk_pending;
	__u8 icsk_backoff;
	__u8 icsk_syn_retries;
	__u8 icsk_probes_out;
	__u16 icsk_ext_hdr_len;
	struct {
		__u8 pending;
		__u8 quick;
		__u8 pingpong;
		__u8 retry;
		__u32 ato;
		long unsigned int timeout;
		__u32 lrcvtime;
		__u16 last_seg_size;
		__u16 rcv_mss;
	} icsk_ack;
	struct {
		int search_high;
		int search_low;
		u32 probe_size: 31;
		u32 enabled: 1;
		u32 probe_timestamp;
	} icsk_mtup;
	u32 icsk_probes_tstamp;
	u32 icsk_user_timeout;
	u64 icsk_ca_priv[13];
};

struct inet_bind_bucket {
	possible_net_t ib_net;
	int l3mdev;
	short unsigned int port;
	signed char fastreuse;
	signed char fastreuseport;
	kuid_t fastuid;
	__be32 fast_rcv_saddr;
	short unsigned int fast_sk_family;
	bool fast_ipv6_only;
	struct hlist_node node;
	struct hlist_head owners;
};

struct tcp_ulp_ops {
	struct list_head list;
	int (*init)(struct sock *);
	void (*update)(struct sock *, struct proto *, void (*)(struct sock *));
	void (*release)(struct sock *);
	int (*get_info)(const struct sock *, struct sk_buff *);
	size_t (*get_info_size)(const struct sock *);
	void (*clone)(const struct request_sock *, struct sock *, const gfp_t);
	char name[16];
	struct module *owner;
};

struct tcp_fastopen_cookie {
	__le64 val[2];
	s8 len;
	bool exp;
};

struct tcp_sack_block {
	u32 start_seq;
	u32 end_seq;
};

struct tcp_options_received {
	int ts_recent_stamp;
	u32 ts_recent;
	u32 rcv_tsval;
	u32 rcv_tsecr;
	u16 saw_tstamp: 1;
	u16 tstamp_ok: 1;
	u16 dsack: 1;
	u16 wscale_ok: 1;
	u16 sack_ok: 3;
	u16 smc_ok: 1;
	u16 snd_wscale: 4;
	u16 rcv_wscale: 4;
	u8 saw_unknown: 1;
	u8 unused: 7;
	u8 num_sacks;
	u16 user_mss;
	u16 mss_clamp;
};

struct tcp_rack {
	u64 mstamp;
	u32 rtt_us;
	u32 end_seq;
	u32 last_delivered;
	u8 reo_wnd_steps;
	u8 reo_wnd_persist: 5;
	u8 dsack_seen: 1;
	u8 advanced: 1;
};

struct tcp_fastopen_request;

struct tcp_sock {
	struct inet_connection_sock inet_conn;
	u16 tcp_header_len;
	u16 gso_segs;
	__be32 pred_flags;
	u64 bytes_received;
	u32 segs_in;
	u32 data_segs_in;
	u32 rcv_nxt;
	u32 copied_seq;
	u32 rcv_wup;
	u32 snd_nxt;
	u32 segs_out;
	u32 data_segs_out;
	u64 bytes_sent;
	u64 bytes_acked;
	u32 dsack_dups;
	u32 snd_una;
	u32 snd_sml;
	u32 rcv_tstamp;
	u32 lsndtime;
	u32 last_oow_ack_time;
	u32 compressed_ack_rcv_nxt;
	u32 tsoffset;
	struct list_head tsq_node;
	struct list_head tsorted_sent_queue;
	u32 snd_wl1;
	u32 snd_wnd;
	u32 max_window;
	u32 mss_cache;
	u32 window_clamp;
	u32 rcv_ssthresh;
	struct tcp_rack rack;
	u16 advmss;
	u8 compressed_ack;
	u8 dup_ack_counter: 2;
	u8 tlp_retrans: 1;
	u8 unused: 5;
	u32 chrono_start;
	u32 chrono_stat[3];
	u8 chrono_type: 2;
	u8 rate_app_limited: 1;
	u8 fastopen_connect: 1;
	u8 fastopen_no_cookie: 1;
	u8 is_sack_reneg: 1;
	u8 fastopen_client_fail: 2;
	u8 nonagle: 4;
	u8 thin_lto: 1;
	u8 recvmsg_inq: 1;
	u8 repair: 1;
	u8 frto: 1;
	u8 repair_queue;
	u8 save_syn: 2;
	u8 syn_data: 1;
	u8 syn_fastopen: 1;
	u8 syn_fastopen_exp: 1;
	u8 syn_fastopen_ch: 1;
	u8 syn_data_acked: 1;
	u8 is_cwnd_limited: 1;
	u32 tlp_high_seq;
	u32 tcp_tx_delay;
	u64 tcp_wstamp_ns;
	u64 tcp_clock_cache;
	u64 tcp_mstamp;
	u32 srtt_us;
	u32 mdev_us;
	u32 mdev_max_us;
	u32 rttvar_us;
	u32 rtt_seq;
	struct minmax rtt_min;
	u32 packets_out;
	u32 retrans_out;
	u32 max_packets_out;
	u32 max_packets_seq;
	u16 urg_data;
	u8 ecn_flags;
	u8 keepalive_probes;
	u32 reordering;
	u32 reord_seen;
	u32 snd_up;
	struct tcp_options_received rx_opt;
	u32 snd_ssthresh;
	u32 snd_cwnd;
	u32 snd_cwnd_cnt;
	u32 snd_cwnd_clamp;
	u32 snd_cwnd_used;
	u32 snd_cwnd_stamp;
	u32 prior_cwnd;
	u32 prr_delivered;
	u32 prr_out;
	u32 delivered;
	u32 delivered_ce;
	u32 lost;
	u32 app_limited;
	u64 first_tx_mstamp;
	u64 delivered_mstamp;
	u32 rate_delivered;
	u32 rate_interval_us;
	u32 rcv_wnd;
	u32 write_seq;
	u32 notsent_lowat;
	u32 pushed_seq;
	u32 lost_out;
	u32 sacked_out;
	struct hrtimer pacing_timer;
	struct hrtimer compressed_ack_timer;
	struct sk_buff *lost_skb_hint;
	struct sk_buff *retransmit_skb_hint;
	struct rb_root out_of_order_queue;
	struct sk_buff *ooo_last_skb;
	struct tcp_sack_block duplicate_sack[1];
	struct tcp_sack_block selective_acks[4];
	struct tcp_sack_block recv_sack_cache[4];
	struct sk_buff *highest_sack;
	int lost_cnt_hint;
	u32 prior_ssthresh;
	u32 high_seq;
	u32 retrans_stamp;
	u32 undo_marker;
	int undo_retrans;
	u64 bytes_retrans;
	u32 total_retrans;
	u32 urg_seq;
	unsigned int keepalive_time;
	unsigned int keepalive_intvl;
	int linger2;
	u8 bpf_sock_ops_cb_flags;
	u16 timeout_rehash;
	u32 rcv_ooopack;
	u32 rcv_rtt_last_tsecr;
	struct {
		u32 rtt_us;
		u32 seq;
		u64 time;
	} rcv_rtt_est;
	struct {
		u32 space;
		u32 seq;
		u64 time;
	} rcvq_space;
	struct {
		u32 probe_seq_start;
		u32 probe_seq_end;
	} mtu_probe;
	u32 mtu_info;
	struct tcp_fastopen_request *fastopen_req;
	struct request_sock *fastopen_rsk;
	struct saved_syn *saved_syn;
	int: 32;
};

struct tcp_fastopen_request {
	struct tcp_fastopen_cookie cookie;
	struct msghdr *data;
	size_t size;
	int copied;
	struct ubuf_info *uarg;
};

struct fib_nh_exception {
	struct fib_nh_exception *fnhe_next;
	int fnhe_genid;
	__be32 fnhe_daddr;
	u32 fnhe_pmtu;
	bool fnhe_mtu_locked;
	__be32 fnhe_gw;
	long unsigned int fnhe_expires;
	struct rtable *fnhe_rth_input;
	struct rtable *fnhe_rth_output;
	long unsigned int fnhe_stamp;
	struct callback_head rcu;
};

struct rtable {
	struct dst_entry dst;
	int rt_genid;
	unsigned int rt_flags;
	__u16 rt_type;
	__u8 rt_is_input;
	__u8 rt_uses_gateway;
	int rt_iif;
	u8 rt_gw_family;
	union {
		__be32 rt_gw4;
		struct in6_addr rt_gw6;
	};
	u32 rt_mtu_locked: 1;
	u32 rt_pmtu: 31;
	struct list_head rt_uncached;
	struct uncached_list *rt_uncached_list;
};

struct fnhe_hash_bucket {
	struct fib_nh_exception *chain;
};

struct net_protocol {
	int (*early_demux)(struct sk_buff *);
	int (*early_demux_handler)(struct sk_buff *);
	int (*handler)(struct sk_buff *);
	int (*err_handler)(struct sk_buff *, u32);
	unsigned int no_policy: 1;
	unsigned int icmp_strict_tag_validation: 1;
};

struct rt6_exception_bucket {
	struct hlist_head chain;
	int depth;
};

struct xfrm_type {
	struct module *owner;
	u8 proto;
	u8 flags;
	int (*init_state)(struct xfrm_state *);
	void (*destructor)(struct xfrm_state *);
	int (*input)(struct xfrm_state *, struct sk_buff *);
	int (*output)(struct xfrm_state *, struct sk_buff *);
	int (*reject)(struct xfrm_state *, struct sk_buff *, const struct flowi *);
};

struct xfrm_type_offload {
	struct module *owner;
	u8 proto;
	void (*encap)(struct xfrm_state *, struct sk_buff *);
	int (*input_tail)(struct xfrm_state *, struct sk_buff *);
	int (*xmit)(struct xfrm_state *, struct sk_buff *, netdev_features_t);
};

enum {
	SK_MEMINFO_RMEM_ALLOC = 0,
	SK_MEMINFO_RCVBUF = 1,
	SK_MEMINFO_WMEM_ALLOC = 2,
	SK_MEMINFO_SNDBUF = 3,
	SK_MEMINFO_FWD_ALLOC = 4,
	SK_MEMINFO_WMEM_QUEUED = 5,
	SK_MEMINFO_OPTMEM = 6,
	SK_MEMINFO_BACKLOG = 7,
	SK_MEMINFO_DROPS = 8,
	SK_MEMINFO_VARS = 9,
};

enum sknetlink_groups {
	SKNLGRP_NONE = 0,
	SKNLGRP_INET_TCP_DESTROY = 1,
	SKNLGRP_INET_UDP_DESTROY = 2,
	SKNLGRP_INET6_TCP_DESTROY = 3,
	SKNLGRP_INET6_UDP_DESTROY = 4,
	__SKNLGRP_MAX = 5,
};

struct sock_fprog {
	short unsigned int len;
	struct sock_filter *filter;
};

struct inet_request_sock {
	struct request_sock req;
	u16 snd_wscale: 4;
	u16 rcv_wscale: 4;
	u16 tstamp_ok: 1;
	u16 sack_ok: 1;
	u16 wscale_ok: 1;
	u16 ecn_ok: 1;
	u16 acked: 1;
	u16 no_srccheck: 1;
	u16 smc_ok: 1;
	u32 ir_mark;
	union {
		struct ip_options_rcu *ireq_opt;
	};
	int: 32;
};

struct tcp_request_sock_ops;

struct tcp_request_sock {
	struct inet_request_sock req;
	const struct tcp_request_sock_ops *af_specific;
	u64 snt_synack;
	bool tfo_listener;
	bool is_mptcp;
	u32 txhash;
	u32 rcv_isn;
	u32 snt_isn;
	u32 ts_off;
	u32 last_oow_ack_time;
	u32 rcv_nxt;
	u8 syn_tos;
	int: 24;
	int: 32;
};

enum tcp_synack_type {
	TCP_SYNACK_NORMAL = 0,
	TCP_SYNACK_FASTOPEN = 1,
	TCP_SYNACK_COOKIE = 2,
};

struct tcp_request_sock_ops {
	u16 mss_clamp;
	struct dst_entry * (*route_req)(const struct sock *, struct sk_buff *, struct flowi *, struct request_sock *);
	u32 (*init_seq)(const struct sk_buff *);
	u32 (*init_ts_off)(const struct net *, const struct sk_buff *);
	int (*send_synack)(const struct sock *, struct dst_entry *, struct flowi *, struct request_sock *, struct tcp_fastopen_cookie *, enum tcp_synack_type, struct sk_buff *);
};

struct ahash_request;

enum {
	XFRM_POLICY_TYPE_MAIN = 0,
	XFRM_POLICY_TYPE_SUB = 1,
	XFRM_POLICY_TYPE_MAX = 2,
	XFRM_POLICY_TYPE_ANY = 255,
};

enum {
	XFRM_MSG_BASE = 16,
	XFRM_MSG_NEWSA = 16,
	XFRM_MSG_DELSA = 17,
	XFRM_MSG_GETSA = 18,
	XFRM_MSG_NEWPOLICY = 19,
	XFRM_MSG_DELPOLICY = 20,
	XFRM_MSG_GETPOLICY = 21,
	XFRM_MSG_ALLOCSPI = 22,
	XFRM_MSG_ACQUIRE = 23,
	XFRM_MSG_EXPIRE = 24,
	XFRM_MSG_UPDPOLICY = 25,
	XFRM_MSG_UPDSA = 26,
	XFRM_MSG_POLEXPIRE = 27,
	XFRM_MSG_FLUSHSA = 28,
	XFRM_MSG_FLUSHPOLICY = 29,
	XFRM_MSG_NEWAE = 30,
	XFRM_MSG_GETAE = 31,
	XFRM_MSG_REPORT = 32,
	XFRM_MSG_MIGRATE = 33,
	XFRM_MSG_NEWSADINFO = 34,
	XFRM_MSG_GETSADINFO = 35,
	XFRM_MSG_NEWSPDINFO = 36,
	XFRM_MSG_GETSPDINFO = 37,
	XFRM_MSG_MAPPING = 38,
	XFRM_MSG_SETDEFAULT = 39,
	XFRM_MSG_GETDEFAULT = 40,
	__XFRM_MSG_MAX = 41,
};

enum xfrm_attr_type_t {
	XFRMA_UNSPEC = 0,
	XFRMA_ALG_AUTH = 1,
	XFRMA_ALG_CRYPT = 2,
	XFRMA_ALG_COMP = 3,
	XFRMA_ENCAP = 4,
	XFRMA_TMPL = 5,
	XFRMA_SA = 6,
	XFRMA_POLICY = 7,
	XFRMA_SEC_CTX = 8,
	XFRMA_LTIME_VAL = 9,
	XFRMA_REPLAY_VAL = 10,
	XFRMA_REPLAY_THRESH = 11,
	XFRMA_ETIMER_THRESH = 12,
	XFRMA_SRCADDR = 13,
	XFRMA_COADDR = 14,
	XFRMA_LASTUSED = 15,
	XFRMA_POLICY_TYPE = 16,
	XFRMA_MIGRATE = 17,
	XFRMA_ALG_AEAD = 18,
	XFRMA_KMADDRESS = 19,
	XFRMA_ALG_AUTH_TRUNC = 20,
	XFRMA_MARK = 21,
	XFRMA_TFCPAD = 22,
	XFRMA_REPLAY_ESN_VAL = 23,
	XFRMA_SA_EXTRA_FLAGS = 24,
	XFRMA_PROTO = 25,
	XFRMA_ADDRESS_FILTER = 26,
	XFRMA_PAD = 27,
	XFRMA_OFFLOAD_DEV = 28,
	XFRMA_SET_MARK = 29,
	XFRMA_SET_MARK_MASK = 30,
	XFRMA_IF_ID = 31,
	XFRMA_MTIMER_THRESH = 32,
	__XFRMA_MAX = 33,
};

struct ts_state {
	unsigned int offset;
	char cb[48];
};

struct ts_config;

struct ts_ops {
	const char *name;
	struct ts_config * (*init)(const void *, unsigned int, gfp_t, int);
	unsigned int (*find)(struct ts_config *, struct ts_state *);
	void (*destroy)(struct ts_config *);
	void * (*get_pattern)(struct ts_config *);
	unsigned int (*get_pattern_len)(struct ts_config *);
	struct module *owner;
	struct list_head list;
};

struct ts_config {
	struct ts_ops *ops;
	int flags;
	unsigned int (*get_next_block)(unsigned int, const u8 **, struct ts_config *, struct ts_state *);
	void (*finish)(struct ts_config *, struct ts_state *);
};

enum {
	SKB_FCLONE_UNAVAILABLE = 0,
	SKB_FCLONE_ORIG = 1,
	SKB_FCLONE_CLONE = 2,
};

struct sk_buff_fclones {
	struct sk_buff skb1;
	struct sk_buff skb2;
	refcount_t fclone_ref;
	int: 32;
};

struct skb_seq_state {
	__u32 lower_offset;
	__u32 upper_offset;
	__u32 frag_idx;
	__u32 stepped_offset;
	struct sk_buff *root_skb;
	struct sk_buff *cur_skb;
	__u8 *frag_data;
	__u32 frag_off;
};

struct skb_checksum_ops {
	__wsum (*update)(const void *, int, __wsum);
	__wsum (*combine)(__wsum, __wsum, int, int);
};

struct skb_gso_cb {
	union {
		int mac_offset;
		int data_offset;
	};
	int encap_level;
	__wsum csum;
	__u16 csum_start;
};

struct tcphdr {
	__be16 source;
	__be16 dest;
	__be32 seq;
	__be32 ack_seq;
	__u16 res1: 4;
	__u16 doff: 4;
	__u16 fin: 1;
	__u16 syn: 1;
	__u16 rst: 1;
	__u16 psh: 1;
	__u16 ack: 1;
	__u16 urg: 1;
	__u16 ece: 1;
	__u16 cwr: 1;
	__be16 window;
	__sum16 check;
	__be16 urg_ptr;
};

struct udphdr {
	__be16 source;
	__be16 dest;
	__be16 len;
	__sum16 check;
};

struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};

struct ip_auth_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__be16 reserved;
	__be32 spi;
	__be32 seq_no;
	__u8 auth_data[0];
};

struct ipv6_opt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
};

struct ipv6hdr {
	__u8 priority: 4;
	__u8 version: 4;
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

struct frag_hdr {
	__u8 nexthdr;
	__u8 reserved;
	__be16 frag_off;
	__be32 identification;
};

enum {
	SCM_TSTAMP_SND = 0,
	SCM_TSTAMP_SCHED = 1,
	SCM_TSTAMP_ACK = 2,
};

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct vlan_ethhdr {
	union {
		struct {
			unsigned char h_dest[6];
			unsigned char h_source[6];
		};
		struct {
			unsigned char h_dest[6];
			unsigned char h_source[6];
		} addrs;
	};
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct xfrm_offload {
	struct {
		__u32 low;
		__u32 hi;
	} seq;
	__u32 flags;
	__u32 status;
	__u8 proto;
	__u8 inner_ipproto;
};

struct sec_path {
	int len;
	int olen;
	struct xfrm_state *xvec[6];
	struct xfrm_offload ovec[1];
};

struct mpls_shim_hdr {
	__be32 label_stack_entry;
};

struct napi_alloc_cache {
	struct page_frag_cache page;
	unsigned int skb_count;
	void *skb_cache[64];
};

typedef int (*sendmsg_func)(struct sock *, struct msghdr *, struct kvec *, size_t, size_t);

typedef int (*sendpage_func)(struct sock *, struct page *, int, size_t, int);

struct scm_cookie {
	struct pid *pid;
	struct scm_fp_list *fp;
	struct scm_creds creds;
};

struct scm_timestamping {
	struct __kernel_old_timespec ts[3];
};

struct scm_timestamping64 {
	struct __kernel_timespec ts[3];
};

enum {
	TCA_STATS_UNSPEC = 0,
	TCA_STATS_BASIC = 1,
	TCA_STATS_RATE_EST = 2,
	TCA_STATS_QUEUE = 3,
	TCA_STATS_APP = 4,
	TCA_STATS_RATE_EST64 = 5,
	TCA_STATS_PAD = 6,
	TCA_STATS_BASIC_HW = 7,
	TCA_STATS_PKT64 = 8,
	__TCA_STATS_MAX = 9,
};

struct gnet_stats_basic {
	__u64 bytes;
	__u32 packets;
};

struct gnet_stats_rate_est {
	__u32 bps;
	__u32 pps;
};

struct gnet_stats_rate_est64 {
	__u64 bps;
	__u64 pps;
};

struct gnet_estimator {
	signed char interval;
	unsigned char ewma_log;
};

struct net_rate_estimator {
	struct gnet_stats_basic_sync *bstats;
	spinlock_t *stats_lock;
	bool running;
	struct gnet_stats_basic_sync *cpu_bstats;
	u8 ewma_log;
	u8 intvl_log;
	seqcount_t seq;
	u64 last_packets;
	u64 last_bytes;
	u64 avpps;
	u64 avbps;
	long unsigned int next_jiffies;
	struct timer_list timer;
	struct callback_head rcu;
};

enum {
	RTM_BASE = 16,
	RTM_NEWLINK = 16,
	RTM_DELLINK = 17,
	RTM_GETLINK = 18,
	RTM_SETLINK = 19,
	RTM_NEWADDR = 20,
	RTM_DELADDR = 21,
	RTM_GETADDR = 22,
	RTM_NEWROUTE = 24,
	RTM_DELROUTE = 25,
	RTM_GETROUTE = 26,
	RTM_NEWNEIGH = 28,
	RTM_DELNEIGH = 29,
	RTM_GETNEIGH = 30,
	RTM_NEWRULE = 32,
	RTM_DELRULE = 33,
	RTM_GETRULE = 34,
	RTM_NEWQDISC = 36,
	RTM_DELQDISC = 37,
	RTM_GETQDISC = 38,
	RTM_NEWTCLASS = 40,
	RTM_DELTCLASS = 41,
	RTM_GETTCLASS = 42,
	RTM_NEWTFILTER = 44,
	RTM_DELTFILTER = 45,
	RTM_GETTFILTER = 46,
	RTM_NEWACTION = 48,
	RTM_DELACTION = 49,
	RTM_GETACTION = 50,
	RTM_NEWPREFIX = 52,
	RTM_GETMULTICAST = 58,
	RTM_GETANYCAST = 62,
	RTM_NEWNEIGHTBL = 64,
	RTM_GETNEIGHTBL = 66,
	RTM_SETNEIGHTBL = 67,
	RTM_NEWNDUSEROPT = 68,
	RTM_NEWADDRLABEL = 72,
	RTM_DELADDRLABEL = 73,
	RTM_GETADDRLABEL = 74,
	RTM_GETDCB = 78,
	RTM_SETDCB = 79,
	RTM_NEWNETCONF = 80,
	RTM_DELNETCONF = 81,
	RTM_GETNETCONF = 82,
	RTM_NEWMDB = 84,
	RTM_DELMDB = 85,
	RTM_GETMDB = 86,
	RTM_NEWNSID = 88,
	RTM_DELNSID = 89,
	RTM_GETNSID = 90,
	RTM_NEWSTATS = 92,
	RTM_GETSTATS = 94,
	RTM_SETSTATS = 95,
	RTM_NEWCACHEREPORT = 96,
	RTM_NEWCHAIN = 100,
	RTM_DELCHAIN = 101,
	RTM_GETCHAIN = 102,
	RTM_NEWNEXTHOP = 104,
	RTM_DELNEXTHOP = 105,
	RTM_GETNEXTHOP = 106,
	RTM_NEWLINKPROP = 108,
	RTM_DELLINKPROP = 109,
	RTM_GETLINKPROP = 110,
	RTM_NEWVLAN = 112,
	RTM_DELVLAN = 113,
	RTM_GETVLAN = 114,
	RTM_NEWNEXTHOPBUCKET = 116,
	RTM_DELNEXTHOPBUCKET = 117,
	RTM_GETNEXTHOPBUCKET = 118,
	RTM_NEWTUNNEL = 120,
	RTM_DELTUNNEL = 121,
	RTM_GETTUNNEL = 122,
	__RTM_MAX = 123,
};

struct rtgenmsg {
	unsigned char rtgen_family;
};

enum rtnetlink_groups {
	RTNLGRP_NONE = 0,
	RTNLGRP_LINK = 1,
	RTNLGRP_NOTIFY = 2,
	RTNLGRP_NEIGH = 3,
	RTNLGRP_TC = 4,
	RTNLGRP_IPV4_IFADDR = 5,
	RTNLGRP_IPV4_MROUTE = 6,
	RTNLGRP_IPV4_ROUTE = 7,
	RTNLGRP_IPV4_RULE = 8,
	RTNLGRP_IPV6_IFADDR = 9,
	RTNLGRP_IPV6_MROUTE = 10,
	RTNLGRP_IPV6_ROUTE = 11,
	RTNLGRP_IPV6_IFINFO = 12,
	RTNLGRP_DECnet_IFADDR = 13,
	RTNLGRP_NOP2 = 14,
	RTNLGRP_DECnet_ROUTE = 15,
	RTNLGRP_DECnet_RULE = 16,
	RTNLGRP_NOP4 = 17,
	RTNLGRP_IPV6_PREFIX = 18,
	RTNLGRP_IPV6_RULE = 19,
	RTNLGRP_ND_USEROPT = 20,
	RTNLGRP_PHONET_IFADDR = 21,
	RTNLGRP_PHONET_ROUTE = 22,
	RTNLGRP_DCB = 23,
	RTNLGRP_IPV4_NETCONF = 24,
	RTNLGRP_IPV6_NETCONF = 25,
	RTNLGRP_MDB = 26,
	RTNLGRP_MPLS_ROUTE = 27,
	RTNLGRP_NSID = 28,
	RTNLGRP_MPLS_NETCONF = 29,
	RTNLGRP_IPV4_MROUTE_R = 30,
	RTNLGRP_IPV6_MROUTE_R = 31,
	RTNLGRP_NEXTHOP = 32,
	RTNLGRP_BRVLAN = 33,
	RTNLGRP_MCTP_IFADDR = 34,
	RTNLGRP_TUNNEL = 35,
	RTNLGRP_STATS = 36,
	__RTNLGRP_MAX = 37,
};

enum {
	NETNSA_NONE = 0,
	NETNSA_NSID = 1,
	NETNSA_PID = 2,
	NETNSA_FD = 3,
	NETNSA_TARGET_NSID = 4,
	NETNSA_CURRENT_NSID = 5,
	__NETNSA_MAX = 6,
};

struct pcpu_gen_cookie {
	local_t nesting;
	u64 last;
	int: 32;
};

struct gen_cookie {
	struct pcpu_gen_cookie *local;
	int: 32;
	atomic64_t forward_last;
	atomic64_t reverse_last;
};

typedef int (*rtnl_doit_func)(struct sk_buff *, struct nlmsghdr *, struct netlink_ext_ack *);

typedef int (*rtnl_dumpit_func)(struct sk_buff *, struct netlink_callback *);

enum rtnl_link_flags {
	RTNL_FLAG_DOIT_UNLOCKED = 1,
};

struct net_fill_args {
	u32 portid;
	u32 seq;
	int flags;
	int cmd;
	int nsid;
	bool add_ref;
	int ref_nsid;
};

struct rtnl_net_dump_cb {
	struct net *tgt_net;
	struct net *ref_net;
	struct sk_buff *skb;
	struct net_fill_args fillargs;
	int idx;
	int s_idx;
};

enum flow_dissect_ret {
	FLOW_DISSECT_RET_OUT_GOOD = 0,
	FLOW_DISSECT_RET_OUT_BAD = 1,
	FLOW_DISSECT_RET_PROTO_AGAIN = 2,
	FLOW_DISSECT_RET_IPPROTO_AGAIN = 3,
	FLOW_DISSECT_RET_CONTINUE = 4,
};

struct flow_dissector_key_tags {
	u32 flow_label;
};

struct flow_dissector_key_vlan {
	union {
		struct {
			u16 vlan_id: 12;
			u16 vlan_dei: 1;
			u16 vlan_priority: 3;
		};
		__be16 vlan_tci;
	};
	__be16 vlan_tpid;
	__be16 vlan_eth_type;
	u16 padding;
};

struct flow_dissector_mpls_lse {
	u32 mpls_ttl: 8;
	u32 mpls_bos: 1;
	u32 mpls_tc: 3;
	u32 mpls_label: 20;
};

struct flow_dissector_key_mpls {
	struct flow_dissector_mpls_lse ls[7];
	u8 used_lses;
};

struct flow_dissector_key_enc_opts {
	u8 data[255];
	u8 len;
	__be16 dst_opt_type;
};

struct flow_dissector_key_keyid {
	__be32 keyid;
};

struct flow_dissector_key_ipv4_addrs {
	__be32 src;
	__be32 dst;
};

struct flow_dissector_key_ipv6_addrs {
	struct in6_addr src;
	struct in6_addr dst;
};

struct flow_dissector_key_tipc {
	__be32 key;
};

struct flow_dissector_key_addrs {
	union {
		struct flow_dissector_key_ipv4_addrs v4addrs;
		struct flow_dissector_key_ipv6_addrs v6addrs;
		struct flow_dissector_key_tipc tipckey;
	};
};

struct flow_dissector_key_arp {
	__u32 sip;
	__u32 tip;
	__u8 op;
	unsigned char sha[6];
	unsigned char tha[6];
};

struct flow_dissector_key_ports {
	union {
		__be32 ports;
		struct {
			__be16 src;
			__be16 dst;
		};
	};
};

struct flow_dissector_key_icmp {
	struct {
		u8 type;
		u8 code;
	};
	u16 id;
};

struct flow_dissector_key_eth_addrs {
	unsigned char dst[6];
	unsigned char src[6];
};

struct flow_dissector_key_tcp {
	__be16 flags;
};

struct flow_dissector_key_ip {
	__u8 tos;
	__u8 ttl;
};

struct flow_dissector_key_meta {
	int ingress_ifindex;
	u16 ingress_iftype;
};

struct flow_dissector_key_hash {
	u32 hash;
};

struct flow_dissector_key {
	enum flow_dissector_key_id key_id;
	size_t offset;
};

struct flow_keys {
	struct flow_dissector_key_control control;
	struct flow_dissector_key_basic basic;
	struct flow_dissector_key_tags tags;
	struct flow_dissector_key_vlan vlan;
	struct flow_dissector_key_vlan cvlan;
	struct flow_dissector_key_keyid keyid;
	struct flow_dissector_key_ports ports;
	struct flow_dissector_key_icmp icmp;
	struct flow_dissector_key_addrs addrs;
};

struct flow_keys_digest {
	u8 data[16];
};

struct devlink;

enum devlink_port_type {
	DEVLINK_PORT_TYPE_NOTSET = 0,
	DEVLINK_PORT_TYPE_AUTO = 1,
	DEVLINK_PORT_TYPE_ETH = 2,
	DEVLINK_PORT_TYPE_IB = 3,
};

enum devlink_port_flavour {
	DEVLINK_PORT_FLAVOUR_PHYSICAL = 0,
	DEVLINK_PORT_FLAVOUR_CPU = 1,
	DEVLINK_PORT_FLAVOUR_DSA = 2,
	DEVLINK_PORT_FLAVOUR_PCI_PF = 3,
	DEVLINK_PORT_FLAVOUR_PCI_VF = 4,
	DEVLINK_PORT_FLAVOUR_VIRTUAL = 5,
	DEVLINK_PORT_FLAVOUR_UNUSED = 6,
	DEVLINK_PORT_FLAVOUR_PCI_SF = 7,
};

struct devlink_port_phys_attrs {
	u32 port_number;
	u32 split_subport_number;
};

struct devlink_port_pci_pf_attrs {
	u32 controller;
	u16 pf;
	u8 external: 1;
};

struct devlink_port_pci_vf_attrs {
	u32 controller;
	u16 pf;
	u16 vf;
	u8 external: 1;
};

struct devlink_port_pci_sf_attrs {
	u32 controller;
	u32 sf;
	u16 pf;
	u8 external: 1;
};

struct devlink_port_attrs {
	u8 split: 1;
	u8 splittable: 1;
	u32 lanes;
	enum devlink_port_flavour flavour;
	struct netdev_phys_item_id switch_id;
	union {
		struct devlink_port_phys_attrs phys;
		struct devlink_port_pci_pf_attrs pci_pf;
		struct devlink_port_pci_vf_attrs pci_vf;
		struct devlink_port_pci_sf_attrs pci_sf;
	};
};

struct devlink_rate;

struct devlink_port {
	struct list_head list;
	struct list_head param_list;
	struct list_head region_list;
	struct devlink *devlink;
	unsigned int index;
	spinlock_t type_lock;
	enum devlink_port_type type;
	enum devlink_port_type desired_type;
	void *type_dev;
	struct devlink_port_attrs attrs;
	u8 attrs_set: 1;
	u8 switch_port: 1;
	struct delayed_work type_warn_dw;
	struct list_head reporter_list;
	struct mutex reporters_lock;
	struct devlink_rate *devlink_rate;
};

struct ip_tunnel_parm {
	char name[16];
	int link;
	__be16 i_flags;
	__be16 o_flags;
	__be32 i_key;
	__be32 o_key;
	struct iphdr iph;
};

struct mii_bus;

struct mdio_device {
	struct device dev;
	struct mii_bus *bus;
	char modalias[32];
	int (*bus_match)(struct device *, struct device_driver *);
	void (*device_free)(struct mdio_device *);
	void (*device_remove)(struct mdio_device *);
	int addr;
	int flags;
	struct gpio_desc *reset_gpio;
	struct reset_control *reset_ctrl;
	unsigned int reset_assert_delay;
	unsigned int reset_deassert_delay;
};

struct phy_c45_device_ids {
	u32 devices_in_package;
	u32 mmds_present;
	u32 device_ids[32];
};

enum phy_state {
	PHY_DOWN = 0,
	PHY_READY = 1,
	PHY_HALTED = 2,
	PHY_UP = 3,
	PHY_RUNNING = 4,
	PHY_NOLINK = 5,
	PHY_CABLETEST = 6,
};

struct phylink;

struct phy_driver;

struct phy_package_shared;

struct mii_timestamper;

struct phy_device {
	struct mdio_device mdio;
	struct phy_driver *drv;
	u32 phy_id;
	struct phy_c45_device_ids c45_ids;
	unsigned int is_c45: 1;
	unsigned int is_internal: 1;
	unsigned int is_pseudo_fixed_link: 1;
	unsigned int is_gigabit_capable: 1;
	unsigned int has_fixups: 1;
	unsigned int suspended: 1;
	unsigned int suspended_by_mdio_bus: 1;
	unsigned int sysfs_links: 1;
	unsigned int loopback_enabled: 1;
	unsigned int downshifted_rate: 1;
	unsigned int is_on_sfp_module: 1;
	unsigned int mac_managed_pm: 1;
	unsigned int autoneg: 1;
	unsigned int link: 1;
	unsigned int autoneg_complete: 1;
	unsigned int interrupts: 1;
	enum phy_state state;
	u32 dev_flags;
	phy_interface_t interface;
	int speed;
	int duplex;
	int port;
	int pause;
	int asym_pause;
	u8 master_slave_get;
	u8 master_slave_set;
	u8 master_slave_state;
	long unsigned int supported[3];
	long unsigned int advertising[3];
	long unsigned int lp_advertising[3];
	long unsigned int adv_old[3];
	u32 eee_broken_modes;
	int irq;
	void *priv;
	struct phy_package_shared *shared;
	struct sk_buff *skb;
	void *ehdr;
	struct nlattr *nest;
	struct delayed_work state_queue;
	struct mutex lock;
	bool sfp_bus_attached;
	struct sfp_bus *sfp_bus;
	struct phylink *phylink;
	struct net_device *attached_dev;
	struct mii_timestamper *mii_ts;
	u8 mdix;
	u8 mdix_ctrl;
	void (*phy_link_change)(struct phy_device *, bool);
	void (*adjust_link)(struct net_device *);
};

union tcp_word_hdr {
	struct tcphdr hdr;
	__be32 words[5];
};

enum bpf_ret_code {
	BPF_OK = 0,
	BPF_DROP = 2,
	BPF_REDIRECT = 7,
	BPF_LWT_REROUTE = 128,
};

enum {
	BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG = 1,
	BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL = 2,
	BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP = 4,
};

struct ip_tunnel_key {
	__be64 tun_id;
	union {
		struct {
			__be32 src;
			__be32 dst;
		} ipv4;
		struct {
			struct in6_addr src;
			struct in6_addr dst;
		} ipv6;
	} u;
	__be16 tun_flags;
	u8 tos;
	u8 ttl;
	__be32 label;
	__be16 tp_src;
	__be16 tp_dst;
};

struct ip_tunnel_info {
	struct ip_tunnel_key key;
	u8 options_len;
	u8 mode;
};

struct phy_tdr_config {
	u32 first;
	u32 last;
	u32 step;
	s8 pair;
};

struct mdio_bus_stats {
	u64_stats_t transfers;
	u64_stats_t errors;
	u64_stats_t writes;
	u64_stats_t reads;
	struct u64_stats_sync syncp;
};

struct mii_bus {
	struct module *owner;
	const char *name;
	char id[61];
	void *priv;
	int (*read)(struct mii_bus *, int, int);
	int (*write)(struct mii_bus *, int, int, u16);
	int (*reset)(struct mii_bus *);
	struct mdio_bus_stats stats[32];
	struct mutex mdio_lock;
	struct device *parent;
	enum {
		MDIOBUS_ALLOCATED = 1,
		MDIOBUS_REGISTERED = 2,
		MDIOBUS_UNREGISTERED = 3,
		MDIOBUS_RELEASED = 4,
	} state;
	struct device dev;
	struct mdio_device *mdio_map[32];
	u32 phy_mask;
	u32 phy_ignore_ta_mask;
	int irq[32];
	int reset_delay_us;
	int reset_post_delay_us;
	struct gpio_desc *reset_gpiod;
	enum {
		MDIOBUS_NO_CAP = 0,
		MDIOBUS_C22 = 1,
		MDIOBUS_C45 = 2,
		MDIOBUS_C22_C45 = 3,
	} probe_capabilities;
	struct mutex shared_lock;
	struct phy_package_shared *shared[32];
};

struct mdio_driver_common {
	struct device_driver driver;
	int flags;
};

struct mii_timestamper {
	bool (*rxtstamp)(struct mii_timestamper *, struct sk_buff *, int);
	void (*txtstamp)(struct mii_timestamper *, struct sk_buff *, int);
	int (*hwtstamp)(struct mii_timestamper *, struct ifreq *);
	void (*link_state)(struct mii_timestamper *, struct phy_device *);
	int (*ts_info)(struct mii_timestamper *, struct ethtool_ts_info *);
	struct device *device;
};

struct phy_package_shared {
	int addr;
	refcount_t refcnt;
	long unsigned int flags;
	size_t priv_size;
	void *priv;
};

struct phy_driver {
	struct mdio_driver_common mdiodrv;
	u32 phy_id;
	char *name;
	u32 phy_id_mask;
	const long unsigned int * const features;
	u32 flags;
	const void *driver_data;
	int (*soft_reset)(struct phy_device *);
	int (*config_init)(struct phy_device *);
	int (*probe)(struct phy_device *);
	int (*get_features)(struct phy_device *);
	int (*suspend)(struct phy_device *);
	int (*resume)(struct phy_device *);
	int (*config_aneg)(struct phy_device *);
	int (*aneg_done)(struct phy_device *);
	int (*read_status)(struct phy_device *);
	int (*config_intr)(struct phy_device *);
	irqreturn_t (*handle_interrupt)(struct phy_device *);
	void (*remove)(struct phy_device *);
	int (*match_phy_device)(struct phy_device *);
	int (*set_wol)(struct phy_device *, struct ethtool_wolinfo *);
	void (*get_wol)(struct phy_device *, struct ethtool_wolinfo *);
	void (*link_change_notify)(struct phy_device *);
	int (*read_mmd)(struct phy_device *, int, u16);
	int (*write_mmd)(struct phy_device *, int, u16, u16);
	int (*read_page)(struct phy_device *);
	int (*write_page)(struct phy_device *, int);
	int (*module_info)(struct phy_device *, struct ethtool_modinfo *);
	int (*module_eeprom)(struct phy_device *, struct ethtool_eeprom *, u8 *);
	int (*cable_test_start)(struct phy_device *);
	int (*cable_test_tdr_start)(struct phy_device *, const struct phy_tdr_config *);
	int (*cable_test_get_status)(struct phy_device *, bool *);
	int (*get_sset_count)(struct phy_device *);
	void (*get_strings)(struct phy_device *, u8 *);
	void (*get_stats)(struct phy_device *, struct ethtool_stats *, u64 *);
	int (*get_tunable)(struct phy_device *, struct ethtool_tunable *, void *);
	int (*set_tunable)(struct phy_device *, struct ethtool_tunable *, const void *);
	int (*set_loopback)(struct phy_device *, bool);
	int (*get_sqi)(struct phy_device *);
	int (*get_sqi_max)(struct phy_device *);
};

enum devlink_rate_type {
	DEVLINK_RATE_TYPE_LEAF = 0,
	DEVLINK_RATE_TYPE_NODE = 1,
};

struct devlink_rate {
	struct list_head list;
	enum devlink_rate_type type;
	struct devlink *devlink;
	void *priv;
	u64 tx_share;
	u64 tx_max;
	struct devlink_rate *parent;
	union {
		struct devlink_port *devlink_port;
		struct {
			char *name;
			refcount_t refcnt;
		};
	};
};

enum lwtunnel_encap_types {
	LWTUNNEL_ENCAP_NONE = 0,
	LWTUNNEL_ENCAP_MPLS = 1,
	LWTUNNEL_ENCAP_IP = 2,
	LWTUNNEL_ENCAP_ILA = 3,
	LWTUNNEL_ENCAP_IP6 = 4,
	LWTUNNEL_ENCAP_SEG6 = 5,
	LWTUNNEL_ENCAP_BPF = 6,
	LWTUNNEL_ENCAP_SEG6_LOCAL = 7,
	LWTUNNEL_ENCAP_RPL = 8,
	LWTUNNEL_ENCAP_IOAM6 = 9,
	__LWTUNNEL_ENCAP_MAX = 10,
};

struct arphdr {
	__be16 ar_hrd;
	__be16 ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	__be16 ar_op;
};

enum metadata_type {
	METADATA_IP_TUNNEL = 0,
	METADATA_HW_PORT_MUX = 1,
};

struct hw_port_info {
	struct net_device *lower_dev;
	u32 port_id;
};

struct metadata_dst {
	struct dst_entry dst;
	enum metadata_type type;
	union {
		struct ip_tunnel_info tun_info;
		struct hw_port_info port_info;
	} u;
};

struct gre_base_hdr {
	__be16 flags;
	__be16 protocol;
};

struct gre_full_hdr {
	struct gre_base_hdr fixed_header;
	__be16 csum;
	__be16 reserved1;
	__be32 key;
	__be32 seq;
};

struct pptp_gre_header {
	struct gre_base_hdr gre_hd;
	__be16 payload_len;
	__be16 call_id;
	__be32 seq;
	__be32 ack;
};

struct tipc_basic_hdr {
	__be32 w[4];
};

struct icmphdr {
	__u8 type;
	__u8 code;
	__sum16 checksum;
	union {
		struct {
			__be16 id;
			__be16 sequence;
		} echo;
		__be32 gateway;
		struct {
			__be16 __unused;
			__be16 mtu;
		} frag;
		__u8 reserved[4];
	} un;
};

enum sctp_msg_flags {
	MSG_NOTIFICATION = 32768,
};

enum dccp_state {
	DCCP_OPEN = 1,
	DCCP_REQUESTING = 2,
	DCCP_LISTEN = 10,
	DCCP_RESPOND = 3,
	DCCP_ACTIVE_CLOSEREQ = 4,
	DCCP_PASSIVE_CLOSE = 8,
	DCCP_CLOSING = 11,
	DCCP_TIME_WAIT = 6,
	DCCP_CLOSED = 7,
	DCCP_NEW_SYN_RECV = 12,
	DCCP_PARTOPEN = 13,
	DCCP_PASSIVE_CLOSEREQ = 14,
	DCCP_MAX_STATES = 15,
};

enum l2tp_debug_flags {
	L2TP_MSG_DEBUG = 1,
	L2TP_MSG_CONTROL = 2,
	L2TP_MSG_SEQ = 4,
	L2TP_MSG_DATA = 8,
};

struct pppoe_tag {
	__be16 tag_type;
	__be16 tag_len;
	char tag_data[0];
};

struct pppoe_hdr {
	__u8 type: 4;
	__u8 ver: 4;
	__u8 code;
	__be16 sid;
	__be16 length;
	struct pppoe_tag tag[0];
};

struct hsr_tag {
	__be16 path_and_LSDU_size;
	__be16 sequence_nr;
	__be16 encap_proto;
};

struct mpls_label {
	__be32 entry;
};

struct clock_identity {
	u8 id[8];
};

struct port_identity {
	struct clock_identity clock_identity;
	__be16 port_number;
};

struct ptp_header {
	u8 tsmt;
	u8 ver;
	__be16 message_length;
	u8 domain_number;
	u8 reserved1;
	u8 flag_field[2];
	__be64 correction;
	__be32 reserved2;
	struct port_identity source_port_identity;
	__be16 sequence_id;
	u8 control;
	u8 log_message_interval;
};

enum batadv_packettype {
	BATADV_IV_OGM = 0,
	BATADV_BCAST = 1,
	BATADV_CODED = 2,
	BATADV_ELP = 3,
	BATADV_OGM2 = 4,
	BATADV_UNICAST = 64,
	BATADV_UNICAST_FRAG = 65,
	BATADV_UNICAST_4ADDR = 66,
	BATADV_ICMP = 67,
	BATADV_UNICAST_TVLV = 68,
};

struct batadv_unicast_packet {
	__u8 packet_type;
	__u8 version;
	__u8 ttl;
	__u8 ttvn;
	__u8 dest[6];
};

struct _flow_keys_digest_data {
	__be16 n_proto;
	u8 ip_proto;
	u8 padding;
	__be32 ports;
	__be32 src;
	__be32 dst;
};

struct qdisc_walker {
	int stop;
	int skip;
	int count;
	int (*fn)(struct Qdisc *, long unsigned int, struct qdisc_walker *);
};

struct xfrm_dst {
	union {
		struct dst_entry dst;
		struct rtable rt;
		struct rt6_info rt6;
	} u;
	struct dst_entry *route;
	struct dst_entry *child;
	struct dst_entry *path;
	struct xfrm_policy *pols[2];
	int num_pols;
	int num_xfrms;
	u32 xfrm_genid;
	u32 policy_genid;
	u32 route_mtu_cached;
	u32 child_mtu_cached;
	u32 route_cookie;
	u32 path_cookie;
};

enum {
	IF_OPER_UNKNOWN = 0,
	IF_OPER_NOTPRESENT = 1,
	IF_OPER_DOWN = 2,
	IF_OPER_LOWERLAYERDOWN = 3,
	IF_OPER_TESTING = 4,
	IF_OPER_DORMANT = 5,
	IF_OPER_UP = 6,
};

struct ifbond {
	__s32 bond_mode;
	__s32 num_slaves;
	__s32 miimon;
};

typedef struct ifbond ifbond;

struct ifslave {
	__s32 slave_id;
	char slave_name[16];
	__s8 link;
	__s8 state;
	__u32 link_failure_count;
};

typedef struct ifslave ifslave;

enum {
	NAPIF_STATE_SCHED = 1,
	NAPIF_STATE_MISSED = 2,
	NAPIF_STATE_DISABLE = 4,
	NAPIF_STATE_NPSVC = 8,
	NAPIF_STATE_LISTED = 16,
	NAPIF_STATE_NO_BUSY_POLL = 32,
	NAPIF_STATE_IN_BUSY_POLL = 64,
	NAPIF_STATE_PREFER_BUSY_POLL = 128,
	NAPIF_STATE_THREADED = 256,
	NAPIF_STATE_SCHED_THREADED = 512,
};

struct net_device_path_stack {
	int num_paths;
	struct net_device_path path[5];
};

struct bpf_xdp_link {
	struct bpf_link link;
	struct net_device *dev;
	int flags;
};

struct netdev_net_notifier {
	struct list_head list;
	struct notifier_block *nb;
};

struct packet_type {
	__be16 type;
	bool ignore_outgoing;
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	int (*func)(struct sk_buff *, struct net_device *, struct packet_type *, struct net_device *);
	void (*list_func)(struct list_head *, struct packet_type *, struct net_device *);
	bool (*id_match)(struct packet_type *, struct sock *);
	struct net *af_packet_net;
	void *af_packet_priv;
	struct list_head list;
};

struct netdev_notifier_info_ext {
	struct netdev_notifier_info info;
	union {
		u32 mtu;
	} ext;
};

struct netdev_notifier_change_info {
	struct netdev_notifier_info info;
	unsigned int flags_changed;
};

struct netdev_notifier_changeupper_info {
	struct netdev_notifier_info info;
	struct net_device *upper_dev;
	bool master;
	bool linking;
	void *upper_info;
};

struct netdev_notifier_changelowerstate_info {
	struct netdev_notifier_info info;
	void *lower_state_info;
};

struct netdev_notifier_pre_changeaddr_info {
	struct netdev_notifier_info info;
	const unsigned char *dev_addr;
};

enum netdev_offload_xstats_type {
	NETDEV_OFFLOAD_XSTATS_TYPE_L3 = 1,
};

struct netdev_notifier_offload_xstats_rd {
	struct rtnl_hw_stats64 stats;
	bool used;
};

struct netdev_notifier_offload_xstats_ru {
	bool used;
};

struct netdev_notifier_offload_xstats_info {
	struct netdev_notifier_info info;
	enum netdev_offload_xstats_type type;
	union {
		struct netdev_notifier_offload_xstats_rd *report_delta;
		struct netdev_notifier_offload_xstats_ru *report_used;
	};
};

typedef int (*bpf_op_t)(struct net_device *, struct netdev_bpf *);

enum {
	NESTED_SYNC_IMM_BIT = 0,
	NESTED_SYNC_TODO_BIT = 1,
};

struct netdev_nested_priv {
	unsigned char flags;
	void *data;
};

struct netdev_bonding_info {
	ifslave slave;
	ifbond master;
};

struct netdev_notifier_bonding_info {
	struct netdev_notifier_info info;
	struct netdev_bonding_info bonding_info;
};

enum qdisc_state_t {
	__QDISC_STATE_SCHED = 0,
	__QDISC_STATE_DEACTIVATED = 1,
	__QDISC_STATE_MISSED = 2,
	__QDISC_STATE_DRAINING = 3,
};

enum qdisc_state2_t {
	__QDISC_STATE2_RUNNING = 0,
};

struct tcf_walker {
	int stop;
	int skip;
	int count;
	bool nonempty;
	long unsigned int cookie;
	int (*fn)(struct tcf_proto *, void *, struct tcf_walker *);
};

struct udp_hslot;

struct udp_table {
	struct udp_hslot *hash;
	struct udp_hslot *hash2;
	unsigned int mask;
	unsigned int log;
};

struct udp_hslot {
	struct hlist_head head;
	int count;
	spinlock_t lock;
};

struct udp_tunnel_info {
	short unsigned int type;
	sa_family_t sa_family;
	__be16 port;
	u8 hw_priv;
};

struct udp_tunnel_nic_shared {
	struct udp_tunnel_nic *udp_tunnel_nic_info;
	struct list_head devices;
};

struct dev_kfree_skb_cb {
	enum skb_free_reason reason;
};

struct netdev_adjacent {
	struct net_device *dev;
	netdevice_tracker dev_tracker;
	bool master;
	bool ignore;
	u16 ref_nr;
	void *private;
	struct list_head list;
	struct callback_head rcu;
};

enum {
	NDA_UNSPEC = 0,
	NDA_DST = 1,
	NDA_LLADDR = 2,
	NDA_CACHEINFO = 3,
	NDA_PROBES = 4,
	NDA_VLAN = 5,
	NDA_PORT = 6,
	NDA_VNI = 7,
	NDA_IFINDEX = 8,
	NDA_MASTER = 9,
	NDA_LINK_NETNSID = 10,
	NDA_SRC_VNI = 11,
	NDA_PROTOCOL = 12,
	NDA_NH_ID = 13,
	NDA_FDB_EXT_ATTRS = 14,
	NDA_FLAGS_EXT = 15,
	__NDA_MAX = 16,
};

struct nda_cacheinfo {
	__u32 ndm_confirmed;
	__u32 ndm_used;
	__u32 ndm_updated;
	__u32 ndm_refcnt;
};

struct ndt_stats {
	__u64 ndts_allocs;
	__u64 ndts_destroys;
	__u64 ndts_hash_grows;
	__u64 ndts_res_failed;
	__u64 ndts_lookups;
	__u64 ndts_hits;
	__u64 ndts_rcv_probes_mcast;
	__u64 ndts_rcv_probes_ucast;
	__u64 ndts_periodic_gc_runs;
	__u64 ndts_forced_gc_runs;
	__u64 ndts_table_fulls;
};

enum {
	NDTPA_UNSPEC = 0,
	NDTPA_IFINDEX = 1,
	NDTPA_REFCNT = 2,
	NDTPA_REACHABLE_TIME = 3,
	NDTPA_BASE_REACHABLE_TIME = 4,
	NDTPA_RETRANS_TIME = 5,
	NDTPA_GC_STALETIME = 6,
	NDTPA_DELAY_PROBE_TIME = 7,
	NDTPA_QUEUE_LEN = 8,
	NDTPA_APP_PROBES = 9,
	NDTPA_UCAST_PROBES = 10,
	NDTPA_MCAST_PROBES = 11,
	NDTPA_ANYCAST_DELAY = 12,
	NDTPA_PROXY_DELAY = 13,
	NDTPA_PROXY_QLEN = 14,
	NDTPA_LOCKTIME = 15,
	NDTPA_QUEUE_LENBYTES = 16,
	NDTPA_MCAST_REPROBES = 17,
	NDTPA_PAD = 18,
	__NDTPA_MAX = 19,
};

struct ndtmsg {
	__u8 ndtm_family;
	__u8 ndtm_pad1;
	__u16 ndtm_pad2;
};

struct ndt_config {
	__u16 ndtc_key_len;
	__u16 ndtc_entry_size;
	__u32 ndtc_entries;
	__u32 ndtc_last_flush;
	__u32 ndtc_last_rand;
	__u32 ndtc_hash_rnd;
	__u32 ndtc_hash_mask;
	__u32 ndtc_hash_chain_gc;
	__u32 ndtc_proxy_qlen;
};

enum {
	NDTA_UNSPEC = 0,
	NDTA_NAME = 1,
	NDTA_THRESH1 = 2,
	NDTA_THRESH2 = 3,
	NDTA_THRESH3 = 4,
	NDTA_CONFIG = 5,
	NDTA_PARMS = 6,
	NDTA_STATS = 7,
	NDTA_GC_INTERVAL = 8,
	NDTA_PAD = 9,
	__NDTA_MAX = 10,
};

enum {
	RTN_UNSPEC = 0,
	RTN_UNICAST = 1,
	RTN_LOCAL = 2,
	RTN_BROADCAST = 3,
	RTN_ANYCAST = 4,
	RTN_MULTICAST = 5,
	RTN_BLACKHOLE = 6,
	RTN_UNREACHABLE = 7,
	RTN_PROHIBIT = 8,
	RTN_THROW = 9,
	RTN_NAT = 10,
	RTN_XRESOLVE = 11,
	__RTN_MAX = 12,
};

enum {
	NEIGH_ARP_TABLE = 0,
	NEIGH_ND_TABLE = 1,
	NEIGH_DN_TABLE = 2,
	NEIGH_NR_TABLES = 3,
	NEIGH_LINK_TABLE = 3,
};

struct neigh_seq_state {
	struct seq_net_private p;
	struct neigh_table *tbl;
	struct neigh_hash_table *nht;
	void * (*neigh_sub_iter)(struct neigh_seq_state *, struct neighbour *, loff_t *);
	unsigned int bucket;
	unsigned int flags;
};

struct neighbour_cb {
	long unsigned int sched_next;
	unsigned int flags;
};

enum netevent_notif_type {
	NETEVENT_NEIGH_UPDATE = 1,
	NETEVENT_REDIRECT = 2,
	NETEVENT_DELAY_PROBE_TIME_UPDATE = 3,
	NETEVENT_IPV4_MPATH_HASH_UPDATE = 4,
	NETEVENT_IPV6_MPATH_HASH_UPDATE = 5,
	NETEVENT_IPV4_FWD_UPDATE_PRIORITY_UPDATE = 6,
};

struct neigh_dump_filter {
	int master_idx;
	int dev_idx;
};

struct neigh_sysctl_table {
	struct ctl_table_header *sysctl_header;
	struct ctl_table neigh_vars[21];
};

struct netlink_dump_control {
	int (*start)(struct netlink_callback *);
	int (*dump)(struct sk_buff *, struct netlink_callback *);
	int (*done)(struct netlink_callback *);
	void *data;
	struct module *module;
	u32 min_dump_alloc;
};

struct rtnl_link_stats {
	__u32 rx_packets;
	__u32 tx_packets;
	__u32 rx_bytes;
	__u32 tx_bytes;
	__u32 rx_errors;
	__u32 tx_errors;
	__u32 rx_dropped;
	__u32 tx_dropped;
	__u32 multicast;
	__u32 collisions;
	__u32 rx_length_errors;
	__u32 rx_over_errors;
	__u32 rx_crc_errors;
	__u32 rx_frame_errors;
	__u32 rx_fifo_errors;
	__u32 rx_missed_errors;
	__u32 tx_aborted_errors;
	__u32 tx_carrier_errors;
	__u32 tx_fifo_errors;
	__u32 tx_heartbeat_errors;
	__u32 tx_window_errors;
	__u32 rx_compressed;
	__u32 tx_compressed;
	__u32 rx_nohandler;
};

struct rtnl_link_ifmap {
	__u64 mem_start;
	__u64 mem_end;
	__u64 base_addr;
	__u16 irq;
	__u8 dma;
	__u8 port;
};

enum {
	IFLA_UNSPEC = 0,
	IFLA_ADDRESS = 1,
	IFLA_BROADCAST = 2,
	IFLA_IFNAME = 3,
	IFLA_MTU = 4,
	IFLA_LINK = 5,
	IFLA_QDISC = 6,
	IFLA_STATS = 7,
	IFLA_COST = 8,
	IFLA_PRIORITY = 9,
	IFLA_MASTER = 10,
	IFLA_WIRELESS = 11,
	IFLA_PROTINFO = 12,
	IFLA_TXQLEN = 13,
	IFLA_MAP = 14,
	IFLA_WEIGHT = 15,
	IFLA_OPERSTATE = 16,
	IFLA_LINKMODE = 17,
	IFLA_LINKINFO = 18,
	IFLA_NET_NS_PID = 19,
	IFLA_IFALIAS = 20,
	IFLA_NUM_VF = 21,
	IFLA_VFINFO_LIST = 22,
	IFLA_STATS64 = 23,
	IFLA_VF_PORTS = 24,
	IFLA_PORT_SELF = 25,
	IFLA_AF_SPEC = 26,
	IFLA_GROUP = 27,
	IFLA_NET_NS_FD = 28,
	IFLA_EXT_MASK = 29,
	IFLA_PROMISCUITY = 30,
	IFLA_NUM_TX_QUEUES = 31,
	IFLA_NUM_RX_QUEUES = 32,
	IFLA_CARRIER = 33,
	IFLA_PHYS_PORT_ID = 34,
	IFLA_CARRIER_CHANGES = 35,
	IFLA_PHYS_SWITCH_ID = 36,
	IFLA_LINK_NETNSID = 37,
	IFLA_PHYS_PORT_NAME = 38,
	IFLA_PROTO_DOWN = 39,
	IFLA_GSO_MAX_SEGS = 40,
	IFLA_GSO_MAX_SIZE = 41,
	IFLA_PAD = 42,
	IFLA_XDP = 43,
	IFLA_EVENT = 44,
	IFLA_NEW_NETNSID = 45,
	IFLA_IF_NETNSID = 46,
	IFLA_TARGET_NETNSID = 46,
	IFLA_CARRIER_UP_COUNT = 47,
	IFLA_CARRIER_DOWN_COUNT = 48,
	IFLA_NEW_IFINDEX = 49,
	IFLA_MIN_MTU = 50,
	IFLA_MAX_MTU = 51,
	IFLA_PROP_LIST = 52,
	IFLA_ALT_IFNAME = 53,
	IFLA_PERM_ADDRESS = 54,
	IFLA_PROTO_DOWN_REASON = 55,
	IFLA_PARENT_DEV_NAME = 56,
	IFLA_PARENT_DEV_BUS_NAME = 57,
	IFLA_GRO_MAX_SIZE = 58,
	__IFLA_MAX = 59,
};

enum {
	IFLA_PROTO_DOWN_REASON_UNSPEC = 0,
	IFLA_PROTO_DOWN_REASON_MASK = 1,
	IFLA_PROTO_DOWN_REASON_VALUE = 2,
	__IFLA_PROTO_DOWN_REASON_CNT = 3,
	IFLA_PROTO_DOWN_REASON_MAX = 2,
};

enum {
	IFLA_BRPORT_UNSPEC = 0,
	IFLA_BRPORT_STATE = 1,
	IFLA_BRPORT_PRIORITY = 2,
	IFLA_BRPORT_COST = 3,
	IFLA_BRPORT_MODE = 4,
	IFLA_BRPORT_GUARD = 5,
	IFLA_BRPORT_PROTECT = 6,
	IFLA_BRPORT_FAST_LEAVE = 7,
	IFLA_BRPORT_LEARNING = 8,
	IFLA_BRPORT_UNICAST_FLOOD = 9,
	IFLA_BRPORT_PROXYARP = 10,
	IFLA_BRPORT_LEARNING_SYNC = 11,
	IFLA_BRPORT_PROXYARP_WIFI = 12,
	IFLA_BRPORT_ROOT_ID = 13,
	IFLA_BRPORT_BRIDGE_ID = 14,
	IFLA_BRPORT_DESIGNATED_PORT = 15,
	IFLA_BRPORT_DESIGNATED_COST = 16,
	IFLA_BRPORT_ID = 17,
	IFLA_BRPORT_NO = 18,
	IFLA_BRPORT_TOPOLOGY_CHANGE_ACK = 19,
	IFLA_BRPORT_CONFIG_PENDING = 20,
	IFLA_BRPORT_MESSAGE_AGE_TIMER = 21,
	IFLA_BRPORT_FORWARD_DELAY_TIMER = 22,
	IFLA_BRPORT_HOLD_TIMER = 23,
	IFLA_BRPORT_FLUSH = 24,
	IFLA_BRPORT_MULTICAST_ROUTER = 25,
	IFLA_BRPORT_PAD = 26,
	IFLA_BRPORT_MCAST_FLOOD = 27,
	IFLA_BRPORT_MCAST_TO_UCAST = 28,
	IFLA_BRPORT_VLAN_TUNNEL = 29,
	IFLA_BRPORT_BCAST_FLOOD = 30,
	IFLA_BRPORT_GROUP_FWD_MASK = 31,
	IFLA_BRPORT_NEIGH_SUPPRESS = 32,
	IFLA_BRPORT_ISOLATED = 33,
	IFLA_BRPORT_BACKUP_PORT = 34,
	IFLA_BRPORT_MRP_RING_OPEN = 35,
	IFLA_BRPORT_MRP_IN_OPEN = 36,
	IFLA_BRPORT_MCAST_EHT_HOSTS_LIMIT = 37,
	IFLA_BRPORT_MCAST_EHT_HOSTS_CNT = 38,
	IFLA_BRPORT_LOCKED = 39,
	__IFLA_BRPORT_MAX = 40,
};

enum {
	IFLA_INFO_UNSPEC = 0,
	IFLA_INFO_KIND = 1,
	IFLA_INFO_DATA = 2,
	IFLA_INFO_XSTATS = 3,
	IFLA_INFO_SLAVE_KIND = 4,
	IFLA_INFO_SLAVE_DATA = 5,
	__IFLA_INFO_MAX = 6,
};

enum {
	IFLA_VF_INFO_UNSPEC = 0,
	IFLA_VF_INFO = 1,
	__IFLA_VF_INFO_MAX = 2,
};

enum {
	IFLA_VF_UNSPEC = 0,
	IFLA_VF_MAC = 1,
	IFLA_VF_VLAN = 2,
	IFLA_VF_TX_RATE = 3,
	IFLA_VF_SPOOFCHK = 4,
	IFLA_VF_LINK_STATE = 5,
	IFLA_VF_RATE = 6,
	IFLA_VF_RSS_QUERY_EN = 7,
	IFLA_VF_STATS = 8,
	IFLA_VF_TRUST = 9,
	IFLA_VF_IB_NODE_GUID = 10,
	IFLA_VF_IB_PORT_GUID = 11,
	IFLA_VF_VLAN_LIST = 12,
	IFLA_VF_BROADCAST = 13,
	__IFLA_VF_MAX = 14,
};

struct ifla_vf_mac {
	__u32 vf;
	__u8 mac[32];
};

struct ifla_vf_broadcast {
	__u8 broadcast[32];
};

struct ifla_vf_vlan {
	__u32 vf;
	__u32 vlan;
	__u32 qos;
};

enum {
	IFLA_VF_VLAN_INFO_UNSPEC = 0,
	IFLA_VF_VLAN_INFO = 1,
	__IFLA_VF_VLAN_INFO_MAX = 2,
};

struct ifla_vf_vlan_info {
	__u32 vf;
	__u32 vlan;
	__u32 qos;
	__be16 vlan_proto;
};

struct ifla_vf_tx_rate {
	__u32 vf;
	__u32 rate;
};

struct ifla_vf_rate {
	__u32 vf;
	__u32 min_tx_rate;
	__u32 max_tx_rate;
};

struct ifla_vf_spoofchk {
	__u32 vf;
	__u32 setting;
};

struct ifla_vf_link_state {
	__u32 vf;
	__u32 link_state;
};

struct ifla_vf_rss_query_en {
	__u32 vf;
	__u32 setting;
};

enum {
	IFLA_VF_STATS_RX_PACKETS = 0,
	IFLA_VF_STATS_TX_PACKETS = 1,
	IFLA_VF_STATS_RX_BYTES = 2,
	IFLA_VF_STATS_TX_BYTES = 3,
	IFLA_VF_STATS_BROADCAST = 4,
	IFLA_VF_STATS_MULTICAST = 5,
	IFLA_VF_STATS_PAD = 6,
	IFLA_VF_STATS_RX_DROPPED = 7,
	IFLA_VF_STATS_TX_DROPPED = 8,
	__IFLA_VF_STATS_MAX = 9,
};

struct ifla_vf_trust {
	__u32 vf;
	__u32 setting;
};

enum {
	IFLA_VF_PORT_UNSPEC = 0,
	IFLA_VF_PORT = 1,
	__IFLA_VF_PORT_MAX = 2,
};

enum {
	IFLA_PORT_UNSPEC = 0,
	IFLA_PORT_VF = 1,
	IFLA_PORT_PROFILE = 2,
	IFLA_PORT_VSI_TYPE = 3,
	IFLA_PORT_INSTANCE_UUID = 4,
	IFLA_PORT_HOST_UUID = 5,
	IFLA_PORT_REQUEST = 6,
	IFLA_PORT_RESPONSE = 7,
	__IFLA_PORT_MAX = 8,
};

struct if_stats_msg {
	__u8 family;
	__u8 pad1;
	__u16 pad2;
	__u32 ifindex;
	__u32 filter_mask;
};

enum {
	IFLA_STATS_UNSPEC = 0,
	IFLA_STATS_LINK_64 = 1,
	IFLA_STATS_LINK_XSTATS = 2,
	IFLA_STATS_LINK_XSTATS_SLAVE = 3,
	IFLA_STATS_LINK_OFFLOAD_XSTATS = 4,
	IFLA_STATS_AF_SPEC = 5,
	__IFLA_STATS_MAX = 6,
};

enum {
	IFLA_STATS_GETSET_UNSPEC = 0,
	IFLA_STATS_GET_FILTERS = 1,
	IFLA_STATS_SET_OFFLOAD_XSTATS_L3_STATS = 2,
	__IFLA_STATS_GETSET_MAX = 3,
};

enum {
	IFLA_OFFLOAD_XSTATS_UNSPEC = 0,
	IFLA_OFFLOAD_XSTATS_CPU_HIT = 1,
	IFLA_OFFLOAD_XSTATS_HW_S_INFO = 2,
	IFLA_OFFLOAD_XSTATS_L3_STATS = 3,
	__IFLA_OFFLOAD_XSTATS_MAX = 4,
};

enum {
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_UNSPEC = 0,
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_REQUEST = 1,
	IFLA_OFFLOAD_XSTATS_HW_S_INFO_USED = 2,
	__IFLA_OFFLOAD_XSTATS_HW_S_INFO_MAX = 3,
};

enum {
	XDP_ATTACHED_NONE = 0,
	XDP_ATTACHED_DRV = 1,
	XDP_ATTACHED_SKB = 2,
	XDP_ATTACHED_HW = 3,
	XDP_ATTACHED_MULTI = 4,
};

enum {
	IFLA_XDP_UNSPEC = 0,
	IFLA_XDP_FD = 1,
	IFLA_XDP_ATTACHED = 2,
	IFLA_XDP_FLAGS = 3,
	IFLA_XDP_PROG_ID = 4,
	IFLA_XDP_DRV_PROG_ID = 5,
	IFLA_XDP_SKB_PROG_ID = 6,
	IFLA_XDP_HW_PROG_ID = 7,
	IFLA_XDP_EXPECTED_FD = 8,
	__IFLA_XDP_MAX = 9,
};

enum {
	IFLA_EVENT_NONE = 0,
	IFLA_EVENT_REBOOT = 1,
	IFLA_EVENT_FEATURES = 2,
	IFLA_EVENT_BONDING_FAILOVER = 3,
	IFLA_EVENT_NOTIFY_PEERS = 4,
	IFLA_EVENT_IGMP_RESEND = 5,
	IFLA_EVENT_BONDING_OPTIONS = 6,
};

enum {
	IFLA_BRIDGE_FLAGS = 0,
	IFLA_BRIDGE_MODE = 1,
	IFLA_BRIDGE_VLAN_INFO = 2,
	IFLA_BRIDGE_VLAN_TUNNEL_INFO = 3,
	IFLA_BRIDGE_MRP = 4,
	IFLA_BRIDGE_CFM = 5,
	IFLA_BRIDGE_MST = 6,
	__IFLA_BRIDGE_MAX = 7,
};

enum {
	BR_MCAST_DIR_RX = 0,
	BR_MCAST_DIR_TX = 1,
	BR_MCAST_DIR_SIZE = 2,
};

enum rtattr_type_t {
	RTA_UNSPEC = 0,
	RTA_DST = 1,
	RTA_SRC = 2,
	RTA_IIF = 3,
	RTA_OIF = 4,
	RTA_GATEWAY = 5,
	RTA_PRIORITY = 6,
	RTA_PREFSRC = 7,
	RTA_METRICS = 8,
	RTA_MULTIPATH = 9,
	RTA_PROTOINFO = 10,
	RTA_FLOW = 11,
	RTA_CACHEINFO = 12,
	RTA_SESSION = 13,
	RTA_MP_ALGO = 14,
	RTA_TABLE = 15,
	RTA_MARK = 16,
	RTA_MFC_STATS = 17,
	RTA_VIA = 18,
	RTA_NEWDST = 19,
	RTA_PREF = 20,
	RTA_ENCAP_TYPE = 21,
	RTA_ENCAP = 22,
	RTA_EXPIRES = 23,
	RTA_PAD = 24,
	RTA_UID = 25,
	RTA_TTL_PROPAGATE = 26,
	RTA_IP_PROTO = 27,
	RTA_SPORT = 28,
	RTA_DPORT = 29,
	RTA_NH_ID = 30,
	__RTA_MAX = 31,
};

struct rta_cacheinfo {
	__u32 rta_clntref;
	__u32 rta_lastuse;
	__s32 rta_expires;
	__u32 rta_error;
	__u32 rta_used;
	__u32 rta_id;
	__u32 rta_ts;
	__u32 rta_tsage;
};

struct ifinfomsg {
	unsigned char ifi_family;
	unsigned char __ifi_pad;
	short unsigned int ifi_type;
	int ifi_index;
	unsigned int ifi_flags;
	unsigned int ifi_change;
};

struct rtnl_af_ops {
	struct list_head list;
	int family;
	int (*fill_link_af)(struct sk_buff *, const struct net_device *, u32);
	size_t (*get_link_af_size)(const struct net_device *, u32);
	int (*validate_link_af)(const struct net_device *, const struct nlattr *, struct netlink_ext_ack *);
	int (*set_link_af)(struct net_device *, const struct nlattr *, struct netlink_ext_ack *);
	int (*fill_stats_af)(struct sk_buff *, const struct net_device *);
	size_t (*get_stats_af_size)(const struct net_device *);
};

struct rtnl_link {
	rtnl_doit_func doit;
	rtnl_dumpit_func dumpit;
	struct module *owner;
	unsigned int flags;
	struct callback_head rcu;
};

struct rtnl_offload_xstats_request_used {
	bool request;
	bool used;
};

struct rtnl_stats_dump_filters {
	u32 mask[6];
};

enum {
	IF_LINK_MODE_DEFAULT = 0,
	IF_LINK_MODE_DORMANT = 1,
	IF_LINK_MODE_TESTING = 2,
};

enum lw_bits {
	LW_URGENT = 0,
};

enum {
	INET_DIAG_REQ_NONE = 0,
	INET_DIAG_REQ_BYTECODE = 1,
	INET_DIAG_REQ_SK_BPF_STORAGES = 2,
	INET_DIAG_REQ_PROTOCOL = 3,
	__INET_DIAG_REQ_MAX = 4,
};

struct sock_diag_req {
	__u8 sdiag_family;
	__u8 sdiag_protocol;
};

struct sock_diag_handler {
	__u8 family;
	int (*dump)(struct sk_buff *, struct nlmsghdr *);
	int (*get_info)(struct sk_buff *, struct sock *);
	int (*destroy)(struct sk_buff *, struct nlmsghdr *);
};

struct broadcast_sk {
	struct sock *sk;
	struct work_struct work;
};

enum xdp_buff_flags {
	XDP_FLAGS_HAS_FRAGS = 1,
	XDP_FLAGS_FRAGS_PF_MEMALLOC = 2,
};

enum rt_scope_t {
	RT_SCOPE_UNIVERSE = 0,
	RT_SCOPE_SITE = 200,
	RT_SCOPE_LINK = 253,
	RT_SCOPE_HOST = 254,
	RT_SCOPE_NOWHERE = 255,
};

enum rt_class_t {
	RT_TABLE_UNSPEC = 0,
	RT_TABLE_COMPAT = 252,
	RT_TABLE_DEFAULT = 253,
	RT_TABLE_MAIN = 254,
	RT_TABLE_LOCAL = 255,
	RT_TABLE_MAX = 4294967295,
};

struct nl_info {
	struct nlmsghdr *nlh;
	struct net *nl_net;
	u32 portid;
	u8 skip_notify: 1;
	u8 skip_notify_kernel: 1;
};

struct in6_pktinfo {
	struct in6_addr ipi6_addr;
	int ipi6_ifindex;
};

struct ipv6_rt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 type;
	__u8 segments_left;
};

struct inet_timewait_sock {
	struct sock_common __tw_common;
	__u32 tw_mark;
	volatile unsigned char tw_substate;
	unsigned char tw_rcv_wscale;
	__be16 tw_sport;
	unsigned int tw_transparent: 1;
	unsigned int tw_flowlabel: 20;
	unsigned int tw_pad: 3;
	unsigned int tw_tos: 8;
	u32 tw_txhash;
	u32 tw_priority;
	u32 tw_bslot;
	struct timer_list tw_timer;
	struct inet_bind_bucket *tw_tb;
};

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32 tw_rcv_wnd;
	u32 tw_ts_offset;
	u32 tw_ts_recent;
	u32 tw_last_oow_ack_time;
	int tw_ts_recent_stamp;
	u32 tw_tx_delay;
};

struct udp_sock {
	struct inet_sock inet;
	int pending;
	unsigned int corkflag;
	__u8 encap_type;
	unsigned char no_check6_tx: 1;
	unsigned char no_check6_rx: 1;
	unsigned char encap_enabled: 1;
	unsigned char gro_enabled: 1;
	unsigned char accept_udp_l4: 1;
	unsigned char accept_udp_fraglist: 1;
	__u16 len;
	__u16 gso_size;
	__u16 pcslen;
	__u16 pcrlen;
	__u8 pcflag;
	__u8 unused[3];
	int (*encap_rcv)(struct sock *, struct sk_buff *);
	int (*encap_err_lookup)(struct sock *, struct sk_buff *);
	void (*encap_destroy)(struct sock *);
	struct sk_buff * (*gro_receive)(struct sock *, struct list_head *, struct sk_buff *);
	int (*gro_complete)(struct sock *, struct sk_buff *, int);
	struct sk_buff_head reader_queue;
	int forward_deficit;
	int: 32;
};

struct ipv6_txoptions;

struct inet6_cork {
	struct ipv6_txoptions *opt;
	u8 hop_limit;
	u8 tclass;
};

struct ipv6_txoptions {
	refcount_t refcnt;
	int tot_len;
	__u16 opt_flen;
	__u16 opt_nflen;
	struct ipv6_opt_hdr *hopopt;
	struct ipv6_opt_hdr *dst0opt;
	struct ipv6_rt_hdr *srcrt;
	struct ipv6_opt_hdr *dst1opt;
	struct callback_head rcu;
};

struct ipv6_mc_socklist;

struct ipv6_ac_socklist;

struct ipv6_fl_socklist;

struct ipv6_pinfo {
	struct in6_addr saddr;
	struct in6_pktinfo sticky_pktinfo;
	const struct in6_addr *daddr_cache;
	__be32 flow_label;
	__u32 frag_size;
	__u16 __unused_1: 7;
	__s16 hop_limit: 9;
	__u16 mc_loop: 1;
	__u16 __unused_2: 6;
	__s16 mcast_hops: 9;
	int ucast_oif;
	int mcast_oif;
	union {
		struct {
			__u16 srcrt: 1;
			__u16 osrcrt: 1;
			__u16 rxinfo: 1;
			__u16 rxoinfo: 1;
			__u16 rxhlim: 1;
			__u16 rxohlim: 1;
			__u16 hopopts: 1;
			__u16 ohopopts: 1;
			__u16 dstopts: 1;
			__u16 odstopts: 1;
			__u16 rxflow: 1;
			__u16 rxtclass: 1;
			__u16 rxpmtu: 1;
			__u16 rxorigdstaddr: 1;
			__u16 recvfragsize: 1;
		} bits;
		__u16 all;
	} rxopt;
	__u16 recverr: 1;
	__u16 sndflow: 1;
	__u16 repflow: 1;
	__u16 pmtudisc: 3;
	__u16 padding: 1;
	__u16 srcprefs: 3;
	__u16 dontfrag: 1;
	__u16 autoflowlabel: 1;
	__u16 autoflowlabel_set: 1;
	__u16 mc_all: 1;
	__u16 recverr_rfc4884: 1;
	__u16 rtalert_isolate: 1;
	__u8 min_hopcount;
	__u8 tclass;
	__be32 rcv_flowinfo;
	__u32 dst_cookie;
	struct ipv6_mc_socklist *ipv6_mc_list;
	struct ipv6_ac_socklist *ipv6_ac_list;
	struct ipv6_fl_socklist *ipv6_fl_list;
	struct ipv6_txoptions *opt;
	struct sk_buff *pktoptions;
	struct sk_buff *rxpmtu;
	struct inet6_cork cork;
};

struct ip6_sf_socklist;

struct ipv6_mc_socklist {
	struct in6_addr addr;
	int ifindex;
	unsigned int sfmode;
	struct ipv6_mc_socklist *next;
	struct ip6_sf_socklist *sflist;
	struct callback_head rcu;
};

struct ipv6_ac_socklist {
	struct in6_addr acl_addr;
	int acl_ifindex;
	struct ipv6_ac_socklist *acl_next;
};

struct ip6_flowlabel;

struct ipv6_fl_socklist {
	struct ipv6_fl_socklist *next;
	struct ip6_flowlabel *fl;
	struct callback_head rcu;
};

struct udp6_sock {
	struct udp_sock udp;
	struct ipv6_pinfo inet6;
	int: 32;
};

struct tcp6_sock {
	struct tcp_sock tcp;
	struct ipv6_pinfo inet6;
	int: 32;
};

struct ip6_sf_socklist {
	unsigned int sl_max;
	unsigned int sl_count;
	struct callback_head rcu;
	struct in6_addr sl_addr[0];
};

struct ip6_flowlabel {
	struct ip6_flowlabel *next;
	__be32 label;
	atomic_t users;
	struct in6_addr dst;
	struct ipv6_txoptions *opt;
	long unsigned int linger;
	struct callback_head rcu;
	u8 share;
	union {
		struct pid *pid;
		kuid_t uid;
	} owner;
	long unsigned int lastuse;
	long unsigned int expires;
	struct net *fl_net;
};

struct fib_info;

struct fib_nh {
	struct fib_nh_common nh_common;
	struct hlist_node nh_hash;
	struct fib_info *nh_parent;
	__be32 nh_saddr;
	int nh_saddr_genid;
};

struct fib_info {
	struct hlist_node fib_hash;
	struct hlist_node fib_lhash;
	struct list_head nh_list;
	struct net *fib_net;
	refcount_t fib_treeref;
	refcount_t fib_clntref;
	unsigned int fib_flags;
	unsigned char fib_dead;
	unsigned char fib_protocol;
	unsigned char fib_scope;
	unsigned char fib_type;
	__be32 fib_prefsrc;
	u32 fib_tb_id;
	u32 fib_priority;
	struct dst_metrics *fib_metrics;
	int fib_nhs;
	bool fib_nh_is_v6;
	bool nh_updated;
	struct nexthop *nh;
	struct callback_head rcu;
	struct fib_nh fib_nh[0];
};

struct nh_info;

struct nh_group;

struct nexthop {
	struct rb_node rb_node;
	struct list_head fi_list;
	struct list_head f6i_list;
	struct list_head fdb_list;
	struct list_head grp_list;
	struct net *net;
	u32 id;
	u8 protocol;
	u8 nh_flags;
	bool is_group;
	refcount_t refcnt;
	struct callback_head rcu;
	union {
		struct nh_info *nh_info;
		struct nh_group *nh_grp;
	};
};

struct fib_table;

struct fib_result {
	__be32 prefix;
	unsigned char prefixlen;
	unsigned char nh_sel;
	unsigned char type;
	unsigned char scope;
	u32 tclassid;
	struct fib_nh_common *nhc;
	struct fib_info *fi;
	struct fib_table *table;
	struct hlist_head *fa_head;
};

struct fib_table {
	struct hlist_node tb_hlist;
	u32 tb_id;
	int tb_num_default;
	struct callback_head rcu;
	long unsigned int *tb_data;
	long unsigned int __data[0];
};

struct fib6_result;

struct fib6_config;

struct ipv6_stub {
	int (*ipv6_sock_mc_join)(struct sock *, int, const struct in6_addr *);
	int (*ipv6_sock_mc_drop)(struct sock *, int, const struct in6_addr *);
	struct dst_entry * (*ipv6_dst_lookup_flow)(struct net *, const struct sock *, struct flowi6 *, const struct in6_addr *);
	int (*ipv6_route_input)(struct sk_buff *);
	struct fib6_table * (*fib6_get_table)(struct net *, u32);
	int (*fib6_lookup)(struct net *, int, struct flowi6 *, struct fib6_result *, int);
	int (*fib6_table_lookup)(struct net *, struct fib6_table *, int, struct flowi6 *, struct fib6_result *, int);
	void (*fib6_select_path)(const struct net *, struct fib6_result *, struct flowi6 *, int, bool, const struct sk_buff *, int);
	u32 (*ip6_mtu_from_fib6)(const struct fib6_result *, const struct in6_addr *, const struct in6_addr *);
	int (*fib6_nh_init)(struct net *, struct fib6_nh *, struct fib6_config *, gfp_t, struct netlink_ext_ack *);
	void (*fib6_nh_release)(struct fib6_nh *);
	void (*fib6_nh_release_dsts)(struct fib6_nh *);
	void (*fib6_update_sernum)(struct net *, struct fib6_info *);
	int (*ip6_del_rt)(struct net *, struct fib6_info *, bool);
	void (*fib6_rt_update)(struct net *, struct fib6_info *, struct nl_info *);
	void (*udpv6_encap_enable)();
	void (*ndisc_send_na)(struct net_device *, const struct in6_addr *, const struct in6_addr *, bool, bool, bool, bool);
	void (*xfrm6_local_rxpmtu)(struct sk_buff *, u32);
	int (*xfrm6_udp_encap_rcv)(struct sock *, struct sk_buff *);
	int (*xfrm6_rcv_encap)(struct sk_buff *, int, __be32, int);
	struct neigh_table *nd_tbl;
	int (*ipv6_fragment)(struct net *, struct sock *, struct sk_buff *, int (*)(struct net *, struct sock *, struct sk_buff *));
	struct net_device * (*ipv6_dev_find)(struct net *, const struct in6_addr *, struct net_device *);
};

struct fib6_result {
	struct fib6_nh *nh;
	struct fib6_info *f6i;
	u32 fib6_flags;
	u8 fib6_type;
	struct rt6_info *rt6;
};

struct fib6_config {
	u32 fc_table;
	u32 fc_metric;
	int fc_dst_len;
	int fc_src_len;
	int fc_ifindex;
	u32 fc_flags;
	u32 fc_protocol;
	u16 fc_type;
	u16 fc_delete_all_nh: 1;
	u16 fc_ignore_dev_down: 1;
	u16 __unused: 14;
	u32 fc_nh_id;
	struct in6_addr fc_dst;
	struct in6_addr fc_src;
	struct in6_addr fc_prefsrc;
	struct in6_addr fc_gateway;
	long unsigned int fc_expires;
	struct nlattr *fc_mx;
	int fc_mx_len;
	int fc_mp_len;
	struct nlattr *fc_mp;
	struct nl_info fc_nlinfo;
	struct nlattr *fc_encap;
	u16 fc_encap_type;
	bool fc_is_fdb;
};

struct ipv6_bpf_stub {
	int (*inet6_bind)(struct sock *, struct sockaddr *, int, u32);
	struct sock * (*udp6_lib_lookup)(struct net *, const struct in6_addr *, __be16, const struct in6_addr *, __be16, int, int, struct udp_table *, struct sk_buff *);
};

enum {
	BPF_F_RECOMPUTE_CSUM = 1,
	BPF_F_INVALIDATE_HASH = 2,
};

enum {
	BPF_F_HDR_FIELD_MASK = 15,
};

enum {
	BPF_F_PSEUDO_HDR = 16,
	BPF_F_MARK_MANGLED_0 = 32,
	BPF_F_MARK_ENFORCE = 64,
};

enum {
	BPF_F_INGRESS = 1,
};

enum {
	BPF_F_TUNINFO_IPV6 = 1,
};

enum {
	BPF_F_ZERO_CSUM_TX = 2,
	BPF_F_DONT_FRAGMENT = 4,
	BPF_F_SEQ_NUMBER = 8,
};

enum {
	BPF_CSUM_LEVEL_QUERY = 0,
	BPF_CSUM_LEVEL_INC = 1,
	BPF_CSUM_LEVEL_DEC = 2,
	BPF_CSUM_LEVEL_RESET = 3,
};

enum {
	BPF_F_ADJ_ROOM_FIXED_GSO = 1,
	BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 = 2,
	BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 = 4,
	BPF_F_ADJ_ROOM_ENCAP_L4_GRE = 8,
	BPF_F_ADJ_ROOM_ENCAP_L4_UDP = 16,
	BPF_F_ADJ_ROOM_NO_CSUM_RESET = 32,
	BPF_F_ADJ_ROOM_ENCAP_L2_ETH = 64,
};

enum {
	BPF_ADJ_ROOM_ENCAP_L2_MASK = 255,
	BPF_ADJ_ROOM_ENCAP_L2_SHIFT = 56,
};

enum {
	BPF_SK_LOOKUP_F_REPLACE = 1,
	BPF_SK_LOOKUP_F_NO_REUSEPORT = 2,
};

enum bpf_adj_room_mode {
	BPF_ADJ_ROOM_NET = 0,
	BPF_ADJ_ROOM_MAC = 1,
};

enum bpf_hdr_start_off {
	BPF_HDR_START_MAC = 0,
	BPF_HDR_START_NET = 1,
};

enum {
	BPF_SKB_TSTAMP_UNSPEC = 0,
	BPF_SKB_TSTAMP_DELIVERY_MONO = 1,
};

struct bpf_tunnel_key {
	__u32 tunnel_id;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
	__u8 tunnel_tos;
	__u8 tunnel_ttl;
	__u16 tunnel_ext;
	__u32 tunnel_label;
};

struct bpf_xfrm_state {
	__u32 reqid;
	__u32 spi;
	__u16 family;
	__u16 ext;
	union {
		__u32 remote_ipv4;
		__u32 remote_ipv6[4];
	};
};

struct bpf_tcp_sock {
	__u32 snd_cwnd;
	__u32 srtt_us;
	__u32 rtt_min;
	__u32 snd_ssthresh;
	__u32 rcv_nxt;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 mss_cache;
	__u32 ecn_flags;
	__u32 rate_delivered;
	__u32 rate_interval_us;
	__u32 packets_out;
	__u32 retrans_out;
	__u32 total_retrans;
	__u32 segs_in;
	__u32 data_segs_in;
	__u32 segs_out;
	__u32 data_segs_out;
	__u32 lost_out;
	__u32 sacked_out;
	__u64 bytes_received;
	__u64 bytes_acked;
	__u32 dsack_dups;
	__u32 delivered;
	__u32 delivered_ce;
	__u32 icsk_retransmits;
};

struct bpf_sock_tuple {
	union {
		struct {
			__be32 saddr;
			__be32 daddr;
			__be16 sport;
			__be16 dport;
		} ipv4;
		struct {
			__be32 saddr[4];
			__be32 daddr[4];
			__be16 sport;
			__be16 dport;
		} ipv6;
	};
};

struct bpf_xdp_sock {
	__u32 queue_id;
};

struct bpf_sock_addr {
	__u32 user_family;
	__u32 user_ip4;
	__u32 user_ip6[4];
	__u32 user_port;
	__u32 family;
	__u32 type;
	__u32 protocol;
	__u32 msg_src_ip4;
	__u32 msg_src_ip6[4];
	int: 32;
	union {
		struct bpf_sock *sk;
	};
};

enum {
	BPF_SOCK_OPS_RTO_CB_FLAG = 1,
	BPF_SOCK_OPS_RETRANS_CB_FLAG = 2,
	BPF_SOCK_OPS_STATE_CB_FLAG = 4,
	BPF_SOCK_OPS_RTT_CB_FLAG = 8,
	BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG = 16,
	BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = 32,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG = 64,
	BPF_SOCK_OPS_ALL_CB_FLAGS = 127,
};

enum {
	BPF_SOCK_OPS_VOID = 0,
	BPF_SOCK_OPS_TIMEOUT_INIT = 1,
	BPF_SOCK_OPS_RWND_INIT = 2,
	BPF_SOCK_OPS_TCP_CONNECT_CB = 3,
	BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB = 4,
	BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB = 5,
	BPF_SOCK_OPS_NEEDS_ECN = 6,
	BPF_SOCK_OPS_BASE_RTT = 7,
	BPF_SOCK_OPS_RTO_CB = 8,
	BPF_SOCK_OPS_RETRANS_CB = 9,
	BPF_SOCK_OPS_STATE_CB = 10,
	BPF_SOCK_OPS_TCP_LISTEN_CB = 11,
	BPF_SOCK_OPS_RTT_CB = 12,
	BPF_SOCK_OPS_PARSE_HDR_OPT_CB = 13,
	BPF_SOCK_OPS_HDR_OPT_LEN_CB = 14,
	BPF_SOCK_OPS_WRITE_HDR_OPT_CB = 15,
};

enum {
	TCP_BPF_IW = 1001,
	TCP_BPF_SNDCWND_CLAMP = 1002,
	TCP_BPF_DELACK_MAX = 1003,
	TCP_BPF_RTO_MIN = 1004,
	TCP_BPF_SYN = 1005,
	TCP_BPF_SYN_IP = 1006,
	TCP_BPF_SYN_MAC = 1007,
};

enum {
	BPF_LOAD_HDR_OPT_TCP_SYN = 1,
};

enum {
	BPF_FIB_LOOKUP_DIRECT = 1,
	BPF_FIB_LOOKUP_OUTPUT = 2,
};

enum {
	BPF_FIB_LKUP_RET_SUCCESS = 0,
	BPF_FIB_LKUP_RET_BLACKHOLE = 1,
	BPF_FIB_LKUP_RET_UNREACHABLE = 2,
	BPF_FIB_LKUP_RET_PROHIBIT = 3,
	BPF_FIB_LKUP_RET_NOT_FWDED = 4,
	BPF_FIB_LKUP_RET_FWD_DISABLED = 5,
	BPF_FIB_LKUP_RET_UNSUPP_LWT = 6,
	BPF_FIB_LKUP_RET_NO_NEIGH = 7,
	BPF_FIB_LKUP_RET_FRAG_NEEDED = 8,
};

struct bpf_fib_lookup {
	__u8 family;
	__u8 l4_protocol;
	__be16 sport;
	__be16 dport;
	union {
		__u16 tot_len;
		__u16 mtu_result;
	};
	__u32 ifindex;
	union {
		__u8 tos;
		__be32 flowinfo;
		__u32 rt_metric;
	};
	union {
		__be32 ipv4_src;
		__u32 ipv6_src[4];
	};
	union {
		__be32 ipv4_dst;
		__u32 ipv6_dst[4];
	};
	__be16 h_vlan_proto;
	__be16 h_vlan_TCI;
	__u8 smac[6];
	__u8 dmac[6];
};

struct bpf_redir_neigh {
	__u32 nh_family;
	union {
		__be32 ipv4_nh;
		__u32 ipv6_nh[4];
	};
};

enum bpf_check_mtu_flags {
	BPF_MTU_CHK_SEGS = 1,
};

enum bpf_check_mtu_ret {
	BPF_MTU_CHK_RET_SUCCESS = 0,
	BPF_MTU_CHK_RET_FRAG_NEEDED = 1,
	BPF_MTU_CHK_RET_SEGS_TOOBIG = 2,
};

struct compat_sock_fprog {
	u16 len;
	compat_uptr_t filter;
};

struct bpf_skb_data_end {
	struct qdisc_skb_cb qdisc_cb;
	void *data_meta;
	void *data_end;
};

typedef int (*bpf_aux_classic_check_t)(struct sock_filter *, unsigned int);

struct bpf_sock_addr_kern {
	struct sock *sk;
	struct sockaddr *uaddr;
	u64 tmp_reg;
	void *t_ctx;
};

enum {
	INET_ECN_NOT_ECT = 0,
	INET_ECN_ECT_1 = 1,
	INET_ECN_ECT_0 = 2,
	INET_ECN_CE = 3,
	INET_ECN_MASK = 3,
};

struct tcp_skb_cb {
	__u32 seq;
	__u32 end_seq;
	union {
		__u32 tcp_tw_isn;
		struct {
			u16 tcp_gso_segs;
			u16 tcp_gso_size;
		};
	};
	__u8 tcp_flags;
	__u8 sacked;
	__u8 ip_dsfield;
	__u8 txstamp_ack: 1;
	__u8 eor: 1;
	__u8 has_rxtstamp: 1;
	__u8 unused: 5;
	__u32 ack_seq;
	union {
		struct {
			__u32 is_app_limited: 1;
			__u32 delivered_ce: 20;
			__u32 unused: 11;
			__u32 delivered;
			u64 first_tx_mstamp;
			u64 delivered_mstamp;
		} tx;
		union {
			struct inet_skb_parm h4;
		} header;
	};
};

struct strp_stats {
	long long unsigned int msgs;
	long long unsigned int bytes;
	unsigned int mem_fail;
	unsigned int need_more_hdr;
	unsigned int msg_too_big;
	unsigned int msg_timeouts;
	unsigned int bad_hdr_len;
};

struct strparser;

struct strp_callbacks {
	int (*parse_msg)(struct strparser *, struct sk_buff *);
	void (*rcv_msg)(struct strparser *, struct sk_buff *);
	int (*read_sock_done)(struct strparser *, int);
	void (*abort_parser)(struct strparser *, int);
	void (*lock)(struct strparser *);
	void (*unlock)(struct strparser *);
};

struct strparser {
	struct sock *sk;
	u32 stopped: 1;
	u32 paused: 1;
	u32 aborted: 1;
	u32 interrupted: 1;
	u32 unrecov_intr: 1;
	struct sk_buff **skb_nextp;
	struct sk_buff *skb_head;
	unsigned int need_bytes;
	struct delayed_work msg_timer_work;
	struct work_struct work;
	struct strp_stats stats;
	struct strp_callbacks cb;
};

struct strp_msg {
	int full_len;
	int offset;
};

struct _strp_msg {
	struct strp_msg strp;
	int accum_len;
};

struct sk_skb_cb {
	unsigned char data[20];
	struct _strp_msg strp;
	u64 temp_reg;
};

struct xdp_umem {
	void *addrs;
	u64 size;
	u32 headroom;
	u32 chunk_size;
	u32 chunks;
	u32 npgs;
	struct user_struct *user;
	refcount_t users;
	u8 flags;
	bool zc;
	struct page **pgs;
	int id;
	struct list_head xsk_dma_list;
	struct work_struct work;
};

struct xsk_queue;

struct xdp_sock {
	struct sock sk;
	struct xsk_queue *rx;
	struct net_device *dev;
	struct xdp_umem *umem;
	struct list_head flush_node;
	struct xsk_buff_pool *pool;
	u16 queue_id;
	bool zc;
	enum {
		XSK_READY = 0,
		XSK_BOUND = 1,
		XSK_UNBOUND = 2,
	} state;
	struct xsk_queue *tx;
	struct list_head tx_list;
	spinlock_t rx_lock;
	u64 rx_dropped;
	u64 rx_queue_full;
	struct list_head map_list;
	spinlock_t map_list_lock;
	struct mutex mutex;
	struct xsk_queue *fq_tmp;
	struct xsk_queue *cq_tmp;
};

struct nh_info {
	struct hlist_node dev_hash;
	struct nexthop *nh_parent;
	u8 family;
	bool reject_nh;
	bool fdb_nh;
	union {
		struct fib_nh_common fib_nhc;
		struct fib_nh fib_nh;
		struct fib6_nh fib6_nh;
	};
};

struct nh_grp_entry;

struct nh_res_bucket {
	struct nh_grp_entry *nh_entry;
	atomic_long_t used_time;
	long unsigned int migrated_time;
	bool occupied;
	u8 nh_flags;
};

struct nh_grp_entry {
	struct nexthop *nh;
	u8 weight;
	union {
		struct {
			atomic_t upper_bound;
		} hthr;
		struct {
			struct list_head uw_nh_entry;
			u16 count_buckets;
			u16 wants_buckets;
		} res;
	};
	struct list_head nh_list;
	struct nexthop *nh_parent;
};

struct nh_res_table {
	struct net *net;
	u32 nhg_id;
	struct delayed_work upkeep_dw;
	struct list_head uw_nh_entries;
	long unsigned int unbalanced_since;
	u32 idle_timer;
	u32 unbalanced_timer;
	u16 num_nh_buckets;
	struct nh_res_bucket nh_buckets[0];
};

struct nh_group {
	struct nh_group *spare;
	u16 num_nh;
	bool is_multipath;
	bool hash_threshold;
	bool resilient;
	bool fdb_nh;
	bool has_v4;
	struct nh_res_table *res_table;
	struct nh_grp_entry nh_entries[0];
};

struct tls_crypto_info {
	__u16 version;
	__u16 cipher_type;
};

struct tls12_crypto_info_aes_gcm_128 {
	struct tls_crypto_info info;
	unsigned char iv[8];
	unsigned char key[16];
	unsigned char salt[4];
	unsigned char rec_seq[8];
};

struct tls12_crypto_info_aes_gcm_256 {
	struct tls_crypto_info info;
	unsigned char iv[8];
	unsigned char key[32];
	unsigned char salt[4];
	unsigned char rec_seq[8];
};

struct tls12_crypto_info_chacha20_poly1305 {
	struct tls_crypto_info info;
	unsigned char iv[12];
	unsigned char key[32];
	unsigned char salt[0];
	unsigned char rec_seq[8];
};

struct tls12_crypto_info_sm4_gcm {
	struct tls_crypto_info info;
	unsigned char iv[8];
	unsigned char key[16];
	unsigned char salt[4];
	unsigned char rec_seq[8];
};

struct tls12_crypto_info_sm4_ccm {
	struct tls_crypto_info info;
	unsigned char iv[8];
	unsigned char key[16];
	unsigned char salt[4];
	unsigned char rec_seq[8];
};

struct tls_sw_context_rx {
	struct crypto_aead *aead_recv;
	struct crypto_wait async_wait;
	struct strparser strp;
	struct sk_buff_head rx_list;
	void (*saved_data_ready)(struct sock *);
	struct sk_buff *recv_pkt;
	u8 control;
	u8 async_capable: 1;
	u8 decrypted: 1;
	atomic_t decrypt_pending;
	spinlock_t decrypt_compl_lock;
	bool async_notify;
};

struct cipher_context {
	char *iv;
	char *rec_seq;
};

union tls_crypto_context {
	struct tls_crypto_info info;
	union {
		struct tls12_crypto_info_aes_gcm_128 aes_gcm_128;
		struct tls12_crypto_info_aes_gcm_256 aes_gcm_256;
		struct tls12_crypto_info_chacha20_poly1305 chacha20_poly1305;
		struct tls12_crypto_info_sm4_gcm sm4_gcm;
		struct tls12_crypto_info_sm4_ccm sm4_ccm;
	};
};

struct tls_prot_info {
	u16 version;
	u16 cipher_type;
	u16 prepend_size;
	u16 tag_size;
	u16 overhead_size;
	u16 iv_size;
	u16 salt_size;
	u16 rec_seq_size;
	u16 aad_size;
	u16 tail_size;
};

struct tls_context {
	struct tls_prot_info prot_info;
	u8 tx_conf: 3;
	u8 rx_conf: 3;
	int (*push_pending_record)(struct sock *, int);
	void (*sk_write_space)(struct sock *);
	void *priv_ctx_tx;
	void *priv_ctx_rx;
	struct net_device *netdev;
	struct cipher_context tx;
	struct cipher_context rx;
	struct scatterlist *partially_sent_record;
	u16 partially_sent_offset;
	bool in_tcp_sendpages;
	bool pending_open_record_frags;
	struct mutex tx_lock;
	long unsigned int flags;
	struct proto *sk_proto;
	struct sock *sk;
	void (*sk_destruct)(struct sock *);
	union tls_crypto_context crypto_send;
	union tls_crypto_context crypto_recv;
	struct list_head list;
	refcount_t refcount;
	struct callback_head rcu;
};

typedef u64 (*btf_bpf_skb_get_pay_offset)(struct sk_buff *);

typedef u64 (*btf_bpf_skb_get_nlattr)(struct sk_buff *, u32, u32);

typedef u64 (*btf_bpf_skb_get_nlattr_nest)(struct sk_buff *, u32, u32);

typedef u64 (*btf_bpf_skb_load_helper_8)(const struct sk_buff *, const void *, int, int);

typedef u64 (*btf_bpf_skb_load_helper_8_no_cache)(const struct sk_buff *, int);

typedef u64 (*btf_bpf_skb_load_helper_16)(const struct sk_buff *, const void *, int, int);

typedef u64 (*btf_bpf_skb_load_helper_16_no_cache)(const struct sk_buff *, int);

typedef u64 (*btf_bpf_skb_load_helper_32)(const struct sk_buff *, const void *, int, int);

typedef u64 (*btf_bpf_skb_load_helper_32_no_cache)(const struct sk_buff *, int);

struct bpf_scratchpad {
	union {
		__be32 diff[128];
		u8 buff[512];
	};
};

typedef u64 (*btf_bpf_skb_store_bytes)(struct sk_buff *, u32, const void *, u32, u64);

typedef u64 (*btf_bpf_skb_load_bytes)(const struct sk_buff *, u32, void *, u32);

typedef u64 (*btf_bpf_flow_dissector_load_bytes)(const struct bpf_flow_dissector *, u32, void *, u32);

typedef u64 (*btf_bpf_skb_load_bytes_relative)(const struct sk_buff *, u32, void *, u32, u32);

typedef u64 (*btf_bpf_skb_pull_data)(struct sk_buff *, u32);

typedef u64 (*btf_bpf_sk_fullsock)(struct sock *);

typedef u64 (*btf_sk_skb_pull_data)(struct sk_buff *, u32);

typedef u64 (*btf_bpf_l3_csum_replace)(struct sk_buff *, u32, u64, u64, u64);

typedef u64 (*btf_bpf_l4_csum_replace)(struct sk_buff *, u32, u64, u64, u64);

typedef u64 (*btf_bpf_csum_diff)(__be32 *, u32, __be32 *, u32, __wsum);

typedef u64 (*btf_bpf_csum_update)(struct sk_buff *, __wsum);

typedef u64 (*btf_bpf_csum_level)(struct sk_buff *, u64);

enum {
	BPF_F_NEIGH = 2,
	BPF_F_PEER = 4,
	BPF_F_NEXTHOP = 8,
};

typedef u64 (*btf_bpf_clone_redirect)(struct sk_buff *, u32, u64);

typedef u64 (*btf_bpf_redirect)(u32, u64);

typedef u64 (*btf_bpf_redirect_peer)(u32, u64);

typedef u64 (*btf_bpf_redirect_neigh)(u32, struct bpf_redir_neigh *, int, u64);

typedef u64 (*btf_bpf_msg_apply_bytes)(struct sk_msg *, u32);

typedef u64 (*btf_bpf_msg_cork_bytes)(struct sk_msg *, u32);

typedef u64 (*btf_bpf_msg_pull_data)(struct sk_msg *, u32, u32, u64);

typedef u64 (*btf_bpf_msg_push_data)(struct sk_msg *, u32, u32, u64);

typedef u64 (*btf_bpf_msg_pop_data)(struct sk_msg *, u32, u32, u64);

typedef u64 (*btf_bpf_get_cgroup_classid)(const struct sk_buff *);

typedef u64 (*btf_bpf_get_route_realm)(const struct sk_buff *);

typedef u64 (*btf_bpf_get_hash_recalc)(struct sk_buff *);

typedef u64 (*btf_bpf_set_hash_invalid)(struct sk_buff *);

typedef u64 (*btf_bpf_set_hash)(struct sk_buff *, u32);

typedef u64 (*btf_bpf_skb_vlan_push)(struct sk_buff *, __be16, u16);

typedef u64 (*btf_bpf_skb_vlan_pop)(struct sk_buff *);

typedef u64 (*btf_bpf_skb_change_proto)(struct sk_buff *, __be16, u64);

typedef u64 (*btf_bpf_skb_change_type)(struct sk_buff *, u32);

typedef u64 (*btf_sk_skb_adjust_room)(struct sk_buff *, s32, u32, u64);

typedef u64 (*btf_bpf_skb_adjust_room)(struct sk_buff *, s32, u32, u64);

typedef u64 (*btf_bpf_skb_change_tail)(struct sk_buff *, u32, u64);

typedef u64 (*btf_sk_skb_change_tail)(struct sk_buff *, u32, u64);

typedef u64 (*btf_bpf_skb_change_head)(struct sk_buff *, u32, u64);

typedef u64 (*btf_sk_skb_change_head)(struct sk_buff *, u32, u64);

typedef u64 (*btf_bpf_xdp_get_buff_len)(struct xdp_buff *);

typedef u64 (*btf_bpf_xdp_adjust_head)(struct xdp_buff *, int);

typedef u64 (*btf_bpf_xdp_load_bytes)(struct xdp_buff *, u32, void *, u32);

typedef u64 (*btf_bpf_xdp_store_bytes)(struct xdp_buff *, u32, void *, u32);

typedef u64 (*btf_bpf_xdp_adjust_tail)(struct xdp_buff *, int);

typedef u64 (*btf_bpf_xdp_adjust_meta)(struct xdp_buff *, int);

typedef u64 (*btf_bpf_xdp_redirect)(u32, u64);

typedef u64 (*btf_bpf_xdp_redirect_map)(struct bpf_map *, u32, u64);

typedef u64 (*btf_bpf_skb_event_output)(struct sk_buff *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_skb_get_tunnel_key)(struct sk_buff *, struct bpf_tunnel_key *, u32, u64);

typedef u64 (*btf_bpf_skb_get_tunnel_opt)(struct sk_buff *, u8 *, u32);

typedef u64 (*btf_bpf_skb_set_tunnel_key)(struct sk_buff *, const struct bpf_tunnel_key *, u32, u64);

typedef u64 (*btf_bpf_skb_set_tunnel_opt)(struct sk_buff *, const u8 *, u32);

typedef u64 (*btf_bpf_skb_under_cgroup)(struct sk_buff *, struct bpf_map *, u32);

typedef u64 (*btf_bpf_xdp_event_output)(struct xdp_buff *, struct bpf_map *, u64, void *, u64);

typedef u64 (*btf_bpf_get_socket_cookie)(struct sk_buff *);

typedef u64 (*btf_bpf_get_socket_cookie_sock_addr)(struct bpf_sock_addr_kern *);

typedef u64 (*btf_bpf_get_socket_cookie_sock)(struct sock *);

typedef u64 (*btf_bpf_get_socket_ptr_cookie)(struct sock *);

typedef u64 (*btf_bpf_get_socket_cookie_sock_ops)(struct bpf_sock_ops_kern *);

typedef u64 (*btf_bpf_get_netns_cookie_sock)(struct sock *);

typedef u64 (*btf_bpf_get_netns_cookie_sock_addr)(struct bpf_sock_addr_kern *);

typedef u64 (*btf_bpf_get_netns_cookie_sock_ops)(struct bpf_sock_ops_kern *);

typedef u64 (*btf_bpf_get_netns_cookie_sk_msg)(struct sk_msg *);

typedef u64 (*btf_bpf_get_socket_uid)(struct sk_buff *);

typedef u64 (*btf_bpf_sk_setsockopt)(struct sock *, int, int, char *, int);

typedef u64 (*btf_bpf_sk_getsockopt)(struct sock *, int, int, char *, int);




























