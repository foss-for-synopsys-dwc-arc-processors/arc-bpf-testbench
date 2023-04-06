# 1 "uprobe.bpf.c"
# 1 "<built-in>" 1
# 1 "<built-in>" 3
# 322 "<built-in>" 3
# 1 "<command line>" 1
# 1 "<built-in>" 2
# 1 "uprobe.bpf.c" 2


# 1 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h" 1
# 11 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/linux/types.h" 1




# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm/types.h" 1
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/types.h" 1






# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/int-ll64.h" 1
# 12 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/int-ll64.h"
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm/bitsperlong.h" 1
# 11 "/tools/arc-linux-gnu/sysroot/usr/include/asm/bitsperlong.h"
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/bitsperlong.h" 1
# 12 "/tools/arc-linux-gnu/sysroot/usr/include/asm/bitsperlong.h" 2
# 13 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/int-ll64.h" 2







typedef __signed__ char __s8;
typedef unsigned char __u8;

typedef __signed__ short __s16;
typedef unsigned short __u16;

typedef __signed__ int __s32;
typedef unsigned int __u32;


__extension__ typedef __signed__ long long __s64;
__extension__ typedef unsigned long long __u64;
# 8 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/types.h" 2
# 2 "/tools/arc-linux-gnu/sysroot/usr/include/asm/types.h" 2
# 6 "/tools/arc-linux-gnu/sysroot/usr/include/linux/types.h" 2



# 1 "/tools/arc-linux-gnu/sysroot/usr/include/linux/posix_types.h" 1




# 1 "/tools/arc-linux-gnu/sysroot/usr/include/linux/stddef.h" 1
# 6 "/tools/arc-linux-gnu/sysroot/usr/include/linux/posix_types.h" 2
# 25 "/tools/arc-linux-gnu/sysroot/usr/include/linux/posix_types.h"
typedef struct {
 unsigned long fds_bits[1024 / (8 * sizeof(long))];
} __kernel_fd_set;


typedef void (*__kernel_sighandler_t)(int);


typedef int __kernel_key_t;
typedef int __kernel_mqd_t;

# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm/posix_types.h" 1
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/posix_types.h" 1
# 15 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/posix_types.h"
typedef long __kernel_long_t;
typedef unsigned long __kernel_ulong_t;



typedef __kernel_ulong_t __kernel_ino_t;



typedef unsigned int __kernel_mode_t;



typedef int __kernel_pid_t;



typedef int __kernel_ipc_pid_t;



typedef unsigned int __kernel_uid_t;
typedef unsigned int __kernel_gid_t;



typedef __kernel_long_t __kernel_suseconds_t;



typedef int __kernel_daddr_t;



typedef unsigned int __kernel_uid32_t;
typedef unsigned int __kernel_gid32_t;



typedef __kernel_uid_t __kernel_old_uid_t;
typedef __kernel_gid_t __kernel_old_gid_t;



typedef unsigned int __kernel_old_dev_t;
# 72 "/tools/arc-linux-gnu/sysroot/usr/include/asm-generic/posix_types.h"
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_long_t __kernel_ssize_t;
typedef __kernel_long_t __kernel_ptrdiff_t;




typedef struct {
 int val[2];
} __kernel_fsid_t;





typedef __kernel_long_t __kernel_off_t;
typedef long long __kernel_loff_t;
typedef __kernel_long_t __kernel_old_time_t;
typedef __kernel_long_t __kernel_time_t;
typedef long long __kernel_time64_t;
typedef __kernel_long_t __kernel_clock_t;
typedef int __kernel_timer_t;
typedef int __kernel_clockid_t;
typedef char * __kernel_caddr_t;
typedef unsigned short __kernel_uid16_t;
typedef unsigned short __kernel_gid16_t;
# 2 "/tools/arc-linux-gnu/sysroot/usr/include/asm/posix_types.h" 2
# 37 "/tools/arc-linux-gnu/sysroot/usr/include/linux/posix_types.h" 2
# 10 "/tools/arc-linux-gnu/sysroot/usr/include/linux/types.h" 2
# 24 "/tools/arc-linux-gnu/sysroot/usr/include/linux/types.h"
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __le32;
typedef __u32 __be32;
typedef __u64 __le64;
typedef __u64 __be64;

typedef __u16 __sum16;
typedef __u32 __wsum;
# 47 "/tools/arc-linux-gnu/sysroot/usr/include/linux/types.h"
typedef unsigned __poll_t;
# 12 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h" 2
# 1 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf_common.h" 1
# 13 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h" 2
# 53 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum {
 BPF_REG_0 = 0,
 BPF_REG_1,
 BPF_REG_2,
 BPF_REG_3,
 BPF_REG_4,
 BPF_REG_5,
 BPF_REG_6,
 BPF_REG_7,
 BPF_REG_8,
 BPF_REG_9,
 BPF_REG_10,
 __MAX_BPF_REG,
};




struct bpf_insn {
 __u8 code;
 __u8 dst_reg:4;
 __u8 src_reg:4;
 __s16 off;
 __s32 imm;
};


struct bpf_lpm_trie_key {
 __u32 prefixlen;
 __u8 data[0];
};

struct bpf_cgroup_storage_key {
 __u64 cgroup_inode_id;
 __u32 attach_type;
};

enum bpf_cgroup_iter_order {
 BPF_CGROUP_ITER_ORDER_UNSPEC = 0,
 BPF_CGROUP_ITER_SELF_ONLY,
 BPF_CGROUP_ITER_DESCENDANTS_PRE,
 BPF_CGROUP_ITER_DESCENDANTS_POST,
 BPF_CGROUP_ITER_ANCESTORS_UP,
};

union bpf_iter_link_info {
 struct {
  __u32 map_fd;
 } map;
 struct {
  enum bpf_cgroup_iter_order order;






  __u32 cgroup_fd;
  __u64 cgroup_id;
 } cgroup;

 struct {
  __u32 tid;
  __u32 pid;
  __u32 pid_fd;
 } task;
};
# 865 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum bpf_cmd {
 BPF_MAP_CREATE,
 BPF_MAP_LOOKUP_ELEM,
 BPF_MAP_UPDATE_ELEM,
 BPF_MAP_DELETE_ELEM,
 BPF_MAP_GET_NEXT_KEY,
 BPF_PROG_LOAD,
 BPF_OBJ_PIN,
 BPF_OBJ_GET,
 BPF_PROG_ATTACH,
 BPF_PROG_DETACH,
 BPF_PROG_TEST_RUN,
 BPF_PROG_RUN = BPF_PROG_TEST_RUN,
 BPF_PROG_GET_NEXT_ID,
 BPF_MAP_GET_NEXT_ID,
 BPF_PROG_GET_FD_BY_ID,
 BPF_MAP_GET_FD_BY_ID,
 BPF_OBJ_GET_INFO_BY_FD,
 BPF_PROG_QUERY,
 BPF_RAW_TRACEPOINT_OPEN,
 BPF_BTF_LOAD,
 BPF_BTF_GET_FD_BY_ID,
 BPF_TASK_FD_QUERY,
 BPF_MAP_LOOKUP_AND_DELETE_ELEM,
 BPF_MAP_FREEZE,
 BPF_BTF_GET_NEXT_ID,
 BPF_MAP_LOOKUP_BATCH,
 BPF_MAP_LOOKUP_AND_DELETE_BATCH,
 BPF_MAP_UPDATE_BATCH,
 BPF_MAP_DELETE_BATCH,
 BPF_LINK_CREATE,
 BPF_LINK_UPDATE,
 BPF_LINK_GET_FD_BY_ID,
 BPF_LINK_GET_NEXT_ID,
 BPF_ENABLE_STATS,
 BPF_ITER_CREATE,
 BPF_LINK_DETACH,
 BPF_PROG_BIND_MAP,
};

enum bpf_map_type {
 BPF_MAP_TYPE_UNSPEC,
 BPF_MAP_TYPE_HASH,
 BPF_MAP_TYPE_ARRAY,
 BPF_MAP_TYPE_PROG_ARRAY,
 BPF_MAP_TYPE_PERF_EVENT_ARRAY,
 BPF_MAP_TYPE_PERCPU_HASH,
 BPF_MAP_TYPE_PERCPU_ARRAY,
 BPF_MAP_TYPE_STACK_TRACE,
 BPF_MAP_TYPE_CGROUP_ARRAY,
 BPF_MAP_TYPE_LRU_HASH,
 BPF_MAP_TYPE_LRU_PERCPU_HASH,
 BPF_MAP_TYPE_LPM_TRIE,
 BPF_MAP_TYPE_ARRAY_OF_MAPS,
 BPF_MAP_TYPE_HASH_OF_MAPS,
 BPF_MAP_TYPE_DEVMAP,
 BPF_MAP_TYPE_SOCKMAP,
 BPF_MAP_TYPE_CPUMAP,
 BPF_MAP_TYPE_XSKMAP,
 BPF_MAP_TYPE_SOCKHASH,
 BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,






 BPF_MAP_TYPE_CGROUP_STORAGE = BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
 BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
 BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE,
 BPF_MAP_TYPE_QUEUE,
 BPF_MAP_TYPE_STACK,
 BPF_MAP_TYPE_SK_STORAGE,
 BPF_MAP_TYPE_DEVMAP_HASH,
 BPF_MAP_TYPE_STRUCT_OPS,
 BPF_MAP_TYPE_RINGBUF,
 BPF_MAP_TYPE_INODE_STORAGE,
 BPF_MAP_TYPE_TASK_STORAGE,
 BPF_MAP_TYPE_BLOOM_FILTER,
 BPF_MAP_TYPE_USER_RINGBUF,
 BPF_MAP_TYPE_CGRP_STORAGE,
};
# 956 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum bpf_prog_type {
 BPF_PROG_TYPE_UNSPEC,
 BPF_PROG_TYPE_SOCKET_FILTER,
 BPF_PROG_TYPE_KPROBE,
 BPF_PROG_TYPE_SCHED_CLS,
 BPF_PROG_TYPE_SCHED_ACT,
 BPF_PROG_TYPE_TRACEPOINT,
 BPF_PROG_TYPE_XDP,
 BPF_PROG_TYPE_PERF_EVENT,
 BPF_PROG_TYPE_CGROUP_SKB,
 BPF_PROG_TYPE_CGROUP_SOCK,
 BPF_PROG_TYPE_LWT_IN,
 BPF_PROG_TYPE_LWT_OUT,
 BPF_PROG_TYPE_LWT_XMIT,
 BPF_PROG_TYPE_SOCK_OPS,
 BPF_PROG_TYPE_SK_SKB,
 BPF_PROG_TYPE_CGROUP_DEVICE,
 BPF_PROG_TYPE_SK_MSG,
 BPF_PROG_TYPE_RAW_TRACEPOINT,
 BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
 BPF_PROG_TYPE_LWT_SEG6LOCAL,
 BPF_PROG_TYPE_LIRC_MODE2,
 BPF_PROG_TYPE_SK_REUSEPORT,
 BPF_PROG_TYPE_FLOW_DISSECTOR,
 BPF_PROG_TYPE_CGROUP_SYSCTL,
 BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
 BPF_PROG_TYPE_CGROUP_SOCKOPT,
 BPF_PROG_TYPE_TRACING,
 BPF_PROG_TYPE_STRUCT_OPS,
 BPF_PROG_TYPE_EXT,
 BPF_PROG_TYPE_LSM,
 BPF_PROG_TYPE_SK_LOOKUP,
 BPF_PROG_TYPE_SYSCALL,
};

enum bpf_attach_type {
 BPF_CGROUP_INET_INGRESS,
 BPF_CGROUP_INET_EGRESS,
 BPF_CGROUP_INET_SOCK_CREATE,
 BPF_CGROUP_SOCK_OPS,
 BPF_SK_SKB_STREAM_PARSER,
 BPF_SK_SKB_STREAM_VERDICT,
 BPF_CGROUP_DEVICE,
 BPF_SK_MSG_VERDICT,
 BPF_CGROUP_INET4_BIND,
 BPF_CGROUP_INET6_BIND,
 BPF_CGROUP_INET4_CONNECT,
 BPF_CGROUP_INET6_CONNECT,
 BPF_CGROUP_INET4_POST_BIND,
 BPF_CGROUP_INET6_POST_BIND,
 BPF_CGROUP_UDP4_SENDMSG,
 BPF_CGROUP_UDP6_SENDMSG,
 BPF_LIRC_MODE2,
 BPF_FLOW_DISSECTOR,
 BPF_CGROUP_SYSCTL,
 BPF_CGROUP_UDP4_RECVMSG,
 BPF_CGROUP_UDP6_RECVMSG,
 BPF_CGROUP_GETSOCKOPT,
 BPF_CGROUP_SETSOCKOPT,
 BPF_TRACE_RAW_TP,
 BPF_TRACE_FENTRY,
 BPF_TRACE_FEXIT,
 BPF_MODIFY_RETURN,
 BPF_LSM_MAC,
 BPF_TRACE_ITER,
 BPF_CGROUP_INET4_GETPEERNAME,
 BPF_CGROUP_INET6_GETPEERNAME,
 BPF_CGROUP_INET4_GETSOCKNAME,
 BPF_CGROUP_INET6_GETSOCKNAME,
 BPF_XDP_DEVMAP,
 BPF_CGROUP_INET_SOCK_RELEASE,
 BPF_XDP_CPUMAP,
 BPF_SK_LOOKUP,
 BPF_XDP,
 BPF_SK_SKB_VERDICT,
 BPF_SK_REUSEPORT_SELECT,
 BPF_SK_REUSEPORT_SELECT_OR_MIGRATE,
 BPF_PERF_EVENT,
 BPF_TRACE_KPROBE_MULTI,
 BPF_LSM_CGROUP,
 BPF_STRUCT_OPS,
 __MAX_BPF_ATTACH_TYPE
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
 BPF_LINK_TYPE_STRUCT_OPS = 9,

 MAX_BPF_LINK_TYPE,
};
# 1225 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum {
 BPF_ANY = 0,
 BPF_NOEXIST = 1,
 BPF_EXIST = 2,
 BPF_F_LOCK = 4,
};


enum {
 BPF_F_NO_PREALLOC = (1U << 0),






 BPF_F_NO_COMMON_LRU = (1U << 1),

 BPF_F_NUMA_NODE = (1U << 2),


 BPF_F_RDONLY = (1U << 3),
 BPF_F_WRONLY = (1U << 4),


 BPF_F_STACK_BUILD_ID = (1U << 5),


 BPF_F_ZERO_SEED = (1U << 6),


 BPF_F_RDONLY_PROG = (1U << 7),
 BPF_F_WRONLY_PROG = (1U << 8),


 BPF_F_CLONE = (1U << 9),


 BPF_F_MMAPABLE = (1U << 10),


 BPF_F_PRESERVE_ELEMS = (1U << 11),


 BPF_F_INNER_MAP = (1U << 12),


 BPF_F_LINK = (1U << 13),
};
# 1291 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum bpf_stats_type {

 BPF_STATS_RUN_TIME = 0,
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



union bpf_attr {
 struct {
  __u32 map_type;
  __u32 key_size;
  __u32 value_size;
  __u32 max_entries;
  __u32 map_flags;


  __u32 inner_map_fd;
  __u32 numa_node;


  char map_name[16U];
  __u32 map_ifindex;
  __u32 btf_fd;
  __u32 btf_key_type_id;
  __u32 btf_value_type_id;
  __u32 btf_vmlinux_value_type_id;
# 1345 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
  __u64 map_extra;
 };

 struct {
  __u32 map_fd;
  __u64 __attribute__((aligned(8))) key;
  union {
   __u64 __attribute__((aligned(8))) value;
   __u64 __attribute__((aligned(8))) next_key;
  };
  __u64 flags;
 };

 struct {
  __u64 __attribute__((aligned(8))) in_batch;


  __u64 __attribute__((aligned(8))) out_batch;
  __u64 __attribute__((aligned(8))) keys;
  __u64 __attribute__((aligned(8))) values;
  __u32 count;




  __u32 map_fd;
  __u64 elem_flags;
  __u64 flags;
 } batch;

 struct {
  __u32 prog_type;
  __u32 insn_cnt;
  __u64 __attribute__((aligned(8))) insns;
  __u64 __attribute__((aligned(8))) license;
  __u32 log_level;
  __u32 log_size;
  __u64 __attribute__((aligned(8))) log_buf;
  __u32 kern_version;
  __u32 prog_flags;
  char prog_name[16U];
  __u32 prog_ifindex;




  __u32 expected_attach_type;
  __u32 prog_btf_fd;
  __u32 func_info_rec_size;
  __u64 __attribute__((aligned(8))) func_info;
  __u32 func_info_cnt;
  __u32 line_info_rec_size;
  __u64 __attribute__((aligned(8))) line_info;
  __u32 line_info_cnt;
  __u32 attach_btf_id;
  union {

   __u32 attach_prog_fd;

   __u32 attach_btf_obj_fd;
  };
  __u32 core_relo_cnt;
  __u64 __attribute__((aligned(8))) fd_array;
  __u64 __attribute__((aligned(8))) core_relos;
  __u32 core_relo_rec_size;
 };

 struct {
  __u64 __attribute__((aligned(8))) pathname;
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



  __u64 __attribute__((aligned(8))) data_in;
  __u64 __attribute__((aligned(8))) data_out;
  __u32 repeat;
  __u32 duration;
  __u32 ctx_size_in;
  __u32 ctx_size_out;



  __u64 __attribute__((aligned(8))) ctx_in;
  __u64 __attribute__((aligned(8))) ctx_out;
  __u32 flags;
  __u32 cpu;
  __u32 batch_size;
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
  __u64 __attribute__((aligned(8))) info;
 } info;

 struct {
  __u32 target_fd;
  __u32 attach_type;
  __u32 query_flags;
  __u32 attach_flags;
  __u64 __attribute__((aligned(8))) prog_ids;
  __u32 prog_cnt;



  __u64 __attribute__((aligned(8))) prog_attach_flags;
 } query;

 struct {
  __u64 name;
  __u32 prog_fd;
 } raw_tracepoint;

 struct {
  __u64 __attribute__((aligned(8))) btf;
  __u64 __attribute__((aligned(8))) btf_log_buf;
  __u32 btf_size;
  __u32 btf_log_size;
  __u32 btf_log_level;
 };

 struct {
  __u32 pid;
  __u32 fd;
  __u32 flags;
  __u32 buf_len;
  __u64 __attribute__((aligned(8))) buf;




  __u32 prog_id;
  __u32 fd_type;
  __u64 probe_offset;
  __u64 probe_addr;
 } task_fd_query;

 struct {
  union {
   __u32 prog_fd;
   __u32 map_fd;
  };
  union {
   __u32 target_fd;
   __u32 target_ifindex;
  };
  __u32 attach_type;
  __u32 flags;
  union {
   __u32 target_btf_id;
   struct {
    __u64 __attribute__((aligned(8))) iter_info;
    __u32 iter_info_len;
   };
   struct {




    __u64 bpf_cookie;
   } perf_event;
   struct {
    __u32 flags;
    __u32 cnt;
    __u64 __attribute__((aligned(8))) syms;
    __u64 __attribute__((aligned(8))) addrs;
    __u64 __attribute__((aligned(8))) cookies;
   } kprobe_multi;
   struct {

    __u32 target_btf_id;




    __u64 cookie;
   } tracing;
  };
 } link_create;

 struct {
  __u32 link_fd;
  union {

   __u32 new_prog_fd;

   __u32 new_map_fd;
  };
  __u32 flags;
  union {



   __u32 old_prog_fd;



   __u32 old_map_fd;
  };
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

} __attribute__((aligned(8)));
# 5769 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum bpf_func_id {
 BPF_FUNC_unspec = 0, BPF_FUNC_map_lookup_elem = 1, BPF_FUNC_map_update_elem = 2, BPF_FUNC_map_delete_elem = 3, BPF_FUNC_probe_read = 4, BPF_FUNC_ktime_get_ns = 5, BPF_FUNC_trace_printk = 6, BPF_FUNC_get_prandom_u32 = 7, BPF_FUNC_get_smp_processor_id = 8, BPF_FUNC_skb_store_bytes = 9, BPF_FUNC_l3_csum_replace = 10, BPF_FUNC_l4_csum_replace = 11, BPF_FUNC_tail_call = 12, BPF_FUNC_clone_redirect = 13, BPF_FUNC_get_current_pid_tgid = 14, BPF_FUNC_get_current_uid_gid = 15, BPF_FUNC_get_current_comm = 16, BPF_FUNC_get_cgroup_classid = 17, BPF_FUNC_skb_vlan_push = 18, BPF_FUNC_skb_vlan_pop = 19, BPF_FUNC_skb_get_tunnel_key = 20, BPF_FUNC_skb_set_tunnel_key = 21, BPF_FUNC_perf_event_read = 22, BPF_FUNC_redirect = 23, BPF_FUNC_get_route_realm = 24, BPF_FUNC_perf_event_output = 25, BPF_FUNC_skb_load_bytes = 26, BPF_FUNC_get_stackid = 27, BPF_FUNC_csum_diff = 28, BPF_FUNC_skb_get_tunnel_opt = 29, BPF_FUNC_skb_set_tunnel_opt = 30, BPF_FUNC_skb_change_proto = 31, BPF_FUNC_skb_change_type = 32, BPF_FUNC_skb_under_cgroup = 33, BPF_FUNC_get_hash_recalc = 34, BPF_FUNC_get_current_task = 35, BPF_FUNC_probe_write_user = 36, BPF_FUNC_current_task_under_cgroup = 37, BPF_FUNC_skb_change_tail = 38, BPF_FUNC_skb_pull_data = 39, BPF_FUNC_csum_update = 40, BPF_FUNC_set_hash_invalid = 41, BPF_FUNC_get_numa_node_id = 42, BPF_FUNC_skb_change_head = 43, BPF_FUNC_xdp_adjust_head = 44, BPF_FUNC_probe_read_str = 45, BPF_FUNC_get_socket_cookie = 46, BPF_FUNC_get_socket_uid = 47, BPF_FUNC_set_hash = 48, BPF_FUNC_setsockopt = 49, BPF_FUNC_skb_adjust_room = 50, BPF_FUNC_redirect_map = 51, BPF_FUNC_sk_redirect_map = 52, BPF_FUNC_sock_map_update = 53, BPF_FUNC_xdp_adjust_meta = 54, BPF_FUNC_perf_event_read_value = 55, BPF_FUNC_perf_prog_read_value = 56, BPF_FUNC_getsockopt = 57, BPF_FUNC_override_return = 58, BPF_FUNC_sock_ops_cb_flags_set = 59, BPF_FUNC_msg_redirect_map = 60, BPF_FUNC_msg_apply_bytes = 61, BPF_FUNC_msg_cork_bytes = 62, BPF_FUNC_msg_pull_data = 63, BPF_FUNC_bind = 64, BPF_FUNC_xdp_adjust_tail = 65, BPF_FUNC_skb_get_xfrm_state = 66, BPF_FUNC_get_stack = 67, BPF_FUNC_skb_load_bytes_relative = 68, BPF_FUNC_fib_lookup = 69, BPF_FUNC_sock_hash_update = 70, BPF_FUNC_msg_redirect_hash = 71, BPF_FUNC_sk_redirect_hash = 72, BPF_FUNC_lwt_push_encap = 73, BPF_FUNC_lwt_seg6_store_bytes = 74, BPF_FUNC_lwt_seg6_adjust_srh = 75, BPF_FUNC_lwt_seg6_action = 76, BPF_FUNC_rc_repeat = 77, BPF_FUNC_rc_keydown = 78, BPF_FUNC_skb_cgroup_id = 79, BPF_FUNC_get_current_cgroup_id = 80, BPF_FUNC_get_local_storage = 81, BPF_FUNC_sk_select_reuseport = 82, BPF_FUNC_skb_ancestor_cgroup_id = 83, BPF_FUNC_sk_lookup_tcp = 84, BPF_FUNC_sk_lookup_udp = 85, BPF_FUNC_sk_release = 86, BPF_FUNC_map_push_elem = 87, BPF_FUNC_map_pop_elem = 88, BPF_FUNC_map_peek_elem = 89, BPF_FUNC_msg_push_data = 90, BPF_FUNC_msg_pop_data = 91, BPF_FUNC_rc_pointer_rel = 92, BPF_FUNC_spin_lock = 93, BPF_FUNC_spin_unlock = 94, BPF_FUNC_sk_fullsock = 95, BPF_FUNC_tcp_sock = 96, BPF_FUNC_skb_ecn_set_ce = 97, BPF_FUNC_get_listener_sock = 98, BPF_FUNC_skc_lookup_tcp = 99, BPF_FUNC_tcp_check_syncookie = 100, BPF_FUNC_sysctl_get_name = 101, BPF_FUNC_sysctl_get_current_value = 102, BPF_FUNC_sysctl_get_new_value = 103, BPF_FUNC_sysctl_set_new_value = 104, BPF_FUNC_strtol = 105, BPF_FUNC_strtoul = 106, BPF_FUNC_sk_storage_get = 107, BPF_FUNC_sk_storage_delete = 108, BPF_FUNC_send_signal = 109, BPF_FUNC_tcp_gen_syncookie = 110, BPF_FUNC_skb_output = 111, BPF_FUNC_probe_read_user = 112, BPF_FUNC_probe_read_kernel = 113, BPF_FUNC_probe_read_user_str = 114, BPF_FUNC_probe_read_kernel_str = 115, BPF_FUNC_tcp_send_ack = 116, BPF_FUNC_send_signal_thread = 117, BPF_FUNC_jiffies64 = 118, BPF_FUNC_read_branch_records = 119, BPF_FUNC_get_ns_current_pid_tgid = 120, BPF_FUNC_xdp_output = 121, BPF_FUNC_get_netns_cookie = 122, BPF_FUNC_get_current_ancestor_cgroup_id = 123, BPF_FUNC_sk_assign = 124, BPF_FUNC_ktime_get_boot_ns = 125, BPF_FUNC_seq_printf = 126, BPF_FUNC_seq_write = 127, BPF_FUNC_sk_cgroup_id = 128, BPF_FUNC_sk_ancestor_cgroup_id = 129, BPF_FUNC_ringbuf_output = 130, BPF_FUNC_ringbuf_reserve = 131, BPF_FUNC_ringbuf_submit = 132, BPF_FUNC_ringbuf_discard = 133, BPF_FUNC_ringbuf_query = 134, BPF_FUNC_csum_level = 135, BPF_FUNC_skc_to_tcp6_sock = 136, BPF_FUNC_skc_to_tcp_sock = 137, BPF_FUNC_skc_to_tcp_timewait_sock = 138, BPF_FUNC_skc_to_tcp_request_sock = 139, BPF_FUNC_skc_to_udp6_sock = 140, BPF_FUNC_get_task_stack = 141, BPF_FUNC_load_hdr_opt = 142, BPF_FUNC_store_hdr_opt = 143, BPF_FUNC_reserve_hdr_opt = 144, BPF_FUNC_inode_storage_get = 145, BPF_FUNC_inode_storage_delete = 146, BPF_FUNC_d_path = 147, BPF_FUNC_copy_from_user = 148, BPF_FUNC_snprintf_btf = 149, BPF_FUNC_seq_printf_btf = 150, BPF_FUNC_skb_cgroup_classid = 151, BPF_FUNC_redirect_neigh = 152, BPF_FUNC_per_cpu_ptr = 153, BPF_FUNC_this_cpu_ptr = 154, BPF_FUNC_redirect_peer = 155, BPF_FUNC_task_storage_get = 156, BPF_FUNC_task_storage_delete = 157, BPF_FUNC_get_current_task_btf = 158, BPF_FUNC_bprm_opts_set = 159, BPF_FUNC_ktime_get_coarse_ns = 160, BPF_FUNC_ima_inode_hash = 161, BPF_FUNC_sock_from_file = 162, BPF_FUNC_check_mtu = 163, BPF_FUNC_for_each_map_elem = 164, BPF_FUNC_snprintf = 165, BPF_FUNC_sys_bpf = 166, BPF_FUNC_btf_find_by_name_kind = 167, BPF_FUNC_sys_close = 168, BPF_FUNC_timer_init = 169, BPF_FUNC_timer_set_callback = 170, BPF_FUNC_timer_start = 171, BPF_FUNC_timer_cancel = 172, BPF_FUNC_get_func_ip = 173, BPF_FUNC_get_attach_cookie = 174, BPF_FUNC_task_pt_regs = 175, BPF_FUNC_get_branch_snapshot = 176, BPF_FUNC_trace_vprintk = 177, BPF_FUNC_skc_to_unix_sock = 178, BPF_FUNC_kallsyms_lookup_name = 179, BPF_FUNC_find_vma = 180, BPF_FUNC_loop = 181, BPF_FUNC_strncmp = 182, BPF_FUNC_get_func_arg = 183, BPF_FUNC_get_func_ret = 184, BPF_FUNC_get_func_arg_cnt = 185, BPF_FUNC_get_retval = 186, BPF_FUNC_set_retval = 187, BPF_FUNC_xdp_get_buff_len = 188, BPF_FUNC_xdp_load_bytes = 189, BPF_FUNC_xdp_store_bytes = 190, BPF_FUNC_copy_from_user_task = 191, BPF_FUNC_skb_set_tstamp = 192, BPF_FUNC_ima_file_hash = 193, BPF_FUNC_kptr_xchg = 194, BPF_FUNC_map_lookup_percpu_elem = 195, BPF_FUNC_skc_to_mptcp_sock = 196, BPF_FUNC_dynptr_from_mem = 197, BPF_FUNC_ringbuf_reserve_dynptr = 198, BPF_FUNC_ringbuf_submit_dynptr = 199, BPF_FUNC_ringbuf_discard_dynptr = 200, BPF_FUNC_dynptr_read = 201, BPF_FUNC_dynptr_write = 202, BPF_FUNC_dynptr_data = 203, BPF_FUNC_tcp_raw_gen_syncookie_ipv4 = 204, BPF_FUNC_tcp_raw_gen_syncookie_ipv6 = 205, BPF_FUNC_tcp_raw_check_syncookie_ipv4 = 206, BPF_FUNC_tcp_raw_check_syncookie_ipv6 = 207, BPF_FUNC_ktime_get_tai_ns = 208, BPF_FUNC_user_ringbuf_drain = 209, BPF_FUNC_cgrp_storage_get = 210, BPF_FUNC_cgrp_storage_delete = 211,
 __BPF_FUNC_MAX_ID,
};





enum {
 BPF_F_RECOMPUTE_CSUM = (1ULL << 0),
 BPF_F_INVALIDATE_HASH = (1ULL << 1),
};




enum {
 BPF_F_HDR_FIELD_MASK = 0xfULL,
};


enum {
 BPF_F_PSEUDO_HDR = (1ULL << 4),
 BPF_F_MARK_MANGLED_0 = (1ULL << 5),
 BPF_F_MARK_ENFORCE = (1ULL << 6),
};


enum {
 BPF_F_INGRESS = (1ULL << 0),
};


enum {
 BPF_F_TUNINFO_IPV6 = (1ULL << 0),
};


enum {
 BPF_F_SKIP_FIELD_MASK = 0xffULL,
 BPF_F_USER_STACK = (1ULL << 8),

 BPF_F_FAST_STACK_CMP = (1ULL << 9),
 BPF_F_REUSE_STACKID = (1ULL << 10),

 BPF_F_USER_BUILD_ID = (1ULL << 11),
};


enum {
 BPF_F_ZERO_CSUM_TX = (1ULL << 1),
 BPF_F_DONT_FRAGMENT = (1ULL << 2),
 BPF_F_SEQ_NUMBER = (1ULL << 3),
 BPF_F_NO_TUNNEL_KEY = (1ULL << 4),
};


enum {
 BPF_F_TUNINFO_FLAGS = (1ULL << 4),
};




enum {
 BPF_F_INDEX_MASK = 0xffffffffULL,
 BPF_F_CURRENT_CPU = BPF_F_INDEX_MASK,

 BPF_F_CTXLEN_MASK = (0xfffffULL << 32),
};


enum {
 BPF_F_CURRENT_NETNS = (-1L),
};


enum {
 BPF_CSUM_LEVEL_QUERY,
 BPF_CSUM_LEVEL_INC,
 BPF_CSUM_LEVEL_DEC,
 BPF_CSUM_LEVEL_RESET,
};


enum {
 BPF_F_ADJ_ROOM_FIXED_GSO = (1ULL << 0),
 BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 = (1ULL << 1),
 BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 = (1ULL << 2),
 BPF_F_ADJ_ROOM_ENCAP_L4_GRE = (1ULL << 3),
 BPF_F_ADJ_ROOM_ENCAP_L4_UDP = (1ULL << 4),
 BPF_F_ADJ_ROOM_NO_CSUM_RESET = (1ULL << 5),
 BPF_F_ADJ_ROOM_ENCAP_L2_ETH = (1ULL << 6),
 BPF_F_ADJ_ROOM_DECAP_L3_IPV4 = (1ULL << 7),
 BPF_F_ADJ_ROOM_DECAP_L3_IPV6 = (1ULL << 8),
};

enum {
 BPF_ADJ_ROOM_ENCAP_L2_MASK = 0xff,
 BPF_ADJ_ROOM_ENCAP_L2_SHIFT = 56,
};






enum {
 BPF_F_SYSCTL_BASE_NAME = (1ULL << 0),
};


enum {
 BPF_LOCAL_STORAGE_GET_F_CREATE = (1ULL << 0),



 BPF_SK_STORAGE_GET_F_CREATE = BPF_LOCAL_STORAGE_GET_F_CREATE,
};


enum {
 BPF_F_GET_BRANCH_RECORDS_SIZE = (1ULL << 0),
};




enum {
 BPF_RB_NO_WAKEUP = (1ULL << 0),
 BPF_RB_FORCE_WAKEUP = (1ULL << 1),
};


enum {
 BPF_RB_AVAIL_DATA = 0,
 BPF_RB_RING_SIZE = 1,
 BPF_RB_CONS_POS = 2,
 BPF_RB_PROD_POS = 3,
};


enum {
 BPF_RINGBUF_BUSY_BIT = (1U << 31),
 BPF_RINGBUF_DISCARD_BIT = (1U << 30),
 BPF_RINGBUF_HDR_SZ = 8,
};


enum {
 BPF_SK_LOOKUP_F_REPLACE = (1ULL << 0),
 BPF_SK_LOOKUP_F_NO_REUSEPORT = (1ULL << 1),
};


enum bpf_adj_room_mode {
 BPF_ADJ_ROOM_NET,
 BPF_ADJ_ROOM_MAC,
};


enum bpf_hdr_start_off {
 BPF_HDR_START_MAC,
 BPF_HDR_START_NET,
};


enum bpf_lwt_encap_mode {
 BPF_LWT_ENCAP_SEG6,
 BPF_LWT_ENCAP_SEG6_INLINE,
 BPF_LWT_ENCAP_IP,
};


enum {
 BPF_F_BPRM_SECUREEXEC = (1ULL << 0),
};


enum {
 BPF_F_BROADCAST = (1ULL << 3),
 BPF_F_EXCLUDE_INGRESS = (1ULL << 4),
};







enum {
 BPF_SKB_TSTAMP_UNSPEC,
 BPF_SKB_TSTAMP_DELIVERY_MONO,




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
 union { struct bpf_flow_keys * flow_keys; __u64 :64; } __attribute__((aligned(8)));
 __u64 tstamp;
 __u32 wire_len;
 __u32 gso_segs;
 union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
 __u32 gso_size;
 __u8 tstamp_type;
 __u32 :24;
 __u64 hwtstamp;
};

struct bpf_tunnel_key {
 __u32 tunnel_id;
 union {
  __u32 remote_ipv4;
  __u32 remote_ipv6[4];
 };
 __u8 tunnel_tos;
 __u8 tunnel_ttl;
 union {
  __u16 tunnel_ext;
  __be16 tunnel_flags;
 };
 __u32 tunnel_label;
 union {
  __u32 local_ipv4;
  __u32 local_ipv6[4];
 };
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
# 6054 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum bpf_ret_code {
 BPF_OK = 0,

 BPF_DROP = 2,

 BPF_REDIRECT = 7,
# 6068 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 BPF_LWT_REROUTE = 128,




 BPF_FLOW_DISSECTOR_CONTINUE = 129,
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
 __u16 :16;
 __u32 dst_ip4;
 __u32 dst_ip6[4];
 __u32 state;
 __s32 rx_queue_mapping;
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
# 6168 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum xdp_action {
 XDP_ABORTED = 0,
 XDP_DROP,
 XDP_PASS,
 XDP_TX,
 XDP_REDIRECT,
};




struct xdp_md {
 __u32 data;
 __u32 data_end;
 __u32 data_meta;

 __u32 ingress_ifindex;
 __u32 rx_queue_index;

 __u32 egress_ifindex;
};






struct bpf_devmap_val {
 __u32 ifindex;
 union {
  int fd;
  __u32 id;
 } bpf_prog;
};






struct bpf_cpumap_val {
 __u32 qsize;
 union {
  int fd;
  __u32 id;
 } bpf_prog;
};

enum sk_action {
 SK_DROP = 0,
 SK_PASS,
};




struct sk_msg_md {
 union { void * data; __u64 :64; } __attribute__((aligned(8)));
 union { void * data_end; __u64 :64; } __attribute__((aligned(8)));

 __u32 family;
 __u32 remote_ip4;
 __u32 local_ip4;
 __u32 remote_ip6[4];
 __u32 local_ip6[4];
 __u32 remote_port;
 __u32 local_port;
 __u32 size;

 union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
};

struct sk_reuseport_md {




 union { void * data; __u64 :64; } __attribute__((aligned(8)));

 union { void * data_end; __u64 :64; } __attribute__((aligned(8)));






 __u32 len;




 __u32 eth_protocol;
 __u32 ip_protocol;
 __u32 bind_inany;
 __u32 hash;
# 6275 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
 union { struct bpf_sock * migrating_sk; __u64 :64; } __attribute__((aligned(8)));
};



struct bpf_prog_info {
 __u32 type;
 __u32 id;
 __u8 tag[8];
 __u32 jited_prog_len;
 __u32 xlated_prog_len;
 __u64 __attribute__((aligned(8))) jited_prog_insns;
 __u64 __attribute__((aligned(8))) xlated_prog_insns;
 __u64 load_time;
 __u32 created_by_uid;
 __u32 nr_map_ids;
 __u64 __attribute__((aligned(8))) map_ids;
 char name[16U];
 __u32 ifindex;
 __u32 gpl_compatible:1;
 __u32 :31;
 __u64 netns_dev;
 __u64 netns_ino;
 __u32 nr_jited_ksyms;
 __u32 nr_jited_func_lens;
 __u64 __attribute__((aligned(8))) jited_ksyms;
 __u64 __attribute__((aligned(8))) jited_func_lens;
 __u32 btf_id;
 __u32 func_info_rec_size;
 __u64 __attribute__((aligned(8))) func_info;
 __u32 nr_func_info;
 __u32 nr_line_info;
 __u64 __attribute__((aligned(8))) line_info;
 __u64 __attribute__((aligned(8))) jited_line_info;
 __u32 nr_jited_line_info;
 __u32 line_info_rec_size;
 __u32 jited_line_info_rec_size;
 __u32 nr_prog_tags;
 __u64 __attribute__((aligned(8))) prog_tags;
 __u64 run_time_ns;
 __u64 run_cnt;
 __u64 recursion_misses;
 __u32 verified_insns;
 __u32 attach_btf_obj_id;
 __u32 attach_btf_id;
} __attribute__((aligned(8)));

struct bpf_map_info {
 __u32 type;
 __u32 id;
 __u32 key_size;
 __u32 value_size;
 __u32 max_entries;
 __u32 map_flags;
 char name[16U];
 __u32 ifindex;
 __u32 btf_vmlinux_value_type_id;
 __u64 netns_dev;
 __u64 netns_ino;
 __u32 btf_id;
 __u32 btf_key_type_id;
 __u32 btf_value_type_id;
 __u32 :32;
 __u64 map_extra;
} __attribute__((aligned(8)));

struct bpf_btf_info {
 __u64 __attribute__((aligned(8))) btf;
 __u32 btf_size;
 __u32 id;
 __u64 __attribute__((aligned(8))) name;
 __u32 name_len;
 __u32 kernel_btf;
} __attribute__((aligned(8)));

struct bpf_link_info {
 __u32 type;
 __u32 id;
 __u32 prog_id;
 union {
  struct {
   __u64 __attribute__((aligned(8))) tp_name;
   __u32 tp_name_len;
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
   __u64 __attribute__((aligned(8))) target_name;
   __u32 target_name_len;





   union {
    struct {
     __u32 map_id;
    } map;
   };
   union {
    struct {
     __u64 cgroup_id;
     __u32 order;
    } cgroup;
    struct {
     __u32 tid;
     __u32 pid;
    } task;
   };
  } iter;
  struct {
   __u32 netns_ino;
   __u32 attach_type;
  } netns;
  struct {
   __u32 ifindex;
  } xdp;
  struct {
   __u32 map_id;
  } struct_ops;
 };
} __attribute__((aligned(8)));





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


 union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
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
 union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
# 6497 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 union { void * skb_data; __u64 :64; } __attribute__((aligned(8)));
 union { void * skb_data_end; __u64 :64; } __attribute__((aligned(8)));
 __u32 skb_len;



 __u32 skb_tcp_flags;
# 6513 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 __u64 skb_hwtstamp;
};


enum {
 BPF_SOCK_OPS_RTO_CB_FLAG = (1<<0),
 BPF_SOCK_OPS_RETRANS_CB_FLAG = (1<<1),
 BPF_SOCK_OPS_STATE_CB_FLAG = (1<<2),
 BPF_SOCK_OPS_RTT_CB_FLAG = (1<<3),
# 6540 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 BPF_SOCK_OPS_PARSE_ALL_HDR_OPT_CB_FLAG = (1<<4),
# 6549 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 BPF_SOCK_OPS_PARSE_UNKNOWN_HDR_OPT_CB_FLAG = (1<<5),
# 6564 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG = (1<<6),

 BPF_SOCK_OPS_ALL_CB_FLAGS = 0x7F,
};




enum {
 BPF_SOCK_OPS_VOID,
 BPF_SOCK_OPS_TIMEOUT_INIT,


 BPF_SOCK_OPS_RWND_INIT,



 BPF_SOCK_OPS_TCP_CONNECT_CB,


 BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB,



 BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,



 BPF_SOCK_OPS_NEEDS_ECN,


 BPF_SOCK_OPS_BASE_RTT,






 BPF_SOCK_OPS_RTO_CB,




 BPF_SOCK_OPS_RETRANS_CB,





 BPF_SOCK_OPS_STATE_CB,



 BPF_SOCK_OPS_TCP_LISTEN_CB,


 BPF_SOCK_OPS_RTT_CB,

 BPF_SOCK_OPS_PARSE_HDR_OPT_CB,
# 6636 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 BPF_SOCK_OPS_HDR_OPT_LEN_CB,
# 6653 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 BPF_SOCK_OPS_WRITE_HDR_OPT_CB,
# 6679 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
};






enum {
 BPF_TCP_ESTABLISHED = 1,
 BPF_TCP_SYN_SENT,
 BPF_TCP_SYN_RECV,
 BPF_TCP_FIN_WAIT1,
 BPF_TCP_FIN_WAIT2,
 BPF_TCP_TIME_WAIT,
 BPF_TCP_CLOSE,
 BPF_TCP_CLOSE_WAIT,
 BPF_TCP_LAST_ACK,
 BPF_TCP_LISTEN,
 BPF_TCP_CLOSING,
 BPF_TCP_NEW_SYN_RECV,

 BPF_TCP_MAX_STATES
};

enum {
 TCP_BPF_IW = 1001,
 TCP_BPF_SNDCWND_CLAMP = 1002,
 TCP_BPF_DELACK_MAX = 1003,
 TCP_BPF_RTO_MIN = 1004,
# 6740 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
 TCP_BPF_SYN = 1005,
 TCP_BPF_SYN_IP = 1006,
 TCP_BPF_SYN_MAC = 1007,
};

enum {
 BPF_LOAD_HDR_OPT_TCP_SYN = (1ULL << 0),
};




enum {
 BPF_WRITE_HDR_TCP_CURRENT_MSS = 1,






 BPF_WRITE_HDR_TCP_SYNACK_COOKIE = 2,


};

struct bpf_perf_event_value {
 __u64 counter;
 __u64 enabled;
 __u64 running;
};

enum {
 BPF_DEVCG_ACC_MKNOD = (1ULL << 0),
 BPF_DEVCG_ACC_READ = (1ULL << 1),
 BPF_DEVCG_ACC_WRITE = (1ULL << 2),
};

enum {
 BPF_DEVCG_DEV_BLOCK = (1ULL << 0),
 BPF_DEVCG_DEV_CHAR = (1ULL << 1),
};

struct bpf_cgroup_dev_ctx {

 __u32 access_type;
 __u32 major;
 __u32 minor;
};

struct bpf_raw_tracepoint_args {
 __u64 args[0];
};




enum {
 BPF_FIB_LOOKUP_DIRECT = (1U << 0),
 BPF_FIB_LOOKUP_OUTPUT = (1U << 1),
 BPF_FIB_LOOKUP_SKIP_NEIGH = (1U << 2),
};

enum {
 BPF_FIB_LKUP_RET_SUCCESS,
 BPF_FIB_LKUP_RET_BLACKHOLE,
 BPF_FIB_LKUP_RET_UNREACHABLE,
 BPF_FIB_LKUP_RET_PROHIBIT,
 BPF_FIB_LKUP_RET_NOT_FWDED,
 BPF_FIB_LKUP_RET_FWD_DISABLED,
 BPF_FIB_LKUP_RET_UNSUPP_LWT,
 BPF_FIB_LKUP_RET_NO_NEIGH,
 BPF_FIB_LKUP_RET_FRAG_NEEDED,
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
 BPF_MTU_CHK_SEGS = (1U << 0),
};

enum bpf_check_mtu_ret {
 BPF_MTU_CHK_RET_SUCCESS,
 BPF_MTU_CHK_RET_FRAG_NEEDED,
 BPF_MTU_CHK_RET_SEGS_TOOBIG,
};

enum bpf_task_fd_type {
 BPF_FD_TYPE_RAW_TRACEPOINT,
 BPF_FD_TYPE_TRACEPOINT,
 BPF_FD_TYPE_KPROBE,
 BPF_FD_TYPE_KRETPROBE,
 BPF_FD_TYPE_UPROBE,
 BPF_FD_TYPE_URETPROBE,
};

enum {
 BPF_FLOW_DISSECTOR_F_PARSE_1ST_FRAG = (1U << 0),
 BPF_FLOW_DISSECTOR_F_STOP_AT_FLOW_LABEL = (1U << 1),
 BPF_FLOW_DISSECTOR_F_STOP_AT_ENCAP = (1U << 2),
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

struct bpf_spin_lock {
 __u32 val;
};

struct bpf_timer {
 __u64 :64;
 __u64 :64;
} __attribute__((aligned(8)));

struct bpf_dynptr {
 __u64 :64;
 __u64 :64;
} __attribute__((aligned(8)));

struct bpf_list_head {
 __u64 :64;
 __u64 :64;
} __attribute__((aligned(8)));

struct bpf_list_node {
 __u64 :64;
 __u64 :64;
} __attribute__((aligned(8)));

struct bpf_rb_root {
 __u64 :64;
 __u64 :64;
} __attribute__((aligned(8)));

struct bpf_rb_node {
 __u64 :64;
 __u64 :64;
 __u64 :64;
} __attribute__((aligned(8)));

struct bpf_sysctl {
 __u32 write;


 __u32 file_pos;


};

struct bpf_sockopt {
 union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
 union { void * optval; __u64 :64; } __attribute__((aligned(8)));
 union { void * optval_end; __u64 :64; } __attribute__((aligned(8)));

 __s32 level;
 __s32 optname;
 __s32 optlen;
 __s32 retval;
};

struct bpf_pidns_info {
 __u32 pid;
 __u32 tgid;
};


struct bpf_sk_lookup {
 union {
  union { struct bpf_sock * sk; __u64 :64; } __attribute__((aligned(8)));
  __u64 cookie;
 };

 __u32 family;
 __u32 protocol;
 __u32 remote_ip4;
 __u32 remote_ip6[4];
 __be16 remote_port;
 __u16 :16;
 __u32 local_ip4;
 __u32 local_ip6[4];
 __u32 local_port;
 __u32 ingress_ifindex;
};
# 7030 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
struct btf_ptr {
 void *ptr;
 __u32 type_id;
 __u32 flags;
};
# 7045 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
enum {
 BTF_F_COMPACT = (1ULL << 0),
 BTF_F_NONAME = (1ULL << 1),
 BTF_F_PTR_RAW = (1ULL << 2),
 BTF_F_ZERO = (1ULL << 3),
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
 BPF_CORE_TYPE_MATCHES = 12,
};
# 7120 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/linux/bpf.h"
struct bpf_core_relo {
 __u32 insn_off;
 __u32 type_id;
 __u32 access_str_off;
 enum bpf_core_relo_kind kind;
};






enum {
 BPF_F_TIMER_ABS = (1ULL << 0),
};


struct bpf_iter_num {



 __u64 __opaque[1];
} __attribute__((aligned(8)));
# 4 "uprobe.bpf.c" 2
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/linux/ptrace.h" 1
# 59 "/tools/arc-linux-gnu/sysroot/usr/include/linux/ptrace.h"
struct ptrace_peeksiginfo_args {
 __u64 off;
 __u32 flags;
 __s32 nr;
};







struct seccomp_metadata {
 __u64 filter_off;
 __u64 flags;
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



struct ptrace_rseq_configuration {
 __u64 rseq_abi_pointer;
 __u32 rseq_abi_size;
 __u32 signature;
 __u32 flags;
 __u32 pad;
};
# 153 "/tools/arc-linux-gnu/sysroot/usr/include/linux/ptrace.h"
# 1 "/tools/arc-linux-gnu/sysroot/usr/include/asm/ptrace.h" 1
# 34 "/tools/arc-linux-gnu/sysroot/usr/include/asm/ptrace.h"
struct user_regs_struct {

 unsigned long pad;
 struct {
  unsigned long bta, lp_start, lp_end, lp_count;
  unsigned long status32, ret, blink, fp, gp;
  unsigned long r12, r11, r10, r9, r8, r7, r6, r5, r4, r3, r2, r1, r0;
  unsigned long sp;
 } scratch;
 unsigned long pad2;
 struct {
  unsigned long r25, r24, r23, r22, r21, r20;
  unsigned long r19, r18, r17, r16, r15, r14, r13;
 } callee;
 unsigned long efa;
 unsigned long stop_pc;
};

struct user_regs_arcv2 {
 unsigned long r30, r58, r59;
};

struct user_regs_arcv3 {
 unsigned long fpr[32];
};
# 154 "/tools/arc-linux-gnu/sysroot/usr/include/linux/ptrace.h" 2
# 5 "uprobe.bpf.c" 2
# 1 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helpers.h" 1
# 11 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helpers.h"
# 1 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h" 1



struct bpf_fib_lookup;
struct bpf_sk_lookup;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_pidns_info;
struct bpf_redir_neigh;
struct bpf_sock;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct bpf_sock_tuple;
struct bpf_spin_lock;
struct bpf_sysctl;
struct bpf_tcp_sock;
struct bpf_tunnel_key;
struct bpf_xfrm_state;
struct linux_binprm;
struct pt_regs;
struct sk_reuseport_md;
struct sockaddr;
struct tcphdr;
struct seq_file;
struct tcp6_sock;
struct tcp_sock;
struct tcp_timewait_sock;
struct tcp_request_sock;
struct udp6_sock;
struct unix_sock;
struct task_struct;
struct cgroup;
struct __sk_buff;
struct sk_msg_md;
struct xdp_md;
struct path;
struct btf_ptr;
struct inode;
struct socket;
struct file;
struct bpf_timer;
struct mptcp_sock;
struct bpf_dynptr;
struct iphdr;
struct ipv6hdr;
# 56 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
# 78 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
# 88 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
# 102 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_read)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 4;
# 114 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;
# 177 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *) 6;
# 193 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u32 (*bpf_get_prandom_u32)(void) = (void *) 7;
# 206 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u32 (*bpf_get_smp_processor_id)(void) = (void *) 8;
# 227 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len, __u64 flags) = (void *) 9;
# 256 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 size) = (void *) 10;
# 292 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to, __u64 flags) = (void *) 11;
# 327 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_tail_call)(void *ctx, void *prog_array_map, __u32 index) = (void *) 12;
# 355 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_clone_redirect)(struct __sk_buff *skb, __u32 ifindex, __u64 flags) = (void *) 13;
# 368 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *) 14;
# 379 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;
# 394 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_current_comm)(void *buf, __u32 size_of_buf) = (void *) 16;
# 424 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u32 (*bpf_get_cgroup_classid)(struct __sk_buff *skb) = (void *) 17;
# 444 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_vlan_push)(struct __sk_buff *skb, __be16 vlan_proto, __u16 vlan_tci) = (void *) 18;
# 460 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_vlan_pop)(struct __sk_buff *skb) = (void *) 19;
# 515 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_get_tunnel_key)(struct __sk_buff *skb, struct bpf_tunnel_key *key, __u32 size, __u64 flags) = (void *) 20;
# 559 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_set_tunnel_key)(struct __sk_buff *skb, struct bpf_tunnel_key *key, __u32 size, __u64 flags) = (void *) 21;
# 592 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_perf_event_read)(void *map, __u64 flags) = (void *) 22;
# 619 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_redirect)(__u32 ifindex, __u64 flags) = (void *) 23;
# 647 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u32 (*bpf_get_route_realm)(struct __sk_buff *skb) = (void *) 24;
# 696 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_perf_event_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 25;
# 717 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *) 26;
# 763 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_stackid)(void *ctx, void *map, __u64 flags) = (void *) 27;
# 794 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to, __u32 to_size, __wsum seed) = (void *) 28;
# 816 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_get_tunnel_opt)(struct __sk_buff *skb, void *opt, __u32 size) = (void *) 29;
# 830 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_set_tunnel_opt)(struct __sk_buff *skb, void *opt, __u32 size) = (void *) 30;
# 861 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_change_proto)(struct __sk_buff *skb, __be16 proto, __u64 flags) = (void *) 31;
# 892 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_change_type)(struct __sk_buff *skb, __u32 type) = (void *) 32;
# 907 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_under_cgroup)(struct __sk_buff *skb, void *map, __u32 index) = (void *) 33;
# 927 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u32 (*bpf_get_hash_recalc)(struct __sk_buff *skb) = (void *) 34;
# 937 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_current_task)(void) = (void *) 35;
# 960 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_write_user)(void *dst, const void *src, __u32 len) = (void *) 36;
# 976 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_current_task_under_cgroup)(void *map, __u32 index) = (void *) 37;
# 1004 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_change_tail)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *) 38;
# 1045 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_pull_data)(struct __sk_buff *skb, __u32 len) = (void *) 39;
# 1061 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __s64 (*bpf_csum_update)(struct __sk_buff *skb, __wsum csum) = (void *) 40;
# 1075 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void (*bpf_set_hash_invalid)(struct __sk_buff *skb) = (void *) 41;
# 1090 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_numa_node_id)(void) = (void *) 42;
# 1115 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_change_head)(struct __sk_buff *skb, __u32 len, __u64 flags) = (void *) 43;
# 1134 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_xdp_adjust_head)(struct xdp_md *xdp_md, int delta) = (void *) 44;
# 1151 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_read_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 45;
# 1168 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *) 46;
# 1182 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u32 (*bpf_get_socket_uid)(struct __sk_buff *skb) = (void *) 47;
# 1193 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_set_hash)(struct __sk_buff *skb, __u32 hash) = (void *) 48;
# 1233 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_setsockopt)(void *bpf_socket, int level, int optname, void *optval, int optlen) = (void *) 49;
# 1294 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_adjust_room)(struct __sk_buff *skb, __s32 len_diff, __u32 mode, __u64 flags) = (void *) 50;
# 1323 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_redirect_map)(void *map, __u64 key, __u64 flags) = (void *) 51;
# 1338 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sk_redirect_map)(struct __sk_buff *skb, void *map, __u32 key, __u64 flags) = (void *) 52;
# 1361 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sock_map_update)(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags) = (void *) 53;
# 1394 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_xdp_adjust_meta)(struct xdp_md *xdp_md, int delta) = (void *) 54;
# 1448 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_perf_event_read_value)(void *map, __u64 flags, struct bpf_perf_event_value *buf, __u32 buf_size) = (void *) 55;
# 1463 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_perf_prog_read_value)(struct bpf_perf_event_data *ctx, struct bpf_perf_event_value *buf, __u32 buf_size) = (void *) 56;
# 1490 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_getsockopt)(void *bpf_socket, int level, int optname, void *optval, int optlen) = (void *) 57;
# 1519 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_override_return)(struct pt_regs *regs, __u64 rc) = (void *) 58;
# 1567 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sock_ops_cb_flags_set)(struct bpf_sock_ops *bpf_sock, int argval) = (void *) 59;
# 1585 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_redirect_map)(struct sk_msg_md *msg, void *map, __u32 key, __u64 flags) = (void *) 60;
# 1623 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_apply_bytes)(struct sk_msg_md *msg, __u32 bytes) = (void *) 61;
# 1645 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_cork_bytes)(struct sk_msg_md *msg, __u32 bytes) = (void *) 62;
# 1680 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_pull_data)(struct sk_msg_md *msg, __u32 start, __u32 end, __u64 flags) = (void *) 63;
# 1702 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_bind)(struct bpf_sock_addr *ctx, struct sockaddr *addr, int addr_len) = (void *) 64;
# 1720 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_xdp_adjust_tail)(struct xdp_md *xdp_md, int delta) = (void *) 65;
# 1740 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_get_xfrm_state)(struct __sk_buff *skb, __u32 index, struct bpf_xfrm_state *xfrm_state, __u32 size, __u64 flags) = (void *) 66;
# 1787 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_stack)(void *ctx, void *buf, __u32 size, __u64 flags) = (void *) 67;
# 1813 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_load_bytes_relative)(const void *skb, __u32 offset, void *to, __u32 len, __u32 start_header) = (void *) 68;
# 1856 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_fib_lookup)(void *ctx, struct bpf_fib_lookup *params, int plen, __u32 flags) = (void *) 69;
# 1879 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sock_hash_update)(struct bpf_sock_ops *skops, void *map, void *key, __u64 flags) = (void *) 70;
# 1897 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_redirect_hash)(struct sk_msg_md *msg, void *map, void *key, __u64 flags) = (void *) 71;
# 1915 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sk_redirect_hash)(struct __sk_buff *skb, void *map, void *key, __u64 flags) = (void *) 72;
# 1956 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_lwt_push_encap)(struct __sk_buff *skb, __u32 type, void *hdr, __u32 len) = (void *) 73;
# 1975 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_lwt_seg6_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len) = (void *) 74;
# 1995 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_lwt_seg6_adjust_srh)(struct __sk_buff *skb, __u32 offset, __s32 delta) = (void *) 75;
# 2028 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_lwt_seg6_action)(struct __sk_buff *skb, __u32 action, void *param, __u32 param_len) = (void *) 76;
# 2051 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_rc_repeat)(void *ctx) = (void *) 77;
# 2081 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_rc_keydown)(void *ctx, __u32 protocol, __u64 scancode, __u32 toggle) = (void *) 78;
# 2101 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_skb_cgroup_id)(struct __sk_buff *skb) = (void *) 79;
# 2113 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_current_cgroup_id)(void) = (void *) 80;
# 2135 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_get_local_storage)(void *map, __u64 flags) = (void *) 81;
# 2148 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sk_select_reuseport)(struct sk_reuseport_md *reuse, void *map, void *key, __u64 flags) = (void *) 82;
# 2170 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_skb_ancestor_cgroup_id)(struct __sk_buff *skb, int ancestor_level) = (void *) 83;
# 2211 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*bpf_sk_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *) 84;
# 2252 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*bpf_sk_lookup_udp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *) 85;
# 2264 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sk_release)(void *sock) = (void *) 86;
# 2278 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_map_push_elem)(void *map, const void *value, __u64 flags) = (void *) 87;
# 2288 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_map_pop_elem)(void *map, void *value) = (void *) 88;
# 2298 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_map_peek_elem)(void *map, void *value) = (void *) 89;
# 2318 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_push_data)(struct sk_msg_md *msg, __u32 start, __u32 len, __u64 flags) = (void *) 90;
# 2334 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_msg_pop_data)(struct sk_msg_md *msg, __u32 start, __u32 len, __u64 flags) = (void *) 91;
# 2352 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_rc_pointer_rel)(void *ctx, __s32 rel_x, __s32 rel_y) = (void *) 92;
# 2404 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *) 93;
# 2415 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *) 94;
# 2427 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*bpf_sk_fullsock)(struct bpf_sock *sk) = (void *) 95;
# 2439 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct bpf_tcp_sock *(*bpf_tcp_sock)(struct bpf_sock *sk) = (void *) 96;
# 2453 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_ecn_set_ce)(struct __sk_buff *skb) = (void *) 97;
# 2465 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*bpf_get_listener_sock)(struct bpf_sock *sk) = (void *) 98;
# 2488 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct bpf_sock *(*bpf_skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *) 99;
# 2508 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_tcp_check_syncookie)(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len) = (void *) 100;
# 2528 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sysctl_get_name)(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len, __u64 flags) = (void *) 101;
# 2551 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sysctl_get_current_value)(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len) = (void *) 102;
# 2572 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sysctl_get_new_value)(struct bpf_sysctl *ctx, char *buf, unsigned long buf_len) = (void *) 103;
# 2593 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sysctl_set_new_value)(struct bpf_sysctl *ctx, const char *buf, unsigned long buf_len) = (void *) 104;
# 2621 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_strtol)(const char *buf, unsigned long buf_len, __u64 flags, long *res) = (void *) 105;
# 2648 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_strtoul)(const char *buf, unsigned long buf_len, __u64 flags, unsigned long *res) = (void *) 106;
# 2683 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_sk_storage_get)(void *map, void *sk, void *value, __u64 flags) = (void *) 107;
# 2696 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sk_storage_delete)(void *map, void *sk) = (void *) 108;
# 2715 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_send_signal)(__u32 sig) = (void *) 109;
# 2746 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __s64 (*bpf_tcp_gen_syncookie)(void *sk, void *iph, __u32 iph_len, struct tcphdr *th, __u32 th_len) = (void *) 110;
# 2774 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 111;
# 2785 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 112;
# 2796 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 113;
# 2844 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 114;
# 2856 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_probe_read_kernel_str)(void *dst, __u32 size, const void *unsafe_ptr) = (void *) 115;
# 2867 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_tcp_send_ack)(void *tp, __u32 rcv_nxt) = (void *) 116;
# 2885 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_send_signal_thread)(__u32 sig) = (void *) 117;
# 2895 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_jiffies64)(void) = (void *) 118;
# 2918 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_read_branch_records)(struct bpf_perf_event_data *ctx, void *buf, __u32 size, __u64 flags) = (void *) 119;
# 2934 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_ns_current_pid_tgid)(__u64 dev, __u64 ino, struct bpf_pidns_info *nsdata, __u32 size) = (void *) 120;
# 2962 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_xdp_output)(void *ctx, void *map, __u64 flags, void *data, __u64 size) = (void *) 121;
# 2979 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_netns_cookie)(void *ctx) = (void *) 122;
# 3001 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_current_ancestor_cgroup_id)(int ancestor_level) = (void *) 123;
# 3036 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sk_assign)(void *ctx, void *sk, __u64 flags) = (void *) 124;
# 3048 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_ktime_get_boot_ns)(void) = (void *) 125;
# 3081 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_seq_printf)(struct seq_file *m, const char *fmt, __u32 fmt_size, const void *data, __u32 data_len) = (void *) 126;
# 3095 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_seq_write)(struct seq_file *m, const void *data, __u32 len) = (void *) 127;
# 3113 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_sk_cgroup_id)(void *sk) = (void *) 128;
# 3135 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_sk_ancestor_cgroup_id)(void *sk, int ancestor_level) = (void *) 129;
# 3156 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, __u64 size, __u64 flags) = (void *) 130;
# 3168 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) = (void *) 131;
# 3186 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *) 132;
# 3204 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void (*bpf_ringbuf_discard)(void *data, __u64 flags) = (void *) 133;
# 3225 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_ringbuf_query)(void *ringbuf, __u64 flags) = (void *) 134;
# 3261 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_csum_level)(struct __sk_buff *skb, __u64 level) = (void *) 135;
# 3271 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct tcp6_sock *(*bpf_skc_to_tcp6_sock)(void *sk) = (void *) 136;
# 3281 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct tcp_sock *(*bpf_skc_to_tcp_sock)(void *sk) = (void *) 137;
# 3291 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct tcp_timewait_sock *(*bpf_skc_to_tcp_timewait_sock)(void *sk) = (void *) 138;
# 3301 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct tcp_request_sock *(*bpf_skc_to_tcp_request_sock)(void *sk) = (void *) 139;
# 3311 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct udp6_sock *(*bpf_skc_to_udp6_sock)(void *sk) = (void *) 140;
# 3347 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_task_stack)(struct task_struct *task, void *buf, __u32 size, __u64 flags) = (void *) 141;
# 3414 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_load_hdr_opt)(struct bpf_sock_ops *skops, void *searchby_res, __u32 len, __u64 flags) = (void *) 142;
# 3451 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_store_hdr_opt)(struct bpf_sock_ops *skops, const void *from, __u32 len, __u64 flags) = (void *) 143;
# 3477 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_reserve_hdr_opt)(struct bpf_sock_ops *skops, __u32 len, __u64 flags) = (void *) 144;
# 3509 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_inode_storage_get)(void *map, void *inode, void *value, __u64 flags) = (void *) 145;
# 3521 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static int (*bpf_inode_storage_delete)(void *map, void *inode) = (void *) 146;
# 3537 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_d_path)(struct path *path, char *buf, __u32 sz) = (void *) 147;
# 3548 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_copy_from_user)(void *dst, __u32 size, const void *user_ptr) = (void *) 148;
# 3588 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_snprintf_btf)(char *str, __u32 str_size, struct btf_ptr *ptr, __u32 btf_ptr_size, __u64 flags) = (void *) 149;
# 3600 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_seq_printf_btf)(struct seq_file *m, struct btf_ptr *ptr, __u32 ptr_size, __u64 flags) = (void *) 150;
# 3613 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_skb_cgroup_classid)(struct __sk_buff *skb) = (void *) 151;
# 3638 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_redirect_neigh)(__u32 ifindex, struct bpf_redir_neigh *params, int plen, __u64 flags) = (void *) 152;
# 3659 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_per_cpu_ptr)(const void *percpu_ptr, __u32 cpu) = (void *) 153;
# 3675 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_this_cpu_ptr)(const void *percpu_ptr) = (void *) 154;
# 3695 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_redirect_peer)(__u32 ifindex, __u64 flags) = (void *) 155;
# 3727 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_task_storage_get)(void *map, struct task_struct *task, void *value, __u64 flags) = (void *) 156;
# 3739 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_task_storage_delete)(void *map, struct task_struct *task) = (void *) 157;
# 3751 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct task_struct *(*bpf_get_current_task_btf)(void) = (void *) 158;
# 3765 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_bprm_opts_set)(struct linux_binprm *bprm, __u64 flags) = (void *) 159;
# 3779 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_ktime_get_coarse_ns)(void) = (void *) 160;
# 3793 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_ima_inode_hash)(struct inode *inode, void *dst, __u32 size) = (void *) 161;
# 3805 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct socket *(*bpf_sock_from_file)(struct file *file) = (void *) 162;
# 3876 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_check_mtu)(void *ctx, __u32 ifindex, __u32 *mtu_len, __s32 len_diff, __u64 flags) = (void *) 163;
# 3909 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_for_each_map_elem)(void *map, void *callback_fn, void *callback_ctx, __u64 flags) = (void *) 164;
# 3941 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_snprintf)(char *str, __u32 str_size, const char *fmt, __u64 *data, __u32 data_len) = (void *) 165;
# 3951 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sys_bpf)(__u32 cmd, void *attr, __u32 attr_size) = (void *) 166;
# 3961 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_btf_find_by_name_kind)(char *name, int name_sz, __u32 kind, int flags) = (void *) 167;
# 3971 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_sys_close)(__u32 fd) = (void *) 168;
# 3992 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_timer_init)(struct bpf_timer *timer, void *map, __u64 flags) = (void *) 169;
# 4007 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_timer_set_callback)(struct bpf_timer *timer, void *callback_fn) = (void *) 170;
# 4043 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_timer_start)(struct bpf_timer *timer, __u64 nsecs, __u64 flags) = (void *) 171;
# 4057 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_timer_cancel)(struct bpf_timer *timer) = (void *) 172;
# 4068 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_func_ip)(void *ctx) = (void *) 173;
# 4087 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_get_attach_cookie)(void *ctx) = (void *) 174;
# 4097 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_task_pt_regs)(struct task_struct *task) = (void *) 175;
# 4122 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_branch_snapshot)(void *entries, __u32 size, __u64 flags) = (void *) 176;
# 4136 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_trace_vprintk)(const char *fmt, __u32 fmt_size, const void *data, __u32 data_len) = (void *) 177;
# 4146 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct unix_sock *(*bpf_skc_to_unix_sock)(void *sk) = (void *) 178;
# 4165 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_kallsyms_lookup_name)(const char *name, int name_sz, int flags, __u64 *res) = (void *) 179;
# 4188 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_find_vma)(struct task_struct *task, __u64 addr, void *callback_fn, void *callback_ctx, __u64 flags) = (void *) 180;
# 4216 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *) 181;
# 4230 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_strncmp)(const char *s1, __u32 s1_sz, const char *s2) = (void *) 182;
# 4243 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_func_arg)(void *ctx, __u32 n, __u64 *value) = (void *) 183;
# 4256 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_func_ret)(void *ctx, __u64 *value) = (void *) 184;
# 4268 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_get_func_arg_cnt)(void *ctx) = (void *) 185;
# 4281 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static int (*bpf_get_retval)(void) = (void *) 186;
# 4304 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static int (*bpf_set_retval)(int retval) = (void *) 187;
# 4314 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_xdp_get_buff_len)(struct xdp_md *xdp_md) = (void *) 188;
# 4327 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_xdp_load_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 189;
# 4338 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_xdp_store_bytes)(struct xdp_md *xdp_md, __u32 offset, void *buf, __u32 len) = (void *) 190;
# 4352 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_copy_from_user_task)(void *dst, __u32 size, const void *user_ptr, struct task_struct *tsk, __u64 flags) = (void *) 191;
# 4386 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_skb_set_tstamp)(struct __sk_buff *skb, __u64 tstamp, __u32 tstamp_type) = (void *) 192;
# 4400 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_ima_file_hash)(struct file *file, void *dst, __u32 size) = (void *) 193;
# 4415 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_kptr_xchg)(void *map_value, void *ptr) = (void *) 194;
# 4427 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_map_lookup_percpu_elem)(void *map, const void *key, __u32 cpu) = (void *) 195;
# 4437 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static struct mptcp_sock *(*bpf_skc_to_mptcp_sock)(void *sk) = (void *) 196;
# 4452 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_dynptr_from_mem)(void *data, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *) 197;
# 4467 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_ringbuf_reserve_dynptr)(void *ringbuf, __u32 size, __u64 flags, struct bpf_dynptr *ptr) = (void *) 198;
# 4482 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void (*bpf_ringbuf_submit_dynptr)(struct bpf_dynptr *ptr, __u64 flags) = (void *) 199;
# 4496 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void (*bpf_ringbuf_discard_dynptr)(struct bpf_dynptr *ptr, __u64 flags) = (void *) 200;
# 4510 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_dynptr_read)(void *dst, __u32 len, const struct bpf_dynptr *src, __u32 offset, __u64 flags) = (void *) 201;
# 4535 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_dynptr_write)(const struct bpf_dynptr *dst, __u32 offset, void *src, __u32 len, __u64 flags) = (void *) 202;
# 4553 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_dynptr_data)(const struct bpf_dynptr *ptr, __u32 offset, __u32 len) = (void *) 203;
# 4577 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __s64 (*bpf_tcp_raw_gen_syncookie_ipv4)(struct iphdr *iph, struct tcphdr *th, __u32 th_len) = (void *) 204;
# 4603 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __s64 (*bpf_tcp_raw_gen_syncookie_ipv6)(struct ipv6hdr *iph, struct tcphdr *th, __u32 th_len) = (void *) 205;
# 4622 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_tcp_raw_check_syncookie_ipv4)(struct iphdr *iph, struct tcphdr *th) = (void *) 206;
# 4643 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_tcp_raw_check_syncookie_ipv6)(struct ipv6hdr *iph, struct tcphdr *th) = (void *) 207;
# 4658 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static __u64 (*bpf_ktime_get_tai_ns)(void) = (void *) 208;
# 4700 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_user_ringbuf_drain)(void *map, void *callback_fn, void *ctx, __u64 flags) = (void *) 209;
# 4734 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static void *(*bpf_cgrp_storage_get)(void *map, struct cgroup *cgroup, void *value, __u64 flags) = (void *) 210;
# 4746 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helper_defs.h"
static long (*bpf_cgrp_storage_delete)(void *map, struct cgroup *cgroup) = (void *) 211;
# 12 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helpers.h" 2
# 135 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helpers.h"
static inline __attribute__((always_inline)) void
bpf_tail_call_static(void *ctx, const void *map, const __u32 slot)
{
 if (!__builtin_constant_p(slot))
  __builtin_trap();
# 154 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_helpers.h"
 asm volatile("r1 = %[ctx]\n\t"
       "r2 = %[map]\n\t"
       "r3 = %[slot]\n\t"
       "call 12"
       :: [ctx]"r"(ctx), [map]"r"(map), [slot]"i"(slot)
       : "r0", "r1", "r2", "r3", "r4", "r5");
}


enum libbpf_pin_type {
 LIBBPF_PIN_NONE,

 LIBBPF_PIN_BY_NAME,
};

enum libbpf_tristate {
 TRI_NO = 0,
 TRI_YES = 1,
 TRI_MODULE = 2,
};
# 6 "uprobe.bpf.c" 2
# 1 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_tracing.h" 1
# 449 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_tracing.h"
struct pt_regs;
# 787 "/home/ykolerov/workspace/bpf-arc/arc-bpf-framework/applications/deps/include/bpf/bpf_tracing.h"
struct pt_regs;
# 7 "uprobe.bpf.c" 2

char LICENSE[]
# 8 "uprobe.bpf.c"
#pragma GCC diagnostic push
# 8 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 8 "uprobe.bpf.c"
               __attribute__((section("license"), used))
# 8 "uprobe.bpf.c"
#pragma GCC diagnostic pop
# 8 "uprobe.bpf.c"
                              = "Dual BSD/GPL";

#pragma GCC diagnostic push
# 10 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 10 "uprobe.bpf.c"
 __attribute__((section("uprobe"), used))
# 10 "uprobe.bpf.c"
#pragma GCC diagnostic pop
int uprobe_add(struct pt_regs *ctx); static inline __attribute__((always_inline)) typeof(uprobe_add(0)) ____uprobe_add(struct pt_regs *ctx, int a, int b); typeof(uprobe_add(0)) uprobe_add(struct pt_regs *ctx) {
# 11 "uprobe.bpf.c"
#pragma GCC diagnostic push
# 11 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wint-conversion"
# 11 "uprobe.bpf.c"
    return ____uprobe_add(ctx, (void *)(((const struct user_regs_struct *)(ctx))->scratch.r0), (void *)(((const struct user_regs_struct *)(ctx))->scratch.r1));
# 11 "uprobe.bpf.c"
#pragma GCC diagnostic pop
# 11 "uprobe.bpf.c"
    } static inline __attribute__((always_inline)) typeof(uprobe_add(0)) ____uprobe_add(struct pt_regs *ctx, int a, int b)
{
 ({ static const char ____fmt[] = "uprobed_add ENTRY: a = %d, b = %d"; bpf_trace_printk(____fmt, sizeof(____fmt), a, b); });
 return 0;
}

#pragma GCC diagnostic push
# 17 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 17 "uprobe.bpf.c"
 __attribute__((section("uretprobe"), used))
# 17 "uprobe.bpf.c"
#pragma GCC diagnostic pop
int uretprobe_add(struct pt_regs *ctx); static inline __attribute__((always_inline)) typeof(uretprobe_add(0)) ____uretprobe_add(struct pt_regs *ctx, int ret); typeof(uretprobe_add(0)) uretprobe_add(struct pt_regs *ctx) {
# 18 "uprobe.bpf.c"
#pragma GCC diagnostic push
# 18 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wint-conversion"
# 18 "uprobe.bpf.c"
    return ____uretprobe_add(ctx, (void *)(((const struct user_regs_struct *)(ctx))->scratch.r0));
# 18 "uprobe.bpf.c"
#pragma GCC diagnostic pop
# 18 "uprobe.bpf.c"
    } static inline __attribute__((always_inline)) typeof(uretprobe_add(0)) ____uretprobe_add(struct pt_regs *ctx, int ret)
{
 ({ static const char ____fmt[] = "uprobed_add EXIT: return = %d"; bpf_trace_printk(____fmt, sizeof(____fmt), ret); });
 return 0;
}

#pragma GCC diagnostic push
# 24 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 24 "uprobe.bpf.c"
 __attribute__((section("uprobe//proc/self/exe:uprobed_sub"), used))
# 24 "uprobe.bpf.c"
#pragma GCC diagnostic pop
int uprobe_sub(struct pt_regs *ctx); static inline __attribute__((always_inline)) typeof(uprobe_sub(0)) ____uprobe_sub(struct pt_regs *ctx, int a, int b); typeof(uprobe_sub(0)) uprobe_sub(struct pt_regs *ctx) {
# 25 "uprobe.bpf.c"
#pragma GCC diagnostic push
# 25 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wint-conversion"
# 25 "uprobe.bpf.c"
    return ____uprobe_sub(ctx, (void *)(((const struct user_regs_struct *)(ctx))->scratch.r0), (void *)(((const struct user_regs_struct *)(ctx))->scratch.r1));
# 25 "uprobe.bpf.c"
#pragma GCC diagnostic pop
# 25 "uprobe.bpf.c"
    } static inline __attribute__((always_inline)) typeof(uprobe_sub(0)) ____uprobe_sub(struct pt_regs *ctx, int a, int b)
{
 ({ static const char ____fmt[] = "uprobed_sub ENTRY: a = %d, b = %d"; bpf_trace_printk(____fmt, sizeof(____fmt), a, b); });
 return 0;
}

#pragma GCC diagnostic push
# 31 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wignored-attributes"
# 31 "uprobe.bpf.c"
 __attribute__((section("uretprobe//proc/self/exe:uprobed_sub"), used))
# 31 "uprobe.bpf.c"
#pragma GCC diagnostic pop
int uretprobe_sub(struct pt_regs *ctx); static inline __attribute__((always_inline)) typeof(uretprobe_sub(0)) ____uretprobe_sub(struct pt_regs *ctx, int ret); typeof(uretprobe_sub(0)) uretprobe_sub(struct pt_regs *ctx) {
# 32 "uprobe.bpf.c"
#pragma GCC diagnostic push
# 32 "uprobe.bpf.c"
#pragma GCC diagnostic ignored "-Wint-conversion"
# 32 "uprobe.bpf.c"
    return ____uretprobe_sub(ctx, (void *)(((const struct user_regs_struct *)(ctx))->scratch.r0));
# 32 "uprobe.bpf.c"
#pragma GCC diagnostic pop
# 32 "uprobe.bpf.c"
    } static inline __attribute__((always_inline)) typeof(uretprobe_sub(0)) ____uretprobe_sub(struct pt_regs *ctx, int ret)
{
 ({ static const char ____fmt[] = "uprobed_sub EXIT: return = %d"; bpf_trace_printk(____fmt, sizeof(____fmt), ret); });
 return 0;
}
