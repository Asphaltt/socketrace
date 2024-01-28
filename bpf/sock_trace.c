// SPDX-License-Identifier: GPL-2.0
/* Copyright Leon Hwang */

#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_tracing.h"

#include "socket.h"

struct sk_meta {
    __be64 addrs;
    __be16 dport;
    u16 port_num;
    u32 netns;
    u16 family;
    u16 protocol;
} __attribute__((packed));

struct sk_common {
    u8 state;
    u8 reuse_port;
    u8 pad[2];
    u32 bound_ifindex;
} __attribute__((packed));

struct sk_info {
    u32 rx_dst_ifindex;
    u32 backlog_len;
    u32 rcv_buff;
    u32 snd_buff;
    u32 priority;
    u32 mark;
    u16 type;
    u16 pad;
} __attribute__((packed));

struct socket_info {
    u16 state;
    u16 type;
    u32 pad;
    u64 file_inode;
    u64 flags;
} __attribute__((packed));

struct event {
    u32 pid;
    u8 comm[16];
    u32 cpu;
    u64 addr;
    struct sk_meta meta;
    struct sk_common skc;
    struct sk_info sk;
    struct socket_info sock;
    s64 print_stack_id;
} __attribute__((packed));

#define __sizeof_event (sizeof(struct event))

#define MAX_QUEUE_ENTRIES 1024*1024

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, struct event);
    __uint(max_entries, MAX_QUEUE_ENTRIES);
} events SEC(".maps");

struct config {
    u32 pid;
    u32 netns;
    u32 mark;
    u32 addr;
    union {
        u32 port;
        struct {
            u16 port_le;
            u16 port_be;
        };
    };
    u16 protocol;
    u8 output_sock_common;
    u8 output_sock_info;
    u8 output_socket_info;
    u8 output_stack;
    u8 is_set;
    u8 pad;
} __attribute__((packed));

static volatile const struct config CFG;
#define cfg (&CFG)

#define MAX_STACK_DEPTH 50
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256);
	__uint(key_size, sizeof(u32));
	__uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
} print_stack_map SEC(".maps");

static __always_inline u32
get_netns(struct sock *sk) {
    return BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
}

static __always_inline bool
filter_meta(struct sock *sk) {
    u16 protocol;
    u16 family;

    if (cfg->netns && get_netns(sk) != cfg->netns)
            return false;

    if (cfg->mark && BPF_CORE_READ(sk, sk_mark) != cfg->mark)
        return false;

    if (cfg->addr || cfg->port || cfg->protocol) {
        family = BPF_CORE_READ(sk, __sk_common.skc_family);
        protocol = BPF_CORE_READ(sk, sk_protocol);

        if (family != AF_INET && family != AF_INET6)
            return false;

        if (cfg->protocol && protocol != cfg->protocol)
            return false;

        if (cfg->addr && cfg->addr != BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr) &&
            cfg->addr != BPF_CORE_READ(sk, __sk_common.skc_daddr))
            return false;

        if (cfg->port) {
            if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
                return false;

            if (cfg->port_le != BPF_CORE_READ(sk, __sk_common.skc_num) &&
                cfg->port_be != BPF_CORE_READ(sk, __sk_common.skc_dport))
                return false;
        }
    }

    return true;
}

static __always_inline bool
filter(struct sock *sk) {
    if (cfg->pid) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        if (pid != cfg->pid)
            return false;
    }

    return filter_meta(sk);
}

static __always_inline void
set_meta(struct sock *sk, struct sk_meta *meta) {
    meta->addrs = BPF_CORE_READ(sk, __sk_common.skc_addrpair);
    meta->dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    meta->port_num = BPF_CORE_READ(sk, __sk_common.skc_num);
    meta->netns = get_netns(sk);
    meta->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    meta->protocol = BPF_CORE_READ(sk, sk_protocol);
}

struct __skc_reuseport {
    union {
        unsigned char one_byte;
        struct {
            unsigned char		skc_reuse:4;
            unsigned char		skc_reuseport:1;
            unsigned char		skc_ipv6only:1;
            unsigned char		skc_net_refcnt:1;
        };
    };
};

static __always_inline u8
probe_skc_reuseport(struct sock *sk) {
    struct __skc_reuseport reuseport;
    bpf_probe_read_kernel(&reuseport, sizeof(reuseport), (void *) (&sk->__sk_common.skc_state) + 1);
    return reuseport.skc_reuseport;
}

static __always_inline void
set_sk_common(struct sock *sk, struct sk_common *skc) {
    skc->state = BPF_CORE_READ(sk, __sk_common.skc_state);
    skc->reuse_port = probe_skc_reuseport(sk);
    skc->bound_ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
}

static __always_inline void
set_sk_info(struct sock *sk, struct sk_info *sk_info) {
    sk_info->rx_dst_ifindex = BPF_CORE_READ(sk, sk_rx_dst_ifindex);
    sk_info->backlog_len = BPF_CORE_READ(sk, sk_backlog.len);
    sk_info->rcv_buff = BPF_CORE_READ(sk, sk_rcvbuf);
    sk_info->snd_buff = BPF_CORE_READ(sk, sk_sndbuf);
    sk_info->priority = BPF_CORE_READ(sk, sk_priority);
    sk_info->mark = BPF_CORE_READ(sk, sk_mark);
    sk_info->type = BPF_CORE_READ(sk, sk_type);
}

static __always_inline void
set_sock_info(struct sock *sk, struct socket_info *sock_info) {
    struct socket *sock = BPF_CORE_READ(sk, sk_socket);
    if (!sock)
        return;

    sock_info->state = BPF_CORE_READ(sock, state);
    sock_info->type = BPF_CORE_READ(sock, type);
    sock_info->flags = BPF_CORE_READ(sock, flags);
    sock_info->file_inode = BPF_CORE_READ(sock, file, f_inode, i_ino);
}

static __always_inline void
set_output(void *ctx,struct sock *sk, struct event *event) {
    if (cfg->output_sock_common)
        set_sk_common(sk, &event->skc);

    if (cfg->output_sock_info)
        set_sk_info(sk, &event->sk);

    if (cfg->output_socket_info)
        set_sock_info(sk, &event->sock);

    if (cfg->output_stack)
        event->print_stack_id = bpf_get_stackid(ctx, &print_stack_map,
                                                BPF_F_FAST_STACK_CMP);
}

static __noinline bool
handle_everything(void *ctx, struct sock *sk, struct event *event) {
    if (cfg->is_set) {
        if (!filter(sk))
            return false;

        set_output(ctx, sk, event);
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->cpu = bpf_get_smp_processor_id();
    set_meta(sk, &event->meta);

    return true;
}

static __always_inline int
kprobe_sk(struct sock *sk, struct pt_regs *ctx, bool has_get_func_ip) {
    struct event event = {};

    if (!handle_everything(ctx, sk, &event))
        return BPF_OK;

    event.addr = has_get_func_ip ? bpf_get_func_ip(ctx) : PT_REGS_IP(ctx);
    bpf_map_push_elem(&events, &event, BPF_EXIST);

    return BPF_OK;
}

#ifdef HAS_KPROBE_MULTI
#define SOCKTRACE_KPROBE_TYPE "kprobe.multi"
#define SOCKTRACE_GET_FUNC_IP true
#else
#define SOCKTRACE_KPROBE_TYPE "kprobe"
#define SOCKTRACE_GET_FUNC_IP false
#endif /* HAS_KPROBE_MULTI */

#define SOCKTRACE_KPROBE(X)                                 \
  SEC(SOCKTRACE_KPROBE_TYPE "/sk-" #X)                      \
  int kprobe_sk_##X(struct pt_regs *ctx) {                  \
    struct sock *sk = (struct sock *) PT_REGS_PARM##X(ctx); \
    return kprobe_sk(sk, ctx, SOCKTRACE_GET_FUNC_IP);       \
  }

SOCKTRACE_KPROBE(1)
SOCKTRACE_KPROBE(2)
SOCKTRACE_KPROBE(3)
SOCKTRACE_KPROBE(4)
SOCKTRACE_KPROBE(5)

#undef SOCKTRACE_KPROBE
#undef SOCKTRACE_KPROBE_TYPE

char __license[] SEC("license") = "GPL";
