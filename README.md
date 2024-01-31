<!--
 Copyright 2024 Leon Hwang.
 SPDX-License-Identifier: Apache-2.0
-->

# socketrace: a generic socket tracer

`socketrace` is an eBPF-based tool for tracing socket events in Linux kernel
with advanced filtering and aggregation capabilities. It allows you to
introspect of socket events in the kernel, no matter tcp/udp/unix domain/netlink
sockets.

## Running

`socketrace` requires >= 5.3 kernel to run. `--kprobe-way kprobe-multi` requires
5.18 kernel.

`debugfs` has to be mounted at `/sys/kernel/debug`. In case the directory is
empty, it can be mounted with `mount -t debugfs none /sys/kernel/debug`.

The following kernel configs are required:

|           Option         | kprobe-way   |                         Note                         |
| ------------------------ | ------------ | ---------------------------------------------------- |
|CONFIG_DEBUG_INFO_BTF=y   | both         | available >= 5.3 |
|CONFIG_BPF=y              | both         | |
|CONFIG_BPF_SYSCALL=y      | both         | |
|CONFIG_KPROBES=y          | both         | |
|CONFIG_FUNCTION_TRACER=y  | kprobe-multi | /sys/kernel/debug/tracing/available_filter_functions |
|CONFIG_FPROBE=y           | kprobe-multi | available >= 5.18 |

You can use `zgrep $OPTION /proc/config.gz` to check if the option is enabled.

### Usage

```bash
$ ./socketrace -h
Usage of ./socketrace:
      --filter-addr string        filter IPv4 address
      --filter-funcs string       filter functions with Go regexp, empty means all
      --filter-mark uint          filter sock mark
      --filter-netns string       filter network namespace
      --filter-pid uint           filter process id
      --filter-port uint16        filter TCP/UDP port
      --filter-protocol string    filter protocol, tcp, udp, icmp, empty means all
      --kprobe-way string         specify kprobe way, kprobe or kprobe-multi, empty means auto detect
      --output-file string        output file, empty means stdout
      --output-limit-lines uint   limit output lines, 0 means no limit
      --output-sock-common        output common socket information
      --output-sock-info          output sock information
      --output-socket-info        output socket information
      --output-stack              output stack information
```

### Example

```bash
$ ./socketrace --output-limit-lines 10
2024/01/28 14:30:11 Attaching kprobes (via kprobe-multi) to 1090 functions
1090 / 1090 [----------------------------------------------------------------------------------------------------------------------------------] 100.00% ? p/s
2024/01/28 14:30:11 Attached kprobes (via kprobe-multi) to 1090 functions
2024/01/28 14:30:11 Press Ctrl+C to stop
CPU PROCESS                          FUNC
5   926(sshd)                        aa_sk_perm                          192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        inet_send_prepare                   192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_sendmsg                         192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        lock_sock_nested                    192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_sendmsg_locked                  192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_rate_check_app_limited          192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_send_mss                        192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_current_mss                     192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_established_options             192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
5   926(sshd)                        tcp_stream_alloc_skb                192.168.64.2:22 -> 192.168.64.1:55856 netns=4026531840 family=AF_INET6 protocol=IPPROTO_TCP
2024/01/28 14:30:11 Detaching kprobes (via kprobe-multi) from 5 bpf links
5 / 5 [---------------------------------------------------------------------------------------------------------------------------------------] 100.00% 13 p/s
```

## Developing

### Dependencies

- Go >= 1.21.5
- LLVM/clang >= 12

### Build

```bash
make
```

## Credits

Thanks to [pwru](github.com/cilium/pwru). `socketrace` is inspired by `pwru`.
And some of its source code is borrowed from `pwru`.

## Licenses

`socketrace` is licensed under the Apache 2.0 license. And its bpf code is licensed
under the GPL 2.0 license.
