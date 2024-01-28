// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

//go:generate sh -c "echo Generating for $TARGET_GOARCH"
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip kprobeSockTrace ./bpf/sock_trace.c -- -I./bpf/headers -Wno-address-of-packed-member
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET_GOARCH -cc clang -no-strip kprobeMultiSockTrace ./bpf/sock_trace.c -- -D HAS_KPROBE_MULTI -I./bpf/headers -Wno-address-of-packed-member

package main
