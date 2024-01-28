// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package socketrace

import (
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/tklauser/ps"
)

type Output struct {
	flags *Flags
	stack *ebpf.Map
	addrs Addr2Name

	out io.Writer
}

func NewOutput(flags *Flags, stack *ebpf.Map, addrs Addr2Name) (*Output, error) {
	out := os.Stdout
	if flags.OutputFile != "" {
		f, err := os.Create(flags.OutputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		out = f
	}

	return &Output{
		flags: flags,
		stack: stack,
		addrs: addrs,
		out:   out,
	}, nil
}

func (o *Output) Close() error {
	if o.out != os.Stdout {
		return o.out.(*os.File).Close()
	}

	return nil
}

func (o *Output) PrintMeta(w io.Writer, meta *Meta) {
	saddr := netip.AddrFrom4([4]byte(meta.Addrs[4:]))
	daddr := netip.AddrFrom4([4]byte(meta.Addrs[:4]))
	dport := binary.BigEndian.Uint16(meta.Dport[:])
	sport := meta.PortNum
	family := addressFamily(meta.Family)

	var protocol string
	switch family {
	case AF_INET, AF_INET6:
		protocol = ipProto(meta.Protocol).String()
	case AF_NETLINK:
		protocol = netlinkProto(meta.Protocol).String()
	default:
		protocol = fmt.Sprintf("%d", meta.Protocol)
	}

	fmt.Fprintf(w, " %s:%d -> %s:%d netns=%d family=%s protocol=%s", saddr, sport, daddr, dport, meta.Netns, family, protocol)
}

func (o *Output) PrintSockCommon(w io.Writer, skc *SockCommon) {
	state := sockState(skc.State).String()
	fmt.Fprintf(w, " state=%s reuseport=%v bound_ifindex=%d", state, skc.ReusePort == 1, skc.BoundIfindex)
}

func (o *Output) PrintSockInfo(w io.Writer, ski *SockInfo) {
	fmt.Fprintf(w, " rx_dst_ifindex=%d backlog_len=%d rcv_buff=%d snd_buff=%d priority=%d mark=%d type=%d", ski.RxDstIfindex, ski.BacklogLen, ski.RcvBuff, ski.SndBuff, ski.Priority, ski.Mark, ski.Type)
}

func (o *Output) PrintSocketInfo(w io.Writer, meta *Meta, si *SocketInfo) {
	state := socketState(si.State).String()
	typ := sockType(si.Type).String()
	fmt.Fprintf(w, " state=%s type=%s flags=%d f_ino=%d", state, typ, si.Flags, si.FileInode)
}

func nullString(s []byte) string {
	for i, b := range s {
		if b == 0 {
			return string(s[:i])
		}
	}
	return string(s)
}

func getProcess(ev *Event) string {
	pid := ev.Pid
	p, err := ps.FindProcess(int(pid))
	if err != nil {
		return fmt.Sprintf("%d(%s)", pid, nullString(ev.Comm[:]))
	}

	return fmt.Sprintf("%d(%s)", pid, p.Command())
}

func (o *Output) getFuncName(ip uint64) string {
	var addr uint64
	// XXX: not sure why the -1 offset is needed on x86 but not on arm64
	switch runtime.GOARCH {
	case "amd64":
		addr = ip
		if o.flags.KprobeWay == "kprobe-multi" {
			addr -= 1
		}
	case "arm64":
		addr = ip
	}

	var funcName string
	if ksym, ok := o.addrs.Addr2NameMap[addr]; ok {
		funcName = ksym.name
	} else if ksym, ok := o.addrs.Addr2NameMap[addr-4]; runtime.GOARCH == "amd64" && ok {
		// Assume that function has ENDBR in its prelude (enabled by CONFIG_X86_KERNEL_IBT).
		// See https://lore.kernel.org/bpf/20220811091526.172610-5-jolsa@kernel.org/
		// for more ctx.
		funcName = ksym.name
	} else {
		funcName = fmt.Sprintf("0x%x", addr)
	}

	return funcName
}

func (o *Output) PrintHeader() {
	out := o.out

	fmt.Fprintf(out, "%-3s %-32s %-32s\n", "CPU", "PROCESS", "FUNC")
}

func (o *Output) Print(event *Event) {
	out := o.out

	cpu := event.CPU
	process := getProcess(event)
	funcName := o.getFuncName(event.Addr)

	fmt.Fprintf(out, "%-3d %-32s %-32s\t", cpu, process, funcName)

	o.PrintMeta(out, &event.Meta)

	if o.flags.OutputSockCommon {
		o.PrintSockCommon(out, &event.SockCommon)
	}

	if o.flags.OutputSockInfo {
		o.PrintSockInfo(out, &event.SockInfo)
	}

	if o.flags.OutputSocketInfo {
		o.PrintSocketInfo(out, &event.Meta, &event.SocketInfo)
	}

	if o.flags.OutputStack && event.StackID > 0 {
		var stack StackData
		id := uint32(event.StackID)
		if err := o.stack.Lookup(&id, &stack); err == nil {
			for _, ip := range stack.IPs {
				if ip > 0 {
					fmt.Fprintf(out, "\n\t%s", o.addrs.findNearestSym(ip))
				}
			}
		}
		_ = o.stack.Delete(&id)
	}

	fmt.Fprintln(out)
}
