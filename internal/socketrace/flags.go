// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package socketrace

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"unsafe"

	flag "github.com/spf13/pflag"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

type Flags struct {
	Netns string
	netns uint32
	Pid   uint
	Mark  uint

	FilterProtocol string
	protocol       uint16
	FilterAddr     string
	addr           netip.Addr
	FilterPort     uint16
	FilterFuncs    string

	OutputSockCommon bool
	OutputSockInfo   bool
	OutputSocketInfo bool
	OutputStack      bool

	OutputFile string

	OutputLimitLines uint

	KprobeWay string

	ListFuncs string
}

func ParseFlags() (*Flags, error) {
	var f Flags

	flag.StringVar(&f.Netns, "filter-netns", "", "filter network namespace")
	flag.UintVar(&f.Pid, "filter-pid", 0, "filter process id")
	flag.UintVar(&f.Mark, "filter-mark", 0, "filter sock mark")

	flag.StringVar(&f.FilterProtocol, "filter-protocol", "", "filter protocol, tcp, udp, icmp, empty means all")
	flag.StringVar(&f.FilterAddr, "filter-addr", "", "filter IPv4 address")
	flag.Uint16Var(&f.FilterPort, "filter-port", 0, "filter TCP/UDP port")
	flag.StringVar(&f.FilterFuncs, "filter-funcs", "", "filter functions with Go regexp, empty means all")

	flag.BoolVar(&f.OutputSockCommon, "output-sock-common", false, "output common socket information")
	flag.BoolVar(&f.OutputSockInfo, "output-sock-info", false, "output sock information")
	flag.BoolVar(&f.OutputSocketInfo, "output-socket-info", false, "output socket information")
	flag.BoolVar(&f.OutputStack, "output-stack", false, "output stack information")

	flag.StringVar(&f.OutputFile, "output-file", "", "output file, empty means stdout")

	flag.UintVar(&f.OutputLimitLines, "output-limit-lines", 0, "limit output lines, 0 means no limit")

	flag.StringVar(&f.KprobeWay, "kprobe-way", "", "specify kprobe way, kprobe or kprobe-multi, empty means auto detect")

	flag.StringVar(&f.ListFuncs, "list-funcs", "", "list trace-able functions with specified parameter name, like sock in 'struct sock *'")

	flag.Parse()

	if f.FilterProtocol != "" {
		switch f.FilterProtocol {
		case "tcp":
			f.protocol = unix.IPPROTO_TCP
		case "udp":
			f.protocol = unix.IPPROTO_UDP
		case "icmp":
			f.protocol = unix.IPPROTO_ICMP
		default:
			return nil, fmt.Errorf("invalid protocol: %s", f.FilterProtocol)
		}
	}

	if f.FilterAddr != "" {
		addr, err := netip.ParseAddr(f.FilterAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse filter address: %s", err)
		}
		f.addr = addr
	} else {
		f.addr = netip.AddrFrom4([4]byte{0, 0, 0, 0})
	}

	// netns
	if f.Netns != "" {
		n, err := strconv.ParseUint(f.Netns, 10, 32)
		if err == nil {
			f.netns = uint32(n)
		} else {
			handle, err := netns.GetFromPath(f.Netns)
			if err != nil {
				handle, _ = netns.GetFromName(f.Netns)
			}
			if handle != 0 {
				var s unix.Stat_t
				if err := unix.Fstat(int(handle), &s); err != nil {
					f.netns = uint32(s.Ino)
				}
			}
		}

		if f.netns == 0 {
			return nil, fmt.Errorf("failed to parse netns: %s", f.Netns)
		}
	}

	if f.KprobeWay != "" && f.KprobeWay != "kprobe" && f.KprobeWay != "kprobe-multi" {
		return nil, fmt.Errorf("invalid kprobe way: %s", f.KprobeWay)
	}

	return &f, nil
}

func (f *Flags) GetConfig() *Config {
	var c Config

	c.Netns = f.netns
	c.Pid = uint32(f.Pid)
	c.Mark = uint32(f.Mark)
	c.Protocol = f.protocol
	c.Addr = f.addr.As4()

	c.PortLE = f.FilterPort
	c.PortBE = binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&f.FilterPort))[:])

	bool2b := func(b bool) byte {
		if b {
			return 1
		}
		return 0
	}

	c.OutputSockCommon = bool2b(f.OutputSockCommon)
	c.OutputSockInfo = bool2b(f.OutputSockInfo)
	c.OutputSocketInfo = bool2b(f.OutputSocketInfo)
	c.OutputStack = bool2b(f.OutputStack)

	c.IsSet = bool2b(c != Config{})

	return &c
}
