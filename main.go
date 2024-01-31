package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Asphaltt/socketrace/internal/socketrace"
	"github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	flags, err := socketrace.ParseFlags()
	if err != nil {
		log.Fatalf("failed to parse flags: %s", err)
	}

	useKprobeMulti := flags.KprobeWay == "kprobe-multi"
	if flags.KprobeWay == "" && socketrace.HaveBPFLinkKprobeMulti() {
		useKprobeMulti = true
	}

	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		log.Fatalf("failed to load kernel spec: %s", err)
	}

	if flags.ListFuncs != "" {
		socketrace.ListFuncs(flags.ListFuncs, btfSpec)
		return
	}

	funcs, err := socketrace.GetFuncsSock(flags.FilterFuncs, btfSpec)
	if err != nil {
		log.Fatalf("failed to get sock funcs: %s", err)
	}

	addrs, err := socketrace.GetAddrs(funcs, true)
	if err != nil {
		log.Fatalf("failed to get addrs: %s", err)
	}

	var bpfSpec *ebpf.CollectionSpec
	if useKprobeMulti {
		bpfSpec, err = loadKprobeMultiSockTrace()
	} else {
		bpfSpec, err = loadKprobeSockTrace()
	}
	if err != nil {
		log.Fatalf("failed to load kprobe sock trace: %s", err)
	}

	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": flags.GetConfig(),
	}); err != nil {
		log.Fatalf("failed to rewrite constants: %s", err)
	}

	coll, err := ebpf.NewCollection(bpfSpec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Printf("failed to load collection: %s\n%+v", err, ve)
			return
		}
		log.Fatalf("failed to create collection: %s", err)
	}
	defer coll.Close()

	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching kprobes (via %s) to %d functions", msg, len(funcs))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	links := make([]link.Link, 0, len(funcs))
	defer func() {
		log.Printf("Detaching kprobes (via %s) from %d bpf links", msg, len(links))

		bar := pb.StartNew(len(links))
		for _, link := range links {
			link.Close()
			bar.Increment()
		}
		bar.Finish()
	}()

	bar := pb.StartNew(len(funcs))
	fns := socketrace.GetFuncsByPos(funcs)
	for pos, funcs := range fns {
		prog, ok := coll.Programs[fmt.Sprintf("kprobe_sk_%d", pos)]
		if !ok {
			log.Fatalf("failed to get program: %s", err)
		}

		if useKprobeMulti {
			ptrs := make([]uintptr, 0, len(fns))
			for _, fn := range funcs {
				if addr, ok := addrs.Name2AddrMap[fn]; ok {
					ptrs = append(ptrs, addr...)
				} else {
					bar.Increment()
					continue
				}
			}
			if len(ptrs) == 0 {
				continue
			}

			opts := link.KprobeMultiOptions{Addresses: ptrs}
			kpm, err := link.KprobeMulti(prog, opts)
			if err != nil {
				log.Fatalf("failed to attach kprobe-multi: %v", err)
			}
			links = append(links, kpm)
			bar.Add(len(funcs))
		} else {
			for _, fn := range funcs {
				kp, err := link.Kprobe(fn, prog, nil)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
						log.Fatalf("failed to attach kprobe: %v", err)
					} else {
						bar.Increment()
						continue
					}
				}

				links = append(links, kp)
				bar.Increment()

				select {
				case <-ctx.Done():
					bar.Finish()
					return
				default:
				}
			}
		}
	}
	bar.Finish()
	log.Printf("Attached kprobes (via %s) to %d functions", msg, len(funcs))

	stackMap := coll.Maps["print_stack_map"]
	output, err := socketrace.NewOutput(flags, stackMap, addrs)
	if err != nil {
		log.Fatalf("failed to create output: %s", err)
	}

	log.Println("Press Ctrl+C to stop")

	output.PrintHeader()

	var event socketrace.Event
	evMap := coll.Maps["events"]

	runForever := flags.OutputLimitLines == 0
	for n := flags.OutputLimitLines; runForever || n > 0; n-- {
		for {
			if err := evMap.LookupAndDelete(nil, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				return
			default:
				time.Sleep(time.Microsecond)
				continue
			}
		}

		output.Print(&event)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
