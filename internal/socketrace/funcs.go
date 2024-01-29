// Copyright 2024 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package socketrace

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"

	"github.com/cilium/ebpf/btf"
)

type Funcs map[string]int

func GetFuncsByPos(funcs Funcs) map[int][]string {
	ret := make(map[int][]string, len(funcs))
	for fn, pos := range funcs {
		ret[pos] = append(ret[pos], fn)
	}
	return ret
}

// getAvailableFilterFunctions return list of functions to which it is possible
// to attach kprobes.
func getAvailableFilterFunctions() (map[string]struct{}, error) {
	availableFuncs := make(map[string]struct{})
	f, err := os.Open("/sys/kernel/debug/tracing/available_filter_functions")
	if err != nil {
		return nil, fmt.Errorf("failed to open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		availableFuncs[scanner.Text()] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return availableFuncs, nil
}

// GetFuncsSock returns a map of function names to argument index for the
// functions that take a `struct sock` pointer as an argument.
func GetFuncsSock(pattern string, spec *btf.Spec) (Funcs, error) {
	return getFuncs(pattern, "sock", spec)
}

func getFuncs(pattern, structName string, spec *btf.Spec) (Funcs, error) {
	funcs := Funcs{}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	availableFuncs, err := getAvailableFilterFunctions()
	if err != nil {
		log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
	}

	iter := spec.Iterate()
	for iter.Next() {
		typ := iter.Type
		fn, ok := typ.(*btf.Func)
		if !ok {
			continue
		}

		fnName := fn.Name

		if pattern != "" && reg.FindString(fnName) != fnName {
			continue
		}

		availableFnName := fnName
		if _, ok := availableFuncs[availableFnName]; !ok {
			continue
		}

		fnProto := fn.Type.(*btf.FuncProto)
		i := 1
		for _, p := range fnProto.Params {
			if ptr, ok := p.Type.(*btf.Pointer); ok {
				if strct, ok := ptr.Target.(*btf.Struct); ok {
					if strct.Name == structName && i <= 5 {
						name := fnName
						funcs[name] = i
						continue
					}
				}
			}

			i += 1
			if i > 5 {
				break
			}
		}
	}

	return funcs, nil
}

func ListFuncs(structName string, spec *btf.Spec) {
	funcs, err := getFuncs("", structName, spec)
	if err != nil {
		log.Fatalf("failed to get funcs: %s", err)
	}

	positions := []string{"", "1st", "2nd", "3rd", "4th", "5th"}
	fns := GetFuncsByPos(funcs)
	for pos := 1; pos <= 5; pos++ {
		fns, ok := fns[pos]
		if !ok {
			continue
		}

		fmt.Printf("With 'struct %s *' as the %s parameter's type, total %d functions:\n",
			structName, positions[pos], len(fns))
		sort.Strings(fns)
		for _, fn := range fns {
			fmt.Printf("  %s\n", fn)
		}
		fmt.Println()
	}

	fmt.Printf("Total: %d\n", len(funcs))
}
