//go:generate bpf2go -go-package main bee taskiter.bpf.c -- -I../../../../_headers/cilium-ebpf -I../../../../_headers/libbpf -I../../../../_headers/beesy

/*
Package main provides a “canary” program that, when run, iterates over all Linux
tasks visible to it, printing the task PID, TID and (“COMM”) name.
*/
package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
	"github.com/thediveo/beesy/beesy/internal/iteriter"
)

// Name returns beeTaskInfo.Fullname as a proper string instead of a fixed-size
// array, terminating the string at the first zero byte encountered in the
// array.
func (ti *beeTaskInfo) Name() string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(&ti.Fullname[0])), unsafe.Sizeof(ti.Fullname))
	// note that the fullname char array isn't zero padded, so we cannot use the
	// usual TrimRight and Co., but instead stop dead at the first zero byte.
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		return strings.Clone(string(b[:idx]))
	}
	return strings.Clone(string(b[:]))
}

func main() {
	var objs beeObjects
	err := loadBeeObjects(&objs, nil)
	if err != nil {
		slog.Error("cannot load eBPF objects", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer objs.Close()

	it, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpTaskInfo,
	})
	if err != nil {
		slog.Error("cannot attach eBPF iterator", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer it.Close()

	for taskInfo, err := range iteriter.All[beeTaskInfo](it) {
		if err != nil {
			slog.Error("eBPF iteration failed", slog.String("error", err.Error()))
			os.Exit(1)
		}
		fmt.Printf("%d %d %q\n", taskInfo.Pid, taskInfo.Tid, taskInfo.Name())
	}
}
