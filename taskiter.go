// Copyright 2025 Harald Albrecht.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy
// of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package beesy

import (
	"bytes"
	"io"
	"iter"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf/link"
)

func (ts *beesyTaskStatus) Name() string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(&ts.Fullname[0])), unsafe.Sizeof(ts.Fullname))
	// note that the fullname char array isn't zero padded, so we cannot use the
	// usual TrimRight and Co., but instead stop dead at the first zero byte.
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		return strings.Clone(string(b[:idx]))
	}
	return strings.Clone(string(b[:]))
}

func newTaskStatus(f io.Reader) (ts beesyTaskStatus, err error) {
	n, err := f.Read(unsafe.Slice((*byte)(unsafe.Pointer(&ts)), unsafe.Sizeof(ts)))
	if err != nil {
		return ts, io.EOF
	}
	if uintptr(n) != unsafe.Sizeof(ts) {
		return ts, io.EOF
	}
	return ts, nil
}

func allTasks(it *link.Iter) iter.Seq[beesyTaskStatus] {
	return func(yield func(beesyTaskStatus) bool) {
		f, err := it.Open()
		if err != nil {
			return
		}
		defer f.Close()
		for {
			taskStatus, err := newTaskStatus(f)
			if err != nil {
				return
			}
			if !yield(taskStatus) {
				return
			}
		}
	}
}
