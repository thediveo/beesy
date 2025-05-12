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

package iteriter

import (
	"io"
	"iter"
	"unsafe"

	"github.com/cilium/ebpf/link"
)

const (
	BPF_TASK_ITER_ALL_PROCS    = 0
	BPF_TASK_ITER_ALL_THREADS  = 1
	BPF_TASK_ITER_PROC_THREADS = 2
)

// All returns an iterator over the elements of the eBPF iterator passed as
// “it”. In case of an iterator failure, the iterator will return a zero element
// together with an error and then end the sequence. The iterator will never
// emit io.EOF as this would be pretty useless for an iterator.
//
// All returns the iterator results as values and not as references; please see
// [AllVolatile] for an optimized version that passed values by reference and
// with the values only valid within the caller's iteration body.
func All[T any](it *link.Iter) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		f, err := it.Open()
		if err != nil {
			var v T
			yield(v, err)
			return
		}
		defer f.Close()
		for {
			v, err := new[T](f)
			if err == io.EOF {
				// new emits io.EOF only after the final value has been read
				// without any error indication.
				return
			}
			// Push either a v with a nil error, or alternatively a zero v with
			// a non-nil error...
			if !yield(v, err) {
				return
			}
			if err != nil {
				return
			}
		}
	}
}

// new returns a T value read from f if successful, otherwise an error. Please
// note that new never returns a non-zero value together with io.EOF. Instead,
// it returns io.EOF as a final error after the last value.
func new[T any](f io.Reader) (v T, err error) {
	n, err := f.Read(unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v)))
	// as per the io.Reader contract, callers should consider the returned
	// amount of bytes read first before looking at any error additionally
	// returned. However, we consider an incomplete read to be at EOF, otherwise
	// returning the particular reading error encountered.
	if uintptr(n) != unsafe.Sizeof(v) {
		var zero T
		if err != nil {
			return zero, err
		}
		return zero, io.EOF
	}
	// We got here because we could read the whole value; at this point, we
	// pointedly ignore any io.EOF as we will deliver it only on the next
	// attempt (if any) to read the next iterator value.
	return v, nil
}

// AllVolatile returns an iterator over the elements of the eBPF iterator passed
// as “it”. In case of an iterator failure, the iterator will return a zero
// element together with an error and then end the sequence. The iterator will
// never emit io.EOF as this would be pretty useless for an iterator.
//
// AllVolatile returns a reference to the current value instead of a (copy of)
// the current value itself. This reference is only valid within the caller's
// iteration body and the reference and value referenced become invalid after
// returning from the iteration body. If an iteration body needs to keep yielded
// values for longer, they must create (shallow) copies themselves.
func AllVolatile[T any](it *link.Iter) iter.Seq2[*T, error] {
	return func(yield func(*T, error) bool) {
		var zero T
		f, err := it.Open()
		if err != nil {
			yield(&zero, err)
			return
		}
		defer f.Close()
		var v T
		for {
			n, err := f.Read(unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v)))
			// as per the io.Reader contract, callers should consider the returned
			// amount of bytes read first before looking at any error additionally
			// returned. However, we consider an incomplete read to be at EOF, otherwise
			// returning the particular reading error encountered.
			if uintptr(n) != unsafe.Sizeof(v) {
				if err != nil {
					yield(&zero, err)
					return
				}
				return
			}
			if !yield(&v, err) {
				return
			}
		}
	}
}
