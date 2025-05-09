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

// All returns in an iterator over the elements of the eBPF iterator it. In case
// of an iterator failure, the iterator will return a zero element together with
// an error and then end the sequence. The iterator will never emit io.EOF as
// this would be pretty useless for an iterator.
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
		if err != nil {
			return v, err
		}
		return v, io.EOF
	}
	return v, nil
}
