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

package rootpidns_test

import (
	"bytes"
	"strings"
	"unsafe"
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

// CallerName returns beeTaskInfo.Callername as a proper string instead of a
// fixed-size array, terminating the string at the first zero byte encountered
// in the array.
func (ti *beeTaskInfo) CallerName() string {
	b := unsafe.Slice((*byte)(unsafe.Pointer(&ti.Callername[0])), unsafe.Sizeof(ti.Callername))
	// note that the fullname char array isn't zero padded, so we cannot use the
	// usual TrimRight and Co., but instead stop dead at the first zero byte.
	if idx := bytes.IndexByte(b, 0); idx >= 0 {
		return strings.Clone(string(b[:idx]))
	}
	return strings.Clone(string(b[:]))
}
