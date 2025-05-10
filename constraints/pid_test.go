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

package constraints

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// pidnr converts some user PID type value into the PID format as used inside
// the Linux kernel.
//
// nota bene: the Linux kernel sources use "pid_t" alias "unsigned int" and that
// gets translated by bpf2go into the Go "int32" type.
func pidnr[P PID](p P) int32 {
	return int32(p)
}

func pid[P PID](p int32) P {
	return P(p)
}

type pidType uint32

var _ = Describe("constraints", func() {

	It("goes forth and backth", func() {
		p := pidType(0x420001)
		Expect(pidnr(p)).To(Equal(int32(0x420001)))
		Expect(pid[int64](pidnr(p))).To(Equal(int64(0x420001)))
		Expect(pidnr(pid[uint64](pidnr(-1)))).To(Equal(int32(-1)))
	})

})
