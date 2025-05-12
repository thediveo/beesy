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

package pidhorizon

import (
	"os"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gleak"
	. "github.com/thediveo/fdooze"
	. "github.com/thediveo/success"
)

var _ = Describe("PID horizons", func() {

	It("reverses a PID mapping", func() {
		localToRoot := map[uint32]uint32{
			1:   42,
			555: 741,
		}
		rootToLocal := Reverse(localToRoot)
		Expect(rootToLocal).To(HaveLen(2))
		Expect(rootToLocal).To(And(
			HaveKeyWithValue(uint32(42), uint32(1)),
			HaveKeyWithValue(uint32(741), uint32(555))))
	})

	Context("ebpf", func() {

		BeforeEach(func() {
			if os.Getuid() != 0 {
				Skip("needs root")
			}

			goodgos := Goroutines()
			goodfds := Filedescriptors()
			Eventually(Goroutines).Within(2 * time.Second).ProbeEvery(10 * time.Millisecond).
				ShouldNot(HaveLeaked(goodgos))
			Expect(Filedescriptors()).NotTo(HaveLeakedFds(goodfds))
		})

		It("loads the iterator successfully, then correctly releases its resources", func() {
			ph := Successful(NewPIDHorizon[int]())
			Expect(ph).NotTo(BeNil())
			defer ph.Close()
		})

		It("discovers the TID mapping", func() {
			ph := Successful(NewPIDHorizon[int]())
			defer ph.Close()
			beyond := ph.NewMapping()
			Expect(beyond).NotTo(BeEmpty())
			Expect(beyond).To(HaveKeyWithValue(os.Getpid(), Not(BeZero())))
			Expect(beyond).To(HaveKeyWithValue(int(1), Not(BeZero())), "missing PID 1 (either real PID 1 or local PID 1)")
		})

	})

})
