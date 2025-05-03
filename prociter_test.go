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
	"os"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/link"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	. "github.com/onsi/gomega/gleak"
	. "github.com/thediveo/success"
)

var _ = Describe("beesy eBPF", func() {

	var objs beesyObjects

	BeforeEach(func() {
		if os.Getuid() != 0 {
			Skip("needs root")
		}

		format.MaxLength = 8192

		Expect(loadBeesyObjects(&objs, nil)).To(Succeed())
		DeferCleanup(func() {
			Expect(objs.Close()).To(Succeed())
		})

		goodgoos := Goroutines()
		DeferCleanup(func() {
			Eventually(Goroutines).Within(2 * time.Second).ProbeEvery(100 * time.Millisecond).
				ShouldNot(HaveLeaked(goodgoos))
		})
	})

	It("should load the eBPF iterator program successfully", func() {
		it := Successful(link.AttachIter(link.IterOptions{
			Program: objs.DumpTaskStatus,
		}))
		defer it.Close()
	})

	It("iterates", func() {
		it := Successful(link.AttachIter(link.IterOptions{
			Program: objs.DumpTaskStatus,
		}))
		defer it.Close()

		f := Successful(it.Open())
		defer f.Close()

		count := 0
		for {
			var taskStatus beesyProcstatus
			n, err := f.Read(unsafe.Slice((*byte)(unsafe.Pointer(&taskStatus)), unsafe.Sizeof(taskStatus)))
			if n == 0 {
				break
			}
			Expect(err).NotTo(HaveOccurred())
			Expect(taskStatus.Pid).NotTo(BeZero())
			Expect(taskStatus.Tid).NotTo(BeZero())
			name := string(unsafe.Slice((*byte)(unsafe.Pointer(&taskStatus.Name)), unsafe.Sizeof(taskStatus.Name)))
			Expect(name).NotTo(BeEmpty())
			println(name)
			count++
		}
		Expect(count).NotTo(BeZero())
	})

})
