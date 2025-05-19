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
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/onsi/gomega/gexec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/thediveo/success"
)

var logLinePrefix = strings.Repeat(" ", 4)

var _ = Describe("iterating tasks inside a child PID namespace", Ordered, func() {

	BeforeAll(func() {
		if os.Getuid() != 0 {
			Skip("needs root in order to create a new child PID namespace")
		}
	})

	It("sees only tasks inside its PID namespace, but not any tasks in the parent PID namespace(s)", func() {
		// At this point we need to run with sufficient privileges, that is,
		// root. And in this situation we don't want to build a dedicated binary
		// for running the eBPF iterator and printing its results: not least,
		// this will fail in devcontainers where the Go toolchain isn't made
		// available to root (which is a good idea). Thus we reuse our own
		// binary to run the eBPF iterator and print the outcome...

		By("running the eBPF iterator as a child test in a new PID child namespace")
		cmd := exec.Command("/proc/self/exe", "-test.v")
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: unix.CLONE_NEWPID,
		}
		cmd.Env = append(cmd.Environ(), canaryEnvVarName+"="+canaryEnvVarValue)
		session := Successful(gexec.Start(cmd, GinkgoWriter, GinkgoWriter))

		By("reading the child test's output, processing logging messages only")
		lines := 0
		for line := range strings.SplitSeq(string(session.Wait().Out.Contents()), "\n") {
			// Parse the output of the test run in the child pid namespace.
			if line == "" {
				break
			}
			// skip anything that somehow belongs to go test's own output, but
			// keep only logging output from the child test.
			if !strings.HasPrefix(line, logLinePrefix) {
				continue
			}
			_, line, ok := strings.Cut(line[4:], " ")
			if !ok {
				continue
			}
			lines++
			var data perTaskJsonInfo
			Expect(json.Unmarshal([]byte(line), &data)).To(Succeed())

			Expect(data.Name).To(Equal("exe")) // ...because the test is run through /proc/self/exe
			Expect(data.Caller).To(Equal("exe"))

			Expect(data.PID).NotTo(Equal(int32(1)))
			Expect(data.LocalPID).To(Equal(int32(1)))

			Expect(data.TID).NotTo(BeZero())
			Expect(data.LocalTID).NotTo(BeZero())
		}
		Expect(lines).NotTo(BeZero(), "missing JSON output line(s)")
	})

})
