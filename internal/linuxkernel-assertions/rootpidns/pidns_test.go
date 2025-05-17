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

	"github.com/thediveo/beesy/internal/linuxkernel-assertions/rootpidns/pidlistercmd/format"
	"github.com/thediveo/beesy/tasks"
	"golang.org/x/sys/unix"

	gof "github.com/onsi/gomega/format"
	"github.com/onsi/gomega/gexec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/thediveo/success"
)

// cmdpkg specifies the name (but not the import path) of the direct sub-package
// containing the task PID listing command.
const cmdpkg = "pidlistercmd"

var cmdcomm = cmdpkg[:min(len(cmdpkg), tasks.MaxCommLen)]

var _ = Describe("iterating tasks inside a child PID namespace", Ordered, func() {

	var canaryPath string

	BeforeAll(func() {
		if os.Getuid() != 0 {
			Skip("needs root")
		}

		gof.MaxLength = 8192

		canaryPath = Successful(gexec.Build("./pidlistercmd", "-buildvcs=false"))
		DeferCleanup(func() {
			gexec.CleanupBuildArtifacts()
		})
	})

	It("sees only tasks inside its PID namespace with host PIDs", func() {
		cmd := exec.Command(canaryPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: unix.CLONE_NEWPID,
		}
		session := Successful(gexec.Start(cmd, GinkgoWriter, GinkgoWriter))

		lines := 0
		for line := range strings.SplitSeq(string(session.Wait().Out.Contents()), "\n") {
			if line == "" {
				break
			}
			lines++
			var data format.Output
			Expect(json.Unmarshal([]byte(line), &data)).To(Succeed())

			Expect(data.Name).To(Equal(cmdcomm))
			Expect(data.Caller).To(Equal(cmdcomm))

			Expect(data.PID).NotTo(Equal(int32(1)))
			Expect(data.LocalPID).To(Equal(int32(1)))

			Expect(data.TID).NotTo(BeZero())
			Expect(data.LocalTID).NotTo(BeZero())
		}
		Expect(lines).NotTo(BeZero())
	})

})
