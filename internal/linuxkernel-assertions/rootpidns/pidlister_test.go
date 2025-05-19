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
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/thediveo/beesy/internal/iteriter"
)

const canaryEnvVarName = "DUMP_CHILD_PIDNS_TASKS"
const canaryEnvVarValue = "GO-GOPHER-GO"

func isDumpChildPidnsTasks() bool {
	return os.Getenv(canaryEnvVarName) == canaryEnvVarValue
}

// TestRunInChildPidNamespace actually isn't so much of a test but rather runs
// the eBPF iterator and then logs its iterator results in order for the parent
// test to pick it up. We run in a PID child namespace in order to test that
// we're seeing only tasks from this PID child namespace, but not from any
// parent PID namespace(s).
func TestRunInChildPidNamespace(t *testing.T) {
	if !isDumpChildPidnsTasks() {
		t.SkipNow()
	}

	// Falling back to testing-only mechanisms as self-flagellation for enjoying
	// Gomega and Ginkgo too much.
	var bees beeObjects
	if err := loadBeeObjects(&bees, nil); err != nil {
		t.Fatalf("cannot load eBPF objects, reason: %s", err.Error())
	}
	defer bees.Close()

	var err error
	it, err := link.AttachIter(link.IterOptions{
		Program: bees.DumpTaskInfo,
	})
	if err != nil {
		t.Fatalf("cannot attach eBPF iterator, reason: %s", err.Error())
	}
	defer it.Close()

	for taskInfo, err := range iteriter.All[beeTaskInfo](it) {
		if err != nil {
			t.Fatalf("eBPF iteration failed, reason: %s", err.Error())
		}
		data, err := json.Marshal(perTaskJsonInfo{
			PID:      taskInfo.Pid,
			LocalPID: taskInfo.LocalPid,
			TID:      taskInfo.Tid,
			LocalTID: taskInfo.LocalTid,
			Name:     taskInfo.Name(),
			Caller:   taskInfo.CallerName(),
		})
		if err != nil {
			slog.Error("cannot marshal task information", slog.String("error", err.Error()))
			os.Exit(1)
		}
		t.Log(string(data))
	}
}

// perTaskJsonInfo the task details as JSON for each of the individual tasks
// iterated over.
type perTaskJsonInfo struct {
	PID      int32  `json:"pid"`
	LocalPID int32  `json:"local-pid"`
	TID      int32  `json:"tid"`
	LocalTID int32  `json:"local-tid"`
	Name     string `json:"name"`
	Caller   string `json:"caller"`
}
