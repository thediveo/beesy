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

//go:generate bpf2go -go-package pidhorizon taskTidIter task_tid_iter.bpf.c -- -I../_headers/cilium-ebpf -I../_headers/libbpf -I../_headers/beesy

package pidhorizon

import (
	"maps"

	"github.com/thediveo/beesy/constraints"
)

// Mapper maps PIDs/TIDs in a (child) PID namespace one-to-one to their
// PIDs/TIDs in the root PID namespace (as seen by the kernel) or vice versa.
//
// See also: [Reverse].
type Mapper[P constraints.PID] map[P]P

// Reverse returns a new PID/TID-to-PID/TID Mapper with the PID/TID mapping
// reversed from m.
func Reverse[P constraints.PID](m Mapper[P]) Mapper[P] {
	r := make(Mapper[P])
	for fromPID, toPID := range maps.All(m) {
		r[toPID] = fromPID
	}
	return r
}
