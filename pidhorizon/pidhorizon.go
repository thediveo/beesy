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
	"fmt"
	"maps"

	"github.com/cilium/ebpf/link"
	"github.com/thediveo/beesy/constraints"
	"github.com/thediveo/beesy/internal/iteriter"
)

// Mapping maps PIDs/TIDs in a (child) PID namespace one-to-one to their
// PIDs/TIDs in the root PID namespace (as seen by the kernel) or vice versa.
//
// See also: [Reverse].
type Mapping[P constraints.PID] map[P]P

// Reverse returns a new, reversed PID/TID-to-PID/TID Mapping for m.
func Reverse[P constraints.PID](m Mapping[P]) Mapping[P] {
	r := make(Mapping[P])
	for fromPID, toPID := range maps.All(m) {
		r[toPID] = fromPID
	}
	return r
}

// NewPIDHorizon returns a new PID horizon for mapping PIDs/TIDs of any type
// satisfying constraints.PID to their PIDs/TIDs in the root PID namespace. Use
// [NewPIDHorizon.NewMapping]
func NewPIDHorizon[P constraints.PID]() (*PIDHorizon[P], error) {
	ph := &PIDHorizon[P]{}
	if err := loadTaskTidIterObjects(&ph.ebpfObjects, nil); err != nil {
		return nil, fmt.Errorf("cannot load Task TID iterator eBPF objects, reason: %w", err)
	}
	var err error
	if ph.taskTIDIter, err = link.AttachIter(link.IterOptions{
		Program: ph.ebpfObjects.DumpTaskTid,
	}); err != nil {
		return nil, fmt.Errorf("cannot attach Task TID iterator, reason: %w", err)
	}
	return ph, nil
}

// PIDHorizon provides looking beyond your current PID namespace horizon to
// learn about PIDs/TIDs of processes you see in the root PID namespace.
// However, it doesn't allow you to see any other processes/tasks than those
// that you can see from your current PID namespace.
type PIDHorizon[P constraints.PID] struct {
	ebpfObjects taskTidIterObjects
	taskTIDIter *link.Iter
}

// Close releases all resources associated with this PIDHorizon.
func (ph *PIDHorizon[P]) Close() {
	if ph.taskTIDIter != nil {
		ph.taskTIDIter.Close()
	}
	ph.ebpfObjects.Close()
}

// NewMapping returns a new PID/TID mapping from this process's PID namespace to
// the root PID namespace for all processes/tasks visible to this process.
func (ph *PIDHorizon[P]) NewMapping() Mapping[P] {
	m := Mapping[P]{}
	for taskinfo, err := range iteriter.AllVolatile[taskTidIterInfo](ph.taskTIDIter) {
		if err != nil {
			break
		}
		m[P(taskinfo.Tid)] = P(taskinfo.RootTid)
	}
	return m
}
