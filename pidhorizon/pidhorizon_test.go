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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
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

})
