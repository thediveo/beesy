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

// PID is a constraint that permits integer types (both signed as well as
// unsiged) with at least 32bits size that can correctly represent Linux PID and
// TID numbers.
//
// Please note that the kernel type “[pid_t]” ultimately maps to “int” (via
// “[__kernel_pid_t]”). Currently, both on 64 bit and 32 bit architectures the
// Linux kernel will thus allocate 32 bits for PIDs and TIDs (yes, even on 64bit
// architectures). However, [/proc/sys/kernel/pid_max] specifies the largest
// possible PID value before wrapping around: on 64 bit systems the highest
// maximum is 2^22.
//
// PID/TID numbers are thus strictly positive. The value 0 has special meanings
// depending on context, for instance, signalling no PID or the idle process.
// Negative PIDs often signal errors.
//
// [pid_t]: https://elixir.bootlin.com/linux/v6.14.6/source/include/linux/types.h#L27
// [__kernel_pid_t]: https://elixir.bootlin.com/linux/v6.14.6/source/include/uapi/asm-generic/posix_types.h#L28
// [/proc/sys/kernel/pid_max]: https://man7.org/linux/man-pages/man5/proc_sys_kernel.5.html
type PID interface {
	~int | ~int32 | ~int64 |
		~uint | ~uint32 | ~uint64 | ~uintptr
}
