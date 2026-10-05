// Copyright (c) 2026 Calasans (ocalasans)
// SPDX-License-Identifier: MIT
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <cstdio>
//
#include <dralyxor/internal/anti_debug/presence.hxx>
#include <dralyxor/internal/anti_debug/hardware_breakpoints.hxx>
#include <dralyxor/internal/anti_debug/timing.hxx>
//
#include "../escape.hxx"
#include "../harness.hxx"
#include "../reporter.hxx"
//
#include "anti_debug_check_cost.hxx"

namespace Dralyxor {
    namespace Benchmark {
        namespace Scenarios {
            void Run_Anti_Debug_Check_Cost() {
                Reporter::Section("=== Cost of each individual anti-debug check Decrypt() runs on every call ===");

                const Harness::Stats presence_stats = Harness::Measure(200, 10, [&] {
                    Escape::Do(static_cast<unsigned>(Dralyxor::Anti_Debug::Presence::Check()));
                });

                Reporter::Latency("Presence::Check() (IsDebuggerPresent/PEB/NtQuery* or TracerPid)", presence_stats);

                const Harness::Stats hardware_stats = Harness::Measure(50, 5, [&] {
                    Escape::Do(static_cast<unsigned>(Dralyxor::Anti_Debug::Hardware_Breakpoints::Check()));
                });

                Reporter::Latency("Hardware_Breakpoints::Check()", hardware_stats);

#if DRALYXOR_LINUX
                Reporter::Note("on Linux, this check forks a child process to read the parent's debug registers via ptrace -- that fork() is the dominant cost of every single Decrypt() call on this platform, not the cipher. On Windows it just calls GetThreadContext on the current thread and is comparatively cheap.");
#endif

                const Harness::Stats timing_stats = Harness::Measure(200, 10, [&] {
                    Escape::Do(static_cast<unsigned>(Dralyxor::Anti_Debug::Timing::Check()));
                });

                Reporter::Latency("Timing::Check()", timing_stats);
            }
        }
    }
}