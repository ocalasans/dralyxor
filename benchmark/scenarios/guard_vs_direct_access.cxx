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
#include <dralyxor/dralyxor.hxx>
//
#include "../escape.hxx"
#include "../harness.hxx"
#include "../reporter.hxx"
//
#include "guard_vs_direct_access.hxx"

namespace Dralyxor {
    namespace Benchmark {
        namespace Scenarios {
            void Run_Guard_Vs_Direct_Access() {
                Reporter::Section("=== Accessor::Guard (scoped RAII copy) vs calling Decrypt()/Encrypt() directly ===");

                auto owner = DRALYXOR_OBFUSCATED("guard overhead measurement payload!");

                const Harness::Stats direct_stats = Harness::Measure(200, 10, [&] {
                    Escape::Do(owner.Decrypt()[0]);

                    owner.Encrypt();
                });

                Reporter::Latency("String::Decrypt()+Encrypt() directly", direct_stats);

                const Harness::Stats guard_stats = Harness::Measure(200, 10, [&] {
                    Dralyxor::Accessor::Guard<decltype(owner)> guard(owner);

                    Escape::Do(guard.Get()[0]);
                });

                Reporter::Latency("Accessor::Guard (construct + Get(), destructor wipes on scope exit)", guard_stats);

                const double ratio = guard_stats.median_ns / direct_stats.median_ns;
                char note[160];

                std::snprintf(note, sizeof(note), "Guard costs %.2fx direct access -- it pays the owner's full anti-debug scan once (same as Decrypt()) plus a second, independent re-encryption of its own copy", ratio);
                Reporter::Note(note);
            }
        }
    }
}