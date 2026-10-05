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
#include "consteval_vs_macro_parity.hxx"

namespace Dralyxor {
    namespace Benchmark {
        namespace Scenarios {
            void Run_Consteval_Vs_Macro_Parity() {
                Reporter::Section("=== Does construction method change runtime Decrypt() cost? (it shouldn't -- the difference is compile-time only) ===");

#if DRALYXOR_HAS_CONSTEVAL
                Dralyxor::Obfuscated::String direct("identical payload, built two different ways");
                auto via_macro = DRALYXOR_OBFUSCATED("identical payload, built two different ways");

                const Harness::Stats direct_stats = Harness::Measure(200, 10, [&] {
                    Escape::Do(direct.Decrypt()[0]);

                    direct.Encrypt();
                });

                Reporter::Latency("direct C++20 consteval construction", direct_stats);

                const Harness::Stats macro_stats = Harness::Measure(200, 10, [&] {
                    Escape::Do(via_macro.Decrypt()[0]);

                    via_macro.Encrypt();
                });

                Reporter::Latency("DRALYXOR_OBFUSCATED macro", macro_stats);

                const double ratio = macro_stats.median_ns / direct_stats.median_ns;
                char note[160];

                std::snprintf(note, sizeof(note), "median ratio macro/direct = %.3fx -- consteval is a compile-time-only guarantee, so this should land close to 1.0x, not favor either path", ratio);
                Reporter::Note(note);
#else
                Reporter::Note("this compiler has no real C++20 consteval, so the direct-construction path doesn't exist here -- skipping (see minimum_supported_standard_cpp14 in examples/ for why DRALYXOR_OBFUSCATED exists in the first place)");
#endif
            }
        }
    }
}