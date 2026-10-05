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
#include "reporter.hxx"

namespace Dralyxor {
    namespace Benchmark {
        void Reporter::Section(const std::string& title) {
            std::printf("\n-- %s --\n", title.c_str());
        }

        void Reporter::Latency(const std::string& name, const Harness::Stats& stats) {
            std::printf("%-46s min %9.1f ns   median %9.1f ns   mean %9.1f ns   max %11.1f ns   stddev %9.1f ns   (n=%zu)\n", name.c_str(), stats.min_ns, stats.median_ns,
            stats.mean_ns, stats.max_ns, stats.stddev_ns, stats.sample_count);

            if (stats.inner_iterations > 1)
                std::printf("   (averaged over %zu calls per trial -- a single call is faster than this clock can resolve directly)\n", stats.inner_iterations);
        }

        void Reporter::Note(const std::string& text) {
            std::printf("   (%s)\n", text.c_str());
        }
    }
}
