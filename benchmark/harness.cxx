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

#include <algorithm>
#include <cmath>
#include <numeric>
//
#include "harness.hxx"

namespace Dralyxor {
    namespace Benchmark {
        Harness::Stats Harness::Compute_Stats(std::vector<double>& samples_ns) {
            std::sort(samples_ns.begin(), samples_ns.end());

            const std::size_t n = samples_ns.size();
            const double sum = std::accumulate(samples_ns.begin(), samples_ns.end(), 0.0);
            const double mean = sum / static_cast<double>(n);

            double variance_sum = 0.0;

            for (double sample : samples_ns) {
                const double diff = sample - mean;

                variance_sum += diff * diff;
            }

            const double median = (n % 2 == 0) ? (samples_ns[n / 2 - 1] + samples_ns[n / 2]) / 2.0 : samples_ns[n / 2];

            return Harness::Stats {
                samples_ns.front(),
                median,
                mean,
                samples_ns.back(),
                std::sqrt(variance_sum / static_cast<double>(n)),
                n,
                1
            };
        }
    }
}