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

#pragma once

#include <chrono>
#include <cstddef>
#include <vector>

namespace Dralyxor {
    namespace Benchmark {
        struct Harness {
            struct Stats {
                double min_ns;
                double median_ns;
                double mean_ns;
                double max_ns;
                double stddev_ns;

                std::size_t sample_count;
                std::size_t inner_iterations;
            };

            static Stats Compute_Stats(std::vector<double>& samples_ns);

            template <typename Fn>
            static std::size_t Calibrate(Fn&& fn) {
                constexpr double min_trial_ns = 100000.0;
                constexpr std::size_t max_iterations = std::size_t{1} << 24;

                std::size_t iterations = 1;

                for (;;) {
                    const auto start = std::chrono::steady_clock::now();

                    for (std::size_t i = 0; i < iterations; ++i)
                        fn();

                    const auto end = std::chrono::steady_clock::now();
                    const double elapsed_ns = std::chrono::duration<double, std::nano>(end - start).count();

                    if (elapsed_ns >= min_trial_ns || iterations >= max_iterations)
                        return iterations;

                    iterations *= 2;
                }
            }

            template <typename Fn>
            static Stats Measure(std::size_t trial_count, std::size_t warmup_count, Fn&& fn) {
                const std::size_t inner_iterations = Calibrate(fn);

                for (std::size_t i = 0; i < warmup_count; ++i) {
                    for (std::size_t j = 0; j < inner_iterations; ++j)
                        fn();
                }

                std::vector<double> samples_ns;
                samples_ns.reserve(trial_count);

                for (std::size_t i = 0; i < trial_count; ++i) {
                    const auto start = std::chrono::steady_clock::now();

                    for (std::size_t j = 0; j < inner_iterations; ++j)
                        fn();

                    const auto end = std::chrono::steady_clock::now();
                    const double elapsed_ns = std::chrono::duration<double, std::nano>(end - start).count();

                    samples_ns.push_back(elapsed_ns / static_cast<double>(inner_iterations));
                }

                Stats stats = Compute_Stats(samples_ns);
                stats.inner_iterations = inner_iterations;

                return stats;
            }
        };
    }
}