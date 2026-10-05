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
#include <cstdint>
//
#include "../attributes.hxx"
#include "../platform.hxx"
//
#if DRALYXOR_ARCH_X86 && DRALYXOR_GNU_LIKE
    #include <x86intrin.h>
#elif DRALYXOR_ARCH_X86 && DRALYXOR_MSVC
    #include <intrin.h>
#endif

#ifndef DRALYXOR_TIMING_WALL_CLOCK_THRESHOLD_MS
    #define DRALYXOR_TIMING_WALL_CLOCK_THRESHOLD_MS 50
#endif

#ifndef DRALYXOR_TIMING_CYCLE_THRESHOLD
    #define DRALYXOR_TIMING_CYCLE_THRESHOLD 500000000ULL
#endif

namespace Dralyxor {
    namespace Anti_Debug {
        namespace Internal {
            DRALYXOR_OPTNONE inline void Busy_Work(volatile std::uint32_t& sink) noexcept {
                std::uint32_t value = sink;

                for (int i = 0; i < 20000; ++i)
                    value = (value * 1664525u) + 1013904223u;

                sink = value;
            }

            inline std::uint64_t Read_Timestamp_Counter() noexcept {
#if DRALYXOR_ARCH_X86 && (DRALYXOR_GNU_LIKE || DRALYXOR_MSVC)
                return __rdtsc();
#else
                return 0;
#endif
            }
        }

        DRALYXOR_NODISCARD inline Types::Detection_Flag Timing::Check() noexcept {
            volatile std::uint32_t sink = 0;

            const auto wall_clock_start = std::chrono::steady_clock::now();
            const std::uint64_t cycles_start = Internal::Read_Timestamp_Counter();

            Internal::Busy_Work(sink);

            const std::uint64_t cycles_end = Internal::Read_Timestamp_Counter();
            const auto wall_clock_end = std::chrono::steady_clock::now();

            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(wall_clock_end - wall_clock_start);

            constexpr auto WALL_CLOCK_ANOMALY_THRESHOLD = std::chrono::milliseconds(DRALYXOR_TIMING_WALL_CLOCK_THRESHOLD_MS);
            constexpr std::uint64_t CYCLE_ANOMALY_THRESHOLD = DRALYXOR_TIMING_CYCLE_THRESHOLD;

            const std::uint64_t cycles_elapsed = cycles_end - cycles_start;
            const bool wall_clock_anomaly = elapsed > WALL_CLOCK_ANOMALY_THRESHOLD;
            const bool cycle_counter_anomaly = cycles_elapsed != 0 && cycles_elapsed > CYCLE_ANOMALY_THRESHOLD;

            if (wall_clock_anomaly || cycle_counter_anomaly)
                return Types::Detection_Flag::Timing_Anomaly;

            return Types::Detection_Flag::None;
        }
    }
}