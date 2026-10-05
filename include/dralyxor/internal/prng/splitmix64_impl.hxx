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

namespace Dralyxor {
    namespace Prng {
        DRALYXOR_CONSTEXPR Splitmix64::Splitmix64(std::uint64_t seed) noexcept : _state { seed } {}

        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Splitmix64::Next() noexcept {
            _state += 0x9E3779B97F4A7C15ULL;

            std::uint64_t z = _state;

            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;

            return z ^ (z >> 31);
        }

        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Splitmix64::Next_Below(std::uint64_t exclusive_upper_bound) noexcept {
            if (exclusive_upper_bound == 0)
                return 0;

            return Next() % exclusive_upper_bound;
        }
    }
}