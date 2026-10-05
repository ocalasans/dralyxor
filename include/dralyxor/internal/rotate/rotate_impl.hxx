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

#include "../standard.hxx"
//
#if DRALYXOR_HAS_CPP20
    #include <bit>
#endif

namespace Dralyxor {
    namespace Rotate {
        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Rotate::Left(Unsigned_T value, int bit_shift) noexcept {
#if DRALYXOR_HAS_CPP20
            return std::rotl(value, bit_shift);
#else
            constexpr int bit_width = static_cast<int>(sizeof(Unsigned_T) * 8);
            const unsigned int normalized_shift = static_cast<unsigned int>(bit_shift) % bit_width;

            if (normalized_shift == 0)
                return value;

            return static_cast<Unsigned_T>(static_cast<Unsigned_T>(value << normalized_shift) | static_cast<Unsigned_T>(value >> (bit_width - normalized_shift)));
#endif
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Rotate::Right(Unsigned_T value, int bit_shift) noexcept {
#if DRALYXOR_HAS_CPP20
            return std::rotr(value, bit_shift);
#else
            constexpr int bit_width = static_cast<int>(sizeof(Unsigned_T) * 8);
            const unsigned int normalized_shift = static_cast<unsigned int>(bit_shift) % bit_width;

            if (normalized_shift == 0)
                return value;

            return static_cast<Unsigned_T>(static_cast<Unsigned_T>(value >> normalized_shift) | static_cast<Unsigned_T>(value << (bit_width - normalized_shift)));
#endif
        }
    }
}