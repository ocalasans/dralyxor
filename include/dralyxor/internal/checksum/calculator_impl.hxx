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

#include "../fnv1a/hash.hxx"
#include "../memory/type_traits.hxx"

namespace Dralyxor {
    namespace Checksum {
        template<typename Char_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Calculator::Compute(const Char_T* data, std::size_t element_count, std::uint64_t seed) noexcept {
            using Unsigned_T = Memory::Type_Traits::Unsigned_Equivalent<Char_T>;

            std::uint64_t hash = seed;

            for (std::size_t i = 0; i < element_count; ++i) {
                const Unsigned_T value = static_cast<Unsigned_T>(data[i]);

                for (std::size_t byte_index = 0; byte_index < sizeof(Unsigned_T); ++byte_index) {
                    const auto byte = static_cast<std::uint8_t>(value >> (byte_index * 8));

                    hash = Fnv1a::Hash::Mix_Byte(hash, byte);
                }
            }

            return hash;
        }
    }
}