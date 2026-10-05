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
    namespace Fnv1a {
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Hash::Mix_Byte(std::uint64_t hash, std::uint8_t byte) noexcept {
            hash ^= static_cast<std::uint64_t>(byte);
            hash *= Types::PRIME;

            return hash;
        }

        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Hash::Of_Cstr(const char* null_terminated_data, std::uint64_t seed) noexcept {
            std::uint64_t hash = seed;

            for (std::size_t i = 0; null_terminated_data[i] != '\0'; ++i)
                hash = Mix_Byte(hash, static_cast<std::uint8_t>(null_terminated_data[i]));

            return hash;
        }
    }
}