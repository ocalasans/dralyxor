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

#include "../prng/splitmix64.hxx"
#include "../seed/mixing.hxx"

namespace Dralyxor {
    namespace Checksum {
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Scrambler::Scramble(std::uint64_t checksum, std::uint64_t seed) noexcept {
            const std::uint64_t mask_seed = Seed::Mixing::Derive_Sub(seed, Seed::Types::Domain::Checksum_Scramble);
            
            const std::uint64_t mask = Prng::Splitmix64 {
                mask_seed
            }.Next();

            return checksum ^ mask;
        }

        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR std::uint64_t Scrambler::Descramble(std::uint64_t scrambled_checksum, std::uint64_t seed) noexcept {
            return Scramble(scrambled_checksum, seed);
        }
    }
}