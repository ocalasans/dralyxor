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

#include <cstdint>
//
#include "../attributes.hxx"
//
#include "types.hxx"

namespace Dralyxor {
    namespace Program {
        struct Scrambler {
            DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL static Types::Scrambled_Program Scramble(const Types::Micro_Program& program, std::uint64_t scramble_seed) noexcept;
            DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR DRALYXOR_NEVER_INLINE_CONSTEXPR_ATTR static Types::Micro_Program Descramble(const Types::Scrambled_Program& scrambled_program, std::uint64_t scramble_seed) noexcept;
        };
    }
}

#include "scrambler_impl.hxx"