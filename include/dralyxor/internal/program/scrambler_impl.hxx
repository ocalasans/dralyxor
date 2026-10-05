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

namespace Dralyxor {
    namespace Program {
        DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL Types::Scrambled_Program Scrambler::Scramble(const Types::Micro_Program& program, std::uint64_t scramble_seed) noexcept {
            Prng::Splitmix64 rng {
                scramble_seed
            };

            Types::Scrambled_Program scrambled {};

            scrambled.length = program.length;

            for (std::size_t i = 0; i < Types::MAX_MICRO_INSTRUCTIONS; ++i) {
                const std::uint64_t mask = rng.Next();
                const auto op_mask = static_cast<std::uint8_t>(mask);
                const auto operand_mask = static_cast<std::uint8_t>(mask >> 8);

                scrambled.instructions[i].masked_op_code = static_cast<std::uint8_t>(DRALYXOR_TO_UNDERLYING(program.instructions[i].op_code) ^ op_mask);
                scrambled.instructions[i].masked_operand = static_cast<std::uint8_t>(program.instructions[i].operand ^ operand_mask);
            }

            return scrambled;
        }

        DRALYXOR_NEVER_INLINE_CONSTEXPR_BEGIN
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR DRALYXOR_NEVER_INLINE_CONSTEXPR_ATTR Types::Micro_Program Scrambler::Descramble(const Types::Scrambled_Program& scrambled_program, std::uint64_t scramble_seed) noexcept {
            Prng::Splitmix64 rng {
                scramble_seed
            };
            
            Types::Micro_Program program {};

            program.length = scrambled_program.length;

            for (std::size_t i = 0; i < Types::MAX_MICRO_INSTRUCTIONS; ++i) {
                const std::uint64_t mask = rng.Next();
                const auto op_mask = static_cast<std::uint8_t>(mask);
                const auto operand_mask = static_cast<std::uint8_t>(mask >> 8);

                program.instructions[i].op_code = static_cast<Types::Operation_Code>(scrambled_program.instructions[i].masked_op_code ^ op_mask);
                program.instructions[i].operand = static_cast<std::uint8_t>(scrambled_program.instructions[i].masked_operand ^ operand_mask);
            }

            return program;
        }
        DRALYXOR_NEVER_INLINE_CONSTEXPR_END
    }
}