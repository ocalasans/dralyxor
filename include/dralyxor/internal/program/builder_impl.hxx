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
        DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL Types::Micro_Program Builder::Build(std::uint64_t program_seed) noexcept {
            constexpr std::size_t CHOICE_COUNT = 7;

            constexpr Types::Operation_Code CHOICES[CHOICE_COUNT] = {
                Types::Operation_Code::Xor,
                Types::Operation_Code::Add,
                Types::Operation_Code::Sub,
                Types::Operation_Code::Rotate_Left,
                Types::Operation_Code::Rotate_Right,
                Types::Operation_Code::Swap_Halves,
                Types::Operation_Code::Multiply_Odd,
            };

            Prng::Splitmix64 rng {
                program_seed
            };
            
            Types::Micro_Program program {};

            constexpr std::size_t LENGTH_SPAN = Types::MAX_MICRO_INSTRUCTIONS - Types::MIN_MICRO_INSTRUCTIONS + 1;
            program.length = Types::MIN_MICRO_INSTRUCTIONS + static_cast<std::size_t>(rng.Next_Below(LENGTH_SPAN));

            for (std::size_t i = 0; i < program.length; ++i) {
                const Types::Operation_Code chosen_op = CHOICES[rng.Next_Below(CHOICE_COUNT)];
                std::uint8_t operand = static_cast<std::uint8_t>(rng.Next_Below(256));

                if (chosen_op == Types::Operation_Code::Multiply_Odd)
                    operand = static_cast<std::uint8_t>(operand | 1);

                program.instructions[i] = Types::Micro_Instruction {
                    chosen_op,
                    operand
                };
            }

            for (std::size_t i = program.length; i < Types::MAX_MICRO_INSTRUCTIONS; ++i) {
                program.instructions[i] = Types::Micro_Instruction {
                    Types::Operation_Code::End,
                    0
                };
            }

            return program;
        }
    }
}