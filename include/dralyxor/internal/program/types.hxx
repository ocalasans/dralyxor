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

#include <cstddef>
#include <cstdint>

namespace Dralyxor {
    namespace Program {
        struct Types {
            enum class Operation_Code : std::uint8_t {
                Nop,
                Xor,
                Add,
                Sub,
                Rotate_Left,
                Rotate_Right,
                Swap_Halves,
                Multiply_Odd,
                End,
            };

            struct Micro_Instruction {
                Operation_Code op_code = Operation_Code::Nop;
                std::uint8_t operand = 0;
            };

            static constexpr std::size_t MIN_MICRO_INSTRUCTIONS = 4;
            static constexpr std::size_t MAX_MICRO_INSTRUCTIONS = 8;

            struct Micro_Program {
                Micro_Instruction instructions[MAX_MICRO_INSTRUCTIONS] {};
                std::size_t length = 0;
            };

            struct Scrambled_Instruction {
                std::uint8_t masked_op_code = 0;
                std::uint8_t masked_operand = 0;
            };

            struct Scrambled_Program {
                Scrambled_Instruction instructions[MAX_MICRO_INSTRUCTIONS] {};
                std::size_t length = 0;
            };
        };
    }
}