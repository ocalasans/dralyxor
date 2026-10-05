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

#include "operations.hxx"

namespace Dralyxor {
    namespace Program {
        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Runner::Run(Unsigned_T value, const Types::Micro_Program& program) noexcept {
            for (std::size_t i = 0; i < program.length; ++i)
                value = Operations::Apply(value, program.instructions[i].op_code, program.instructions[i].operand);

            return value;
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Runner::Run_Inverse(Unsigned_T value, const Types::Micro_Program& program) noexcept {
            for (std::size_t i = program.length; i > 0; --i) {
                const Types::Micro_Instruction& instruction = program.instructions[i - 1];

                value = Operations::Invert(value, instruction.op_code, instruction.operand);
            }

            return value;
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Prepared_Inverse_Cache<Unsigned_T> Runner::Prepare_For_Inverse(const Types::Micro_Program& program) noexcept {
            Prepared_Inverse_Cache<Unsigned_T> cache {};

            for (std::size_t i = 0; i < program.length; ++i) {
                if (program.instructions[i].op_code == Types::Operation_Code::Multiply_Odd)
                    cache.multiply_inverses[i] = Operations::Modular_Inverse_Odd(static_cast<Unsigned_T>(program.instructions[i].operand | 1));
            }

            return cache;
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Runner::Run_Inverse_Prepared(Unsigned_T value, const Types::Micro_Program& program, const Prepared_Inverse_Cache<Unsigned_T>& cache) noexcept {
            for (std::size_t i = program.length; i > 0; --i) {
                const std::size_t index = i - 1;
                const Types::Micro_Instruction& instruction = program.instructions[index];

                if (instruction.op_code == Types::Operation_Code::Multiply_Odd)
                    value = Internal::Wrapping_Multiply(value, cache.multiply_inverses[index]);
                else
                    value = Operations::Invert(value, instruction.op_code, instruction.operand);
            }

            return value;
        }
    }
}