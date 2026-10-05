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

#include "../rotate/rotate.hxx"

namespace Dralyxor {
    namespace Program {
        namespace Internal {
            template<typename Unsigned_T>
            DRALYXOR_CONSTEXPR Unsigned_T Wrapping_Multiply(Unsigned_T a, Unsigned_T b) noexcept {
                return static_cast<Unsigned_T>(static_cast<std::uint64_t>(a) * static_cast<std::uint64_t>(b));
            }
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Operations::Modular_Inverse_Odd(Unsigned_T odd_value) noexcept {
            Unsigned_T inverse = odd_value;

            for (int round = 0; round < 6; ++round)
                inverse = Internal::Wrapping_Multiply(inverse, static_cast<Unsigned_T>(Unsigned_T { 2 } - Internal::Wrapping_Multiply(odd_value, inverse)));

            return inverse;
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Operations::Apply(Unsigned_T value, Types::Operation_Code op_code, std::uint8_t operand) noexcept {
            constexpr int bit_width = static_cast<int>(sizeof(Unsigned_T) * 8);
            const Unsigned_T wide_operand = static_cast<Unsigned_T>(operand);

            switch (op_code) {
                case Types::Operation_Code::Xor:
                    return static_cast<Unsigned_T>(value ^ wide_operand);
                case Types::Operation_Code::Add:
                    return static_cast<Unsigned_T>(value + wide_operand);
                case Types::Operation_Code::Sub:
                    return static_cast<Unsigned_T>(value - wide_operand);
                case Types::Operation_Code::Rotate_Left:
                    return Rotate::Rotate::Left(value, operand % bit_width);
                case Types::Operation_Code::Rotate_Right:
                    return Rotate::Rotate::Right(value, operand % bit_width);
                case Types::Operation_Code::Swap_Halves:
                    return Rotate::Rotate::Left(value, bit_width / 2);
                case Types::Operation_Code::Multiply_Odd:
                    return Internal::Wrapping_Multiply(value, static_cast<Unsigned_T>(operand | 1));
                case Types::Operation_Code::Nop:
                case Types::Operation_Code::End:
                default:
                    return value;
            }
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Unsigned_T Operations::Invert(Unsigned_T value, Types::Operation_Code op_code, std::uint8_t operand) noexcept {
            constexpr int bit_width = static_cast<int>(sizeof(Unsigned_T) * 8);
            const Unsigned_T wide_operand = static_cast<Unsigned_T>(operand);

            switch (op_code) {
                case Types::Operation_Code::Xor:
                    return static_cast<Unsigned_T>(value ^ wide_operand);
                case Types::Operation_Code::Add:
                    return static_cast<Unsigned_T>(value - wide_operand);
                case Types::Operation_Code::Sub:
                    return static_cast<Unsigned_T>(value + wide_operand);
                case Types::Operation_Code::Rotate_Left:
                    return Rotate::Rotate::Right(value, operand % bit_width);
                case Types::Operation_Code::Rotate_Right:
                    return Rotate::Rotate::Left(value, operand % bit_width);
                case Types::Operation_Code::Swap_Halves:
                    return Rotate::Rotate::Right(value, bit_width / 2);
                case Types::Operation_Code::Multiply_Odd:
                    return Internal::Wrapping_Multiply(value, Modular_Inverse_Odd(static_cast<Unsigned_T>(operand | 1)));
                case Types::Operation_Code::Nop:
                case Types::Operation_Code::End:
                default:
                    return value;
            }
        }
    }
}