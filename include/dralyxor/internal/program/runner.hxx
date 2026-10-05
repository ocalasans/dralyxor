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

#include "../attributes.hxx"
//
#include "types.hxx"

namespace Dralyxor {
    namespace Program {
        template<typename Unsigned_T>
        struct Prepared_Inverse_Cache {
            Unsigned_T multiply_inverses[Types::MAX_MICRO_INSTRUCTIONS] {};
        };

        struct Runner {
            template<typename Unsigned_T>
            DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR static Unsigned_T Run(Unsigned_T value, const Types::Micro_Program& program) noexcept;

            template<typename Unsigned_T>
            DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR static Unsigned_T Run_Inverse(Unsigned_T value, const Types::Micro_Program& program) noexcept;

            template<typename Unsigned_T>
            DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR static Prepared_Inverse_Cache<Unsigned_T> Prepare_For_Inverse(const Types::Micro_Program& program) noexcept;

            template<typename Unsigned_T>
            DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR static Unsigned_T Run_Inverse_Prepared(Unsigned_T value, const Types::Micro_Program& program, const Prepared_Inverse_Cache<Unsigned_T>& cache) noexcept;
        };
    }
}

#include "runner_impl.hxx"