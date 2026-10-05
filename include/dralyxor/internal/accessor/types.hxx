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
#include "../program/builder.hxx"
#include "../program/scrambler.hxx"
#include "../program/types.hxx"

namespace Dralyxor {
    namespace Accessor {
        struct Types {
            static constexpr std::uint64_t PROGRAM_BUILD_SEED = 0x5EC0A11C0FFEEULL;

            DRALYXOR_NODISCARD static const Program::Types::Scrambled_Program& Accessor_Program() noexcept {
                static const Program::Types::Scrambled_Program program = Program::Scrambler::Scramble(Program::Builder::Build(PROGRAM_BUILD_SEED), PROGRAM_BUILD_SEED);

                return program;
            }
        };
    }
}