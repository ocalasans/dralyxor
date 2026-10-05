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

#include "../appliers/engine.hxx"
#include "../memory/type_traits.hxx"
#include "../program/runner.hxx"
#include "../program/scrambler.hxx"
#include "../seed/mixing.hxx"

namespace Dralyxor {
    namespace Crypto {
        template<typename Char_T>
        DRALYXOR_CONSTEXPR void Transform(Char_T* data, std::size_t element_count, const Program::Types::Scrambled_Program& scrambled_program, std::uint64_t base_seed, bool is_decrypt) noexcept {
            using Unsigned_T = Memory::Type_Traits::Unsigned_Equivalent<Char_T>;

            const std::uint64_t scramble_seed = Seed::Mixing::Derive_Sub(base_seed, Seed::Types::Domain::Program_Scramble);
            const Program::Types::Micro_Program program = Program::Scrambler::Descramble(scrambled_program, scramble_seed);

            const Program::Prepared_Inverse_Cache<Unsigned_T> inverse_cache = is_decrypt ? Program::Runner::Prepare_For_Inverse<Unsigned_T>(program) : Program::Prepared_Inverse_Cache<Unsigned_T> {};

            for (std::size_t i = 0; i < element_count; ++i) {
                const Unsigned_T current_value = static_cast<Unsigned_T>(data[i]);
                const Unsigned_T new_value = is_decrypt ? Appliers::Engine::Invert<Unsigned_T>(current_value, i, base_seed, program, inverse_cache) : Appliers::Engine::Apply<Unsigned_T>(current_value, i, base_seed, program);

                data[i] = static_cast<Char_T>(new_value);
            }
        }
    }
}