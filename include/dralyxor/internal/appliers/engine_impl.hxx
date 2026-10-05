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
#include "../program/runner.hxx"
#include "../seed/mixing.hxx"

namespace Dralyxor {
    namespace Appliers {
        namespace Internal {
            template<typename Unsigned_T>
            DRALYXOR_CONSTEXPR Unsigned_T Derive_Element_Key(std::uint64_t base_seed, Seed::Types::Domain domain, std::size_t element_index) noexcept {
                const std::uint64_t key_seed = Seed::Mixing::Derive_Sub(base_seed, domain, static_cast<std::uint64_t>(element_index));

                return static_cast<Unsigned_T>(Prng::Splitmix64{key_seed}.Next());
            }

            DRALYXOR_CONSTEXPR Types::Kind Derive_Applier_Kind(std::uint64_t base_seed, std::size_t element_index) noexcept {
                const std::uint64_t choice_seed = Seed::Mixing::Derive_Sub(base_seed, Seed::Types::Domain::Element_Applier_Choice, static_cast<std::uint64_t>(element_index));

                return static_cast<Types::Kind>(Prng::Splitmix64{choice_seed}.Next_Below(2));
            }
        }

        DRALYXOR_NEVER_INLINE_CONSTEXPR_BEGIN
        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR DRALYXOR_NEVER_INLINE_CONSTEXPR_ATTR Unsigned_T Engine::Apply(Unsigned_T value, std::size_t element_index, std::uint64_t base_seed, const Program::Types::Micro_Program& program) noexcept {
            const Types::Kind kind = Internal::Derive_Applier_Kind(base_seed, element_index);
            const Unsigned_T primary_key = Internal::Derive_Element_Key<Unsigned_T>(base_seed, Seed::Types::Domain::Element_Key_Primary, element_index);

            value = static_cast<Unsigned_T>(value ^ primary_key);
            value = Program::Runner::Run(value, program);

            if (kind == Types::Kind::Layered) {
                const Unsigned_T secondary_key = Internal::Derive_Element_Key<Unsigned_T>(base_seed, Seed::Types::Domain::Element_Key_Secondary, element_index);

                value = static_cast<Unsigned_T>(value ^ secondary_key);
                value = Program::Runner::Run(value, program);
            }

            return value;
        }

        template<typename Unsigned_T>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR DRALYXOR_NEVER_INLINE_CONSTEXPR_ATTR Unsigned_T Engine::Invert(Unsigned_T value, std::size_t element_index, std::uint64_t base_seed, const Program::Types::Micro_Program& program, const Program::Prepared_Inverse_Cache<Unsigned_T>& inverse_cache) noexcept {
            const Types::Kind kind = Internal::Derive_Applier_Kind(base_seed, element_index);
            const Unsigned_T primary_key = Internal::Derive_Element_Key<Unsigned_T>(base_seed, Seed::Types::Domain::Element_Key_Primary, element_index);

            if (kind == Types::Kind::Layered) {
                const Unsigned_T secondary_key = Internal::Derive_Element_Key<Unsigned_T>(base_seed, Seed::Types::Domain::Element_Key_Secondary, element_index);

                value = Program::Runner::Run_Inverse_Prepared(value, program, inverse_cache);
                value = static_cast<Unsigned_T>(value ^ secondary_key);
            }

            value = Program::Runner::Run_Inverse_Prepared(value, program, inverse_cache);
            value = static_cast<Unsigned_T>(value ^ primary_key);

            return value;
        }
        DRALYXOR_NEVER_INLINE_CONSTEXPR_END
    }
}