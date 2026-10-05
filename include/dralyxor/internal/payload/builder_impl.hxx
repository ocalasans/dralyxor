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

#include "../checksum/calculator.hxx"
#include "../checksum/scrambler.hxx"
#include "../crypto/cipher.hxx"
#include "../fnv1a/hash.hxx"
#include "../program/builder.hxx"
#include "../program/scrambler.hxx"
#include "../seed/mixing.hxx"
#include "../seed/source.hxx"

namespace Dralyxor {
    namespace Payload {
#if DRALYXOR_HAS_SOURCE_LOCATION
        template<typename Char_T, std::size_t N>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL Types::Encrypted<Char_T, N> Builder::Build(const Char_T (&literal)[N], std::uint64_t extra_seed, std::source_location call_site) noexcept {
#else
        template<typename Char_T, std::size_t N>
        DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL Types::Encrypted<Char_T, N> Builder::Build(const Char_T (&literal)[N], std::uint64_t extra_seed) noexcept {
#endif
            auto content_hash = Checksum::Calculator::Compute<Char_T>(literal, N, Fnv1a::Types::OFFSET_BASIS);

#if DRALYXOR_HAS_SOURCE_LOCATION
            auto seed = Seed::Source::Derive_Base(content_hash, extra_seed, call_site);
#else
            auto seed = Seed::Source::Derive_Base(content_hash, extra_seed);
#endif

            auto program_seed = Seed::Mixing::Derive_Sub(seed, Seed::Types::Domain::Program_Selection);
            auto program = Program::Builder::Build(program_seed);
            auto scramble_seed = Seed::Mixing::Derive_Sub(seed, Seed::Types::Domain::Program_Scramble);
            auto scrambled = Program::Scrambler::Scramble(program, scramble_seed);
            auto content_checksum = Checksum::Calculator::Compute<Char_T>(literal, N, seed);
            auto scrambled_checksum_value = Checksum::Scrambler::Scramble(content_checksum, seed);

            Types::Encrypted<Char_T, N> payload {};

            for (std::size_t i = 0; i < N; ++i)
                payload.storage[i] = literal[i];

            payload.base_seed = seed;
            payload.scrambled_program = scrambled;
            payload.scrambled_checksum = scrambled_checksum_value;

            Crypto::Transform<Char_T>(payload.storage, N, payload.scrambled_program, payload.base_seed, false);

            return payload;
        }
    }
}