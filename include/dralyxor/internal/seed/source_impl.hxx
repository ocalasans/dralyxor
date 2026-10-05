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

#include "../fnv1a/hash.hxx"

namespace Dralyxor {
    namespace Seed {
#if DRALYXOR_HAS_SOURCE_LOCATION
        DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL std::uint64_t Source::Derive_Base(std::uint64_t content_hash, std::uint64_t user_extra_seed, const std::source_location& call_site) noexcept {
            std::uint64_t seed = content_hash ^ user_extra_seed;

            seed = Fnv1a::Hash::Of_Cstr(call_site.file_name(), seed);
            seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(call_site.line()));
            seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(call_site.line() >> 8));
            seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(call_site.line() >> 16));
            seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(call_site.column()));
            seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(call_site.column() >> 8));

            return seed;
        }
#else
        DRALYXOR_NODISCARD DRALYXOR_CONSTEVAL std::uint64_t Source::Derive_Base(std::uint64_t content_hash, std::uint64_t user_extra_seed) noexcept {
            std::uint64_t seed = content_hash ^ user_extra_seed;

            seed = Fnv1a::Hash::Of_Cstr(__DATE__ __TIME__, seed);

            return seed;
        }
#endif
    }
}