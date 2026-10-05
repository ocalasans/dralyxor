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
//
#include "string.hxx"
//
#include "internal/attributes.hxx"
#include "internal/fnv1a/hash.hxx"
#include "internal/payload/builder.hxx"
#include "internal/payload/types.hxx"
#include "internal/standard.hxx"

namespace Dralyxor {
    namespace Internal {
        struct Macros {
            template<typename Char_T, std::size_t N>
            DRALYXOR_NODISCARD static inline Obfuscated::String<Char_T, N> From_Payload(const Payload::Types::Encrypted<Char_T, N>& payload) noexcept {
                return Obfuscated::String<Char_T, N>(payload);
            }

#if !DRALYXOR_HAS_SOURCE_LOCATION
            DRALYXOR_NODISCARD static constexpr std::uint64_t Call_Site_Diversity(const char* file, unsigned int line) noexcept {
                std::uint64_t seed = Fnv1a::Hash::Of_Cstr(file);

                seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(line));
                seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(line >> 8));
                seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(line >> 16));
                seed = Fnv1a::Hash::Mix_Byte(seed, static_cast<std::uint8_t>(line >> 24));

                return seed;
            }
#endif
        };
    }
}

#if DRALYXOR_HAS_CONSTEVAL
    #if DRALYXOR_HAS_SOURCE_LOCATION
        #define DRALYXOR_OBFUSCATED(literal_) \
            (Dralyxor::Internal::Macros::From_Payload(Dralyxor::Payload::Builder::Build((literal_), 0)))
        
        #define DRALYXOR_OBFUSCATED_SEEDED(literal_, seed_) \
            (Dralyxor::Internal::Macros::From_Payload(Dralyxor::Payload::Builder::Build((literal_), (seed_))))
    #else
        #define DRALYXOR_OBFUSCATED(literal_) \
            (Dralyxor::Internal::Macros::From_Payload(Dralyxor::Payload::Builder::Build((literal_), Dralyxor::Internal::Macros::Call_Site_Diversity(__FILE__, __LINE__))))
        
        #define DRALYXOR_OBFUSCATED_SEEDED(literal_, seed_) \
            (Dralyxor::Internal::Macros::From_Payload(Dralyxor::Payload::Builder::Build((literal_), Dralyxor::Internal::Macros::Call_Site_Diversity(__FILE__, __LINE__) ^ (seed_))))
    #endif
#else
    #define DRALYXOR_OBFUSCATED(literal_) \
        (Dralyxor::Internal::Macros::From_Payload([]() noexcept { \
            constexpr auto payload_ = Dralyxor::Payload::Builder::Build((literal_), Dralyxor::Internal::Macros::Call_Site_Diversity(__FILE__, __LINE__)); \
            \
            return payload_; \
        }()))
    
    #define DRALYXOR_OBFUSCATED_SEEDED(literal_, seed_) \
        (Dralyxor::Internal::Macros::From_Payload([]() noexcept { \
            constexpr auto payload_ = Dralyxor::Payload::Builder::Build((literal_), Dralyxor::Internal::Macros::Call_Site_Diversity(__FILE__, __LINE__) ^ (seed_)); \
            \
            return payload_; \
        }()))
#endif