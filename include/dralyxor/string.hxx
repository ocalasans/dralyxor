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
#include "internal/attributes.hxx"
#include "internal/standard.hxx"
#include "internal/anti_debug/runtime_key.hxx"
#include "internal/checksum/calculator.hxx"
#include "internal/checksum/scrambler.hxx"
#include "internal/crypto/cipher.hxx"
#include "internal/memory/secure_clear.hxx"
#include "internal/payload/builder.hxx"
#include "internal/payload/types.hxx"
#include "internal/program/types.hxx"
#include "internal/obfuscated/tamper_guard.hxx"

#if DRALYXOR_HAS_SOURCE_LOCATION
    #include <source_location>
#endif

namespace Dralyxor {
    namespace Obfuscated {
        template<typename Char_T, std::size_t N>
        class String {
            static_assert(sizeof(Char_T) == 1 || sizeof(Char_T) == 2 || sizeof(Char_T) == 4 || sizeof(Char_T) == 8, "Dralyxor > Obfuscated > String: Char_T must be a 1, 2, 4, or 8-byte character type.");
            static_assert(N > 0, "Dralyxor > Obfuscated > String: the literal must include at least the null terminator.");

            public:
                using Char_Type = Char_T;
                static constexpr std::size_t Storage_Size = N;

#if DRALYXOR_HAS_CONSTEVAL
#if DRALYXOR_HAS_SOURCE_LOCATION
                DRALYXOR_CONSTEVAL String(const Char_T (&literal)[N], std::uint64_t extra_seed = 0, std::source_location call_site = std::source_location::current()) noexcept : String(Payload::Builder::Build<Char_T, N>(literal, extra_seed, call_site)) {}
#else
                DRALYXOR_CONSTEVAL String(const Char_T (&literal)[N], std::uint64_t extra_seed = 0) noexcept : String(Payload::Builder::Build<Char_T, N>(literal, extra_seed)) {}
#endif
#endif

                explicit constexpr String(const Payload::Types::Encrypted<Char_T, N>& payload) noexcept;

                ~String() noexcept;

                String(const String&) = delete;
                String& operator=(const String&) = delete;

                String(String&& other) noexcept;
                String& operator=(String&& other) noexcept;

                DRALYXOR_NODISCARD const Char_T* Decrypt() noexcept;
                void Encrypt() noexcept;

                DRALYXOR_NODISCARD bool Is_Content_Intact() const noexcept;

                DRALYXOR_NODISCARD Anti_Debug::Types::Detection_Flag Last_Detection_Flags() const noexcept {
                    return _last_detection_flags;
                }

                DRALYXOR_NODISCARD static constexpr std::size_t Size() noexcept {
                    return N;
                }

            private:
                void Ensure_Not_Tampered() noexcept;

                Char_T _storage[N];
                Program::Types::Scrambled_Program _scrambled_program;
                std::uint64_t _base_seed;
                std::uint64_t _scrambled_checksum;
                Tamper_Guard _tamper_guard;
                Anti_Debug::Types::Detection_Flag _last_detection_flags;
                bool _is_decrypted;
        };
    }
}

#include "internal/obfuscated/string_impl.hxx"