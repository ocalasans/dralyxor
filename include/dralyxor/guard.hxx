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
#include "internal/anti_debug/types.hxx"
#include "internal/crypto/cipher.hxx"
#include "internal/integrity/canary.hxx"
#include "internal/memory/secure_clear.hxx"
#include "internal/accessor/types.hxx"

namespace Dralyxor {
    namespace Accessor {
        template<typename String_T>
        class Guard {
            public:
                using Char_Type = typename String_T::Char_Type;
                static constexpr std::size_t Storage_Size = String_T::Storage_Size;

                explicit Guard(String_T& owner) noexcept;
                ~Guard() noexcept;

                Guard(const Guard&) = delete;
                Guard& operator=(const Guard&) = delete;
                Guard(Guard&&) = delete;
                Guard& operator=(Guard&&) = delete;

                DRALYXOR_NODISCARD const Char_Type* Get() noexcept;

                DRALYXOR_NODISCARD bool Was_Owner_Content_Intact() const noexcept {
                    return _owner_was_intact;
                }

                DRALYXOR_NODISCARD Anti_Debug::Types::Detection_Flag Owner_Detection_Flags() const noexcept {
                    return _owner_detection_flags;
                }

            private:
                Char_Type _storage[Storage_Size];
                std::uint64_t _accessor_seed;
                bool _is_decrypted;
                bool _owner_was_intact;
                Anti_Debug::Types::Detection_Flag _owner_detection_flags;
        };
    }
}

#include "internal/accessor/guard_impl.hxx"