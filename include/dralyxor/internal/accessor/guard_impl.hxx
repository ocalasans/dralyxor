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

namespace Dralyxor {
    namespace Accessor {
        template<typename String_T>
        Guard<String_T>::Guard(String_T& owner) noexcept : _storage {}, _accessor_seed { 0 }, _is_decrypted { false }, _owner_was_intact { false }, _owner_detection_flags {
            Anti_Debug::Types::Detection_Flag::None
        } {
            _accessor_seed = Integrity::Canary::Compute(this, static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(&owner)));

            const Char_Type* plaintext = owner.Decrypt();

            _owner_was_intact = owner.Is_Content_Intact();
            _owner_detection_flags = owner.Last_Detection_Flags();

            for (std::size_t i = 0; i < Storage_Size; ++i)
                _storage[i] = plaintext[i];

            owner.Encrypt();

            Crypto::Transform<Char_Type>(_storage, Storage_Size, Types::Accessor_Program(), _accessor_seed, false);
        }

        template<typename String_T>
        Guard<String_T>::~Guard() noexcept {
            Memory::Secure_Clear::Apply(_storage, sizeof(_storage));
        }

        template<typename String_T>
        DRALYXOR_NODISCARD const typename Guard<String_T>::Char_Type* Guard<String_T>::Get() noexcept {
            if (!_is_decrypted) {
                Crypto::Transform<Char_Type>(_storage, Storage_Size, Types::Accessor_Program(), _accessor_seed, true);

                _is_decrypted = true;
            }

            return _storage;
        }
    }
}