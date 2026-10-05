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

namespace Dralyxor {
    namespace Obfuscated {
        template<typename Char_T, std::size_t N>
        constexpr String<Char_T, N>::String(const Payload::Types::Encrypted<Char_T, N>& payload) noexcept : _storage {}, _scrambled_program {
            payload.scrambled_program
        }, _base_seed {
            payload.base_seed
        }, _scrambled_checksum {
            payload.scrambled_checksum
        }, _tamper_guard {}, _last_detection_flags {
            Anti_Debug::Types::Detection_Flag::None
        }, _is_decrypted { false } {
            for (std::size_t i = 0; i < N; ++i)
                _storage[i] = payload.storage[i];
        }

        template<typename Char_T, std::size_t N>
        String<Char_T, N>::~String() noexcept {
            Memory::Secure_Clear::Apply(_storage, sizeof(_storage));
        }

        template<typename Char_T, std::size_t N>
        String<Char_T, N>::String(String&& other) noexcept : _storage{}, _scrambled_program {
            other._scrambled_program
        }, _base_seed {
            other._base_seed
        }, _scrambled_checksum {
            other._scrambled_checksum
        }, _tamper_guard {}, _last_detection_flags {
            other._last_detection_flags
        }, _is_decrypted {
            other._is_decrypted
        } {
            for (std::size_t i = 0; i < N; ++i)
                _storage[i] = other._storage[i];

            Memory::Secure_Clear::Apply(other._storage, sizeof(other._storage));

            other._is_decrypted = false;
            other._tamper_guard = Tamper_Guard {};
        }

        template<typename Char_T, std::size_t N>
        String<Char_T, N>& String<Char_T, N>::operator=(String&& other) noexcept {
            if (this == &other)
                return *this;

            Memory::Secure_Clear::Apply(_storage, sizeof(_storage));

            for (std::size_t i = 0; i < N; ++i)
                _storage[i] = other._storage[i];

            _scrambled_program = other._scrambled_program;
            _base_seed = other._base_seed;
            _scrambled_checksum = other._scrambled_checksum;
            _is_decrypted = other._is_decrypted;
            _last_detection_flags = other._last_detection_flags;

            _tamper_guard = Tamper_Guard {};

            Memory::Secure_Clear::Apply(other._storage, sizeof(other._storage));

            other._is_decrypted = false;
            other._tamper_guard = Tamper_Guard {};

            return *this;
        }

        template<typename Char_T, std::size_t N>
        void String<Char_T, N>::Ensure_Not_Tampered() noexcept {
            if (!_tamper_guard.Verify(this, _base_seed)) {
                Memory::Secure_Clear::Apply(_storage, sizeof(_storage));

                _is_decrypted = false;
            }
        }

        template<typename Char_T, std::size_t N>
        DRALYXOR_NODISCARD const Char_T* String<Char_T, N>::Decrypt() noexcept {
            Ensure_Not_Tampered();

            if (_is_decrypted)
                return _storage;

            const auto runtime_key_result = Anti_Debug::Runtime_Key::Calculate(_base_seed);

            _last_detection_flags = runtime_key_result.detected_flags;

            Crypto::Transform<Char_T>(_storage, N, _scrambled_program, runtime_key_result.effective_seed, true);

            _is_decrypted = true;

            return _storage;
        }

        template<typename Char_T, std::size_t N>
        void String<Char_T, N>::Encrypt() noexcept {
            Ensure_Not_Tampered();

            if (!_is_decrypted)
                return;

            Crypto::Transform<Char_T>(_storage, N, _scrambled_program, _base_seed, false);

            _is_decrypted = false;
        }

        template<typename Char_T, std::size_t N>
        DRALYXOR_NODISCARD bool String<Char_T, N>::Is_Content_Intact() const noexcept {
            if (!_is_decrypted)
                return false;

            const std::uint64_t expected_checksum = Checksum::Scrambler::Descramble(_scrambled_checksum, _base_seed);
            const std::uint64_t actual_checksum = Checksum::Calculator::Compute<Char_T>(_storage, N, _base_seed);

            return actual_checksum == expected_checksum;
        }
    }
}