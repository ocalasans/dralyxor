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
#include "../checksum/calculator.hxx"
#include "../integrity/canary.hxx"
#include "../seed/mixing.hxx"

namespace Dralyxor {
    namespace Obfuscated {
        template<typename Char_T>
        DRALYXOR_NODISCARD std::uint64_t Tamper_Guard::Compute_Canary(const void* owner_address, std::uint64_t seed, const Char_T* storage, std::size_t element_count) noexcept {
            const std::uint64_t content_fingerprint = Checksum::Calculator::Compute<Char_T>(storage, element_count, seed);
            const std::uint64_t content_aware_seed = Seed::Mixing::Derive_Sub(seed, Seed::Types::Domain::Content_Fingerprint, content_fingerprint);

            return Integrity::Canary::Compute(owner_address, content_aware_seed);
        }

        template<typename Char_T>
        void Tamper_Guard::Bind(const void* owner_address, std::uint64_t seed, const Char_T* storage, std::size_t element_count) noexcept {
            _canary = Compute_Canary<Char_T>(owner_address, seed, storage, element_count);
            _bound = true;
        }

        template<typename Char_T>
        DRALYXOR_NODISCARD bool Tamper_Guard::Verify(const void* owner_address, std::uint64_t seed, const Char_T* storage, std::size_t element_count) noexcept {
            const std::uint64_t expected_canary = Compute_Canary<Char_T>(owner_address, seed, storage, element_count);

            if (!_bound) {
                _canary = expected_canary;
                _bound = true;

                return true;
            }

            if (_canary != expected_canary)
                return (_canary = expected_canary, false);

            return true;
        }
    }
}