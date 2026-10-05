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
#include "../seed/mixing.hxx"

namespace Dralyxor {
    namespace Integrity {
        DRALYXOR_NODISCARD inline std::uint64_t Canary::Compute(const void* self_address, std::uint64_t seed) noexcept {
            const auto address_as_integer = reinterpret_cast<std::uintptr_t>(self_address);
            const std::uint64_t mixed_seed = Seed::Mixing::Derive_Sub(seed, Seed::Types::Domain::Canary, static_cast<std::uint64_t>(address_as_integer));

            return Prng::Splitmix64 {
                mixed_seed
            }.Next();
        }
    }
}