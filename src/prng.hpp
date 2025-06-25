/* ============================================================================= *
 * Dralyxor - The Definitive C++ String Obfuscator ↓                             *
 * An advanced, header-only C++ library for compile-time string obfuscation.     *
 * ============================================================================= *
 *                                                                               *
 * Copyright (c) 2025, Calasans | All rights reserved.                           *
 *                                                                               *
 * Developed by: Calasans                                                        *
 * Repository: https://github.com/ocalasans/dralyxor                             *
 *                                                                               *
 * ============================================================================= *
 *                                                                               *
 * Licensed under the MIT License (MIT);                                         *
 * you may not use this file except in compliance with the License.              *
 * You may obtain a copy of the License at:                                      *
 *                                                                               *
 *     https://opensource.org/licenses/MIT                                       *
 *                                                                               *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      *
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   *
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        *
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, *
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     *
 * THE SOFTWARE.                                                                 *
 *                                                                               *
 * ============================================================================= */

#pragma once

#include <cstdint>
//
#include "detection.hpp"

namespace Dralyxor {
    namespace Detail {
        _DRALYXOR_CONSTEVAL uint64_t fnv1a_hash(const char* str, uint64_t hash = 14695981039346656037ULL) {
            return (*str == 0) ? hash : fnv1a_hash(str + 1, (hash ^ static_cast<uint64_t>(*str)) * 1099511628211ULL);
        }

        class Constexpr_PRNG {
            private:
                uint64_t state;
            public:
                constexpr Constexpr_PRNG(uint64_t seed) : state(seed == 0 ? 1 : seed) {}

                constexpr Constexpr_PRNG Next() const {
                    return Constexpr_PRNG(state * 6364136223846793005ULL + 1442695040888963407ULL);
                }
                
                constexpr uint8_t Key() const {
                    return static_cast<uint8_t>( (state ^ (state >> 32)) & 0xFF);
                }
        };
    }
}