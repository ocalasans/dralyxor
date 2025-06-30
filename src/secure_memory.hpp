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

#include <cstddef>
#include <type_traits>

#if defined(_WIN32) || defined(_WIN64)
    #if !defined(_KERNEL_MODE)
        #include <windows.h>
    #else
        extern "C" __declspec(dllimport) void __stdcall RtlSecureZeroMemory(void*, size_t);
    #endif
#else
    #include <string.h>
#endif

namespace Dralyxor {
    namespace Detail {
        template<typename T, size_t N_Clear>

        inline void Secure_Clear_Memory(T(&buffer)[N_Clear]) noexcept {
            static_assert(N_Clear > 0, "Secure_Clear_Memory cannot be used on zero-sized arrays.");
#if defined(_WIN32) || defined(_WIN64)
#if defined(_KERNEL_MODE)
            RtlSecureZeroMemory(buffer, sizeof(buffer));
#else
            SecureZeroMemory(buffer, sizeof(buffer));
#endif
#else
            volatile void* p_volatile_buffer = buffer;
            memset(const_cast<void*>(p_volatile_buffer), 0, sizeof(buffer));
#endif
        }

        inline void Secure_Clear_Memory_Raw(void* ptr, size_t bytes) noexcept {
            if (!ptr || bytes == 0)
                return;
#if defined(_WIN32) || defined(_WIN64)
#if defined(_KERNEL_MODE)
            RtlSecureZeroMemory(ptr, bytes);
#else
            SecureZeroMemory(ptr, bytes);
#endif
#else
            volatile void* p_volatile_ptr = ptr;
            memset(const_cast<void*>(p_volatile_ptr), 0, bytes);
#endif
        }
    }
}