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

#if defined(_MSC_VER) && defined(_MSVC_LANG)
    #define _DRALYXOR_CPP_STANDARD _MSVC_LANG
#elif defined(__cplusplus)
    #define _DRALYXOR_CPP_STANDARD __cplusplus
#else
    #error "Dralyxor requires a C++ compiler."
#endif

#if _DRALYXOR_CPP_STANDARD < 201402L 
    #error "Dralyxor requires at least C++14 support."
#endif

#if _DRALYXOR_CPP_STANDARD >= 202002L
    #define _DRALYXOR_CPP_VERSION 20
#elif _DRALYXOR_CPP_STANDARD >= 201703L
    #define _DRALYXOR_CPP_VERSION 17
#else
    #define _DRALYXOR_CPP_VERSION 14
#endif

#define _DRALYXOR_CONSTEXPR_FUNC constexpr

#if _DRALYXOR_CPP_VERSION >= 17
    #define _DRALYXOR_IF_CONSTEXPR if constexpr
#else
    #define _DRALYXOR_IF_CONSTEXPR if
#endif

#if _DRALYXOR_CPP_VERSION >= 20
    #define _DRALYXOR_CONSTEVAL consteval
#else
    #define _DRALYXOR_CONSTEVAL constexpr
#endif