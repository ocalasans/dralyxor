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

#include <type_traits>
//
#include "standard.hxx"
#include "compiler.hxx"

#if DRALYXOR_HAS_CPP23
    #include <utility>
#endif

#if DRALYXOR_HAS_CONSTEVAL
    #define DRALYXOR_CONSTEVAL consteval
#else
    #define DRALYXOR_CONSTEVAL constexpr
#endif

#define DRALYXOR_CONSTEXPR constexpr

#if DRALYXOR_HAS_CPP17
    #define DRALYXOR_NODISCARD [[nodiscard]]
#elif DRALYXOR_GNU_LIKE
    #define DRALYXOR_NODISCARD __attribute__((warn_unused_result))
#else
    #define DRALYXOR_NODISCARD
#endif

#if DRALYXOR_CLANG
    #define DRALYXOR_OPTNONE __attribute__((optnone))
#elif DRALYXOR_GCC
    #define DRALYXOR_OPTNONE __attribute__((optimize("O0")))
#else
    #define DRALYXOR_OPTNONE
#endif

#if DRALYXOR_GNU_LIKE
    #define DRALYXOR_NEVER_INLINE __attribute__((noinline))
#elif DRALYXOR_MSVC
    #define DRALYXOR_NEVER_INLINE __declspec(noinline)
#else
    #define DRALYXOR_NEVER_INLINE
#endif

#if DRALYXOR_GCC
    #define DRALYXOR_NEVER_INLINE_CONSTEXPR_BEGIN _Pragma("GCC push_options") _Pragma("GCC optimize(\"no-inline\")")
    #define DRALYXOR_NEVER_INLINE_CONSTEXPR_END _Pragma("GCC pop_options")

     #define DRALYXOR_NEVER_INLINE_CONSTEXPR_ATTR
#else
    #define DRALYXOR_NEVER_INLINE_CONSTEXPR_BEGIN
    #define DRALYXOR_NEVER_INLINE_CONSTEXPR_END

    #define DRALYXOR_NEVER_INLINE_CONSTEXPR_ATTR DRALYXOR_NEVER_INLINE
#endif

#if DRALYXOR_HAS_CPP23
    #define DRALYXOR_TO_UNDERLYING(value_) (std::to_underlying(value_))
#else
    #define DRALYXOR_TO_UNDERLYING(value_) (static_cast<std::underlying_type_t<decltype(value_)>>(value_))
#endif