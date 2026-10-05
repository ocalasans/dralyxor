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

#if defined(_MSVC_LANG)
    #define DRALYXOR_CPLUSPLUS _MSVC_LANG
#else
    #define DRALYXOR_CPLUSPLUS __cplusplus
#endif

#define DRALYXOR_CPP17 201703L
#define DRALYXOR_CPP20 202002L
#define DRALYXOR_CPP23 202302L

#if DRALYXOR_CPLUSPLUS < 201402L
    #error "Dralyxor requires at least C++14."
#endif

#define DRALYXOR_HAS_CPP17 (DRALYXOR_CPLUSPLUS >= DRALYXOR_CPP17)
#define DRALYXOR_HAS_CPP20 (DRALYXOR_CPLUSPLUS >= DRALYXOR_CPP20)
#define DRALYXOR_HAS_CPP23 (DRALYXOR_CPLUSPLUS >= DRALYXOR_CPP23)

#if defined(__has_include)
    #if __has_include(<source_location>) && DRALYXOR_HAS_CPP20
        #define DRALYXOR_HAS_SOURCE_LOCATION 1
    #else
        #define DRALYXOR_HAS_SOURCE_LOCATION 0
    #endif
#else
    #define DRALYXOR_HAS_SOURCE_LOCATION 0
#endif

#if defined(__cpp_consteval)
    #define DRALYXOR_HAS_CONSTEVAL 1
#else
    #define DRALYXOR_HAS_CONSTEVAL 0
#endif