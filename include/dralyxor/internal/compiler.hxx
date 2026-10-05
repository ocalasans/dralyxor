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

#if defined(__clang__)
    #define DRALYXOR_CLANG 1
#else
    #define DRALYXOR_CLANG 0
#endif

#if defined(_MSC_VER) && !DRALYXOR_CLANG
    #define DRALYXOR_MSVC 1
#else
    #define DRALYXOR_MSVC 0
#endif

#if defined(__GNUC__) && !DRALYXOR_CLANG && !DRALYXOR_MSVC
    #define DRALYXOR_GCC 1
#else
    #define DRALYXOR_GCC 0
#endif

#define DRALYXOR_GNU_LIKE (DRALYXOR_CLANG || DRALYXOR_GCC)

#if defined(_MSC_VER)
    #define DRALYXOR_HAS_SEH 1
#else
    #define DRALYXOR_HAS_SEH 0
#endif