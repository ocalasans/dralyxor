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

#include "../platform.hxx"
//
#if DRALYXOR_WINDOWS && DRALYXOR_USER_MODE
    #define WIN32_LEAN_AND_MEAN

    #include <windows.h>
#endif

namespace Dralyxor {
    namespace Memory {
        inline void Secure_Clear::Apply(void* data, std::size_t size_in_bytes) noexcept {
            if (data == nullptr || size_in_bytes == 0)
                return;

#if DRALYXOR_WINDOWS && DRALYXOR_USER_MODE
            SecureZeroMemory(data, size_in_bytes);
#else
            volatile unsigned char* cursor = static_cast<volatile unsigned char*>(data);

            while (size_in_bytes-- > 0)
                *cursor++ = 0;
#endif
        }
    }
}