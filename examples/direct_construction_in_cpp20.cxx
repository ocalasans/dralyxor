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


// With a compiler that supports real C++20 'consteval' (DRALYXOR_HAS_CONSTEVAL), you don't
// need the DRALYXOR_OBFUSCATED macro at all: Obfuscated::String has a constructor that takes
// the literal directly and deduces Char_T/N through CTAD, and 'consteval' guarantees the
// encryption happens at compile time regardless of optimization level. Before C++20, that
// guarantee doesn't come for free from a plain 'constexpr' function (see
// minimum_supported_standard_cpp14.cxx for why the macro exists in the first place).

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

#if !DRALYXOR_HAS_CONSTEVAL
    #error "This example needs a compiler with C++20 consteval support -- build it with cxx_std_20 or newer."
#endif

int main() {
    Dralyxor::Obfuscated::String direct("constructed directly, no macro needed");

    std::printf("decrypted: %s\n", direct.Decrypt());

    return 0;
}