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


// Char_T isn't limited to 'char': String and DRALYXOR_OBFUSCATED work with any 1/2/4/8-byte
// character type. This runs the exact same round-trip check for char, wchar_t, char16_t, and
// char32_t through one templated test function.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

template<typename Char_T>
static bool Equal(const Char_T* a, const Char_T* b) {
    while (*a != Char_T(0) && *b != Char_T(0)) {
        if (*a != *b)
            return false;

        ++a;
        ++b;
    }

    return *a == *b;
}

void Test_Narrow_Char_Round_Trip() {
    auto text = DRALYXOR_OBFUSCATED("narrow");

    DRALYXOR_CHECK(Equal(text.Decrypt(), "narrow"));

    std::printf("Test_Narrow_Char_Round_Trip OK\n");
}

void Test_Wchar_T_Round_Trip() {
    auto text = DRALYXOR_OBFUSCATED(L"wide");

    DRALYXOR_CHECK(Equal(text.Decrypt(), L"wide"));

    std::printf("Test_Wchar_T_Round_Trip OK\n");
}

void Test_Char16_T_Round_Trip() {
    auto text = DRALYXOR_OBFUSCATED(u"utf16");

    DRALYXOR_CHECK(Equal(text.Decrypt(), u"utf16"));

    std::printf("Test_Char16_T_Round_Trip OK\n");
}

void Test_Char32_T_Round_Trip() {
    auto text = DRALYXOR_OBFUSCATED(U"utf32");

    DRALYXOR_CHECK(Equal(text.Decrypt(), U"utf32"));

    std::printf("Test_Char32_T_Round_Trip OK\n");
}

int main() {
    Test_Narrow_Char_Round_Trip();
    Test_Wchar_T_Round_Trip();
    Test_Char16_T_Round_Trip();
    Test_Char32_T_Round_Trip();

    std::printf("All generic_character_types tests passed\n");

    return 0;
}