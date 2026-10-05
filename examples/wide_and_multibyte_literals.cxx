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


// Char_T isn't limited to plain 'char': DRALYXOR_OBFUSCATED works with any 1/2/4/8-byte
// character type, so wchar_t, char16_t and char32_t literals are obfuscated exactly the same
// way. Note: don't mix std::printf and std::wprintf on the same stream (stdout here) --
// choosing an orientation, byte or wide, for a stream on its first use is a C stdio rule
// unrelated to Dralyxor, and mixing them silently drops output. This example sidesteps that
// entirely by printing every wide type as a sequence of codepoints instead.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

template<typename Char_T>
static void Print_Codepoints(const char* label, const Char_T* text) {
    std::printf("%s:", label);

    for (std::size_t i = 0; text[i] != 0; ++i)
        std::printf(" %04X", static_cast<unsigned>(text[i]));

    std::printf("\n");
}

int main() {
    auto narrow = DRALYXOR_OBFUSCATED("narrow");
    auto wide = DRALYXOR_OBFUSCATED(L"wide");
    auto utf16 = DRALYXOR_OBFUSCATED(u"utf16");
    auto utf32 = DRALYXOR_OBFUSCATED(U"utf32");

    std::printf("char: %s\n", narrow.Decrypt());
    Print_Codepoints("wchar_t", wide.Decrypt());
    Print_Codepoints("char16_t", utf16.Decrypt());
    Print_Codepoints("char32_t", utf32.Decrypt());

    return 0;
}