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


// Macro-based construction (the portable entry point) and, where available, direct
// construction via C++20 consteval + CTAD -- both must decrypt back to the exact original
// text, and Size() must always equal the literal's length including its null terminator.

#include <cstdio>
#include <cstring>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

void Test_Macro_Construction_Decrypts_To_Original_Text() {
    auto single_char = DRALYXOR_OBFUSCATED("a");
    auto short_text = DRALYXOR_OBFUSCATED("short");
    auto longer_text = DRALYXOR_OBFUSCATED("a fair bit longer than the other two literals");

    DRALYXOR_CHECK(std::strcmp(single_char.Decrypt(), "a") == 0);
    DRALYXOR_CHECK(std::strcmp(short_text.Decrypt(), "short") == 0);
    DRALYXOR_CHECK(std::strcmp(longer_text.Decrypt(), "a fair bit longer than the other two literals") == 0);

    std::printf("Test_Macro_Construction_Decrypts_To_Original_Text OK\n");
}

void Test_Size_Matches_Literal_Length_Plus_Null_Terminator() {
    auto five_chars = DRALYXOR_OBFUSCATED("12345");

    DRALYXOR_CHECK(five_chars.Size() == 6);
    DRALYXOR_CHECK(five_chars.Decrypt()[5] == '\0');

    std::printf("Test_Size_Matches_Literal_Length_Plus_Null_Terminator OK\n");
}

#if DRALYXOR_HAS_CONSTEVAL
void Test_Direct_Cpp20_Construction_Matches_Macro() {
    Dralyxor::Obfuscated::String direct("built without the macro");
    auto via_macro = DRALYXOR_OBFUSCATED("built without the macro");

    DRALYXOR_CHECK(std::strcmp(direct.Decrypt(), "built without the macro") == 0);
    DRALYXOR_CHECK(std::strcmp(via_macro.Decrypt(), "built without the macro") == 0);

    std::printf("Test_Direct_Cpp20_Construction_Matches_Macro OK\n");
}
#endif

int main() {
    Test_Macro_Construction_Decrypts_To_Original_Text();
    Test_Size_Matches_Literal_Length_Plus_Null_Terminator();

#if DRALYXOR_HAS_CONSTEVAL
    Test_Direct_Cpp20_Construction_Matches_Macro();
#endif

    std::printf("All construction tests passed\n");

    return 0;
}