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


// String is move-only. A moved-to object must end up with the exact content and decrypted/
// encrypted state the source had; the moved-from source has its storage securely wiped and its
// decrypted flag cleared, so a later Decrypt() call on it runs the real decryption routine
// again on that wiped buffer instead of just handing back a cached pointer -- which correctly
// produces content that Is_Content_Intact() reports as NOT intact, rather than silently
// returning something that looks valid. Move assignment only exists between two String
// instances of the exact same Char_T/N (the storage is a fixed-size array), so both objects
// below are built from same-length literals on purpose.

#include <cstdio>
#include <cstring>
#include <utility>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

void Test_Move_Constructor_Transfers_Content_And_Decrypted_State() {
    auto original = DRALYXOR_OBFUSCATED("move me");
    const char* decrypted_before_move = original.Decrypt(); // put it in the decrypted state before moving

    DRALYXOR_CHECK(decrypted_before_move[0] == 'm');

    auto moved(std::move(original));

    DRALYXOR_CHECK(std::strcmp(moved.Decrypt(), "move me") == 0);
    DRALYXOR_CHECK(moved.Is_Content_Intact());

    std::printf("Test_Move_Constructor_Transfers_Content_And_Decrypted_State OK\n");
}

void Test_Move_Assignment_Transfers_Content_And_Decrypted_State() {
    auto original = DRALYXOR_OBFUSCATED("move-assign me"); // 14 chars + null = 15
    auto target = DRALYXOR_OBFUSCATED("overwritten!!!"); // same length, same 'String<char, 15>'
    const char* decrypted_before_move = original.Decrypt();

    DRALYXOR_CHECK(decrypted_before_move[0] == 'm');

    target = std::move(original);

    DRALYXOR_CHECK(std::strcmp(target.Decrypt(), "move-assign me") == 0);
    DRALYXOR_CHECK(target.Is_Content_Intact());

    std::printf("Test_Move_Assignment_Transfers_Content_And_Decrypted_State OK\n");
}

void Test_Moved_From_Object_Reports_Content_Not_Intact_After_Decrypt() {
    auto original = DRALYXOR_OBFUSCATED("source of a move");
    auto moved(std::move(original));

    const char* decrypted_from_moved = moved.Decrypt(); // just to make sure the moved-to object is still perfectly usable

    DRALYXOR_CHECK(decrypted_from_moved[0] == 's');

    const char* decrypted_from_moved_from = original.Decrypt(); // runs real decryption on the now securely-wiped storage

    DRALYXOR_CHECK(decrypted_from_moved_from != nullptr);
    DRALYXOR_CHECK(!original.Is_Content_Intact());

    std::printf("Test_Moved_From_Object_Reports_Content_Not_Intact_After_Decrypt OK\n");
}

int main() {
    Test_Move_Constructor_Transfers_Content_And_Decrypted_State();
    Test_Move_Assignment_Transfers_Content_And_Decrypted_State();
    Test_Moved_From_Object_Reports_Content_Not_Intact_After_Decrypt();

    std::printf("All move_semantics tests passed\n");

    return 0;
}