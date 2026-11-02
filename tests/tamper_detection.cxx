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


// The tamper guard has to notice an edit to the stored bytes -- ciphertext or plaintext -- and not
// only the object being relocated: a modified String must never hand the original secret back.
// Legitimate use (repeated Decrypt()/Encrypt(), moves) must keep working, which the other tests
// cover; this file covers the "someone wrote into the buffer" side.

#include <cstdio>
#include <cstring>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

void Test_Editing_Decrypted_Content_Is_Not_Served_Back_As_The_Secret() {
    auto text = DRALYXOR_OBFUSCATED("do not edit me in memory");

    char* writable_view = const_cast<char*>(text.Decrypt());

    writable_view[0] = 'X';

    DRALYXOR_CHECK(std::strcmp(text.Decrypt(), "Xo not edit me in memory") != 0);
    DRALYXOR_CHECK(!text.Is_Content_Intact());

    std::printf("Test_Editing_Decrypted_Content_Is_Not_Served_Back_As_The_Secret OK\n");
}

void Test_Editing_Encrypted_Content_Never_Yields_The_Secret() {
    auto text = DRALYXOR_OBFUSCATED("do not edit me either");

    char* writable_view = const_cast<char*>(text.Decrypt());

    text.Encrypt();

    writable_view[3] ^= 0x5A;

    const char* result = text.Decrypt();

    DRALYXOR_CHECK(std::strcmp(result, "do not edit me either") != 0);
    DRALYXOR_CHECK(!text.Is_Content_Intact());

    std::printf("Test_Editing_Encrypted_Content_Never_Yields_The_Secret OK\n");
}

void Test_Untouched_Content_Survives_Many_Cycles_Without_False_Positives() {
    auto text = DRALYXOR_OBFUSCATED("nobody touches this one");

    for (int cycle = 0; cycle < 50; ++cycle) {
        DRALYXOR_CHECK(std::strcmp(text.Decrypt(), "nobody touches this one") == 0);
        DRALYXOR_CHECK(std::strcmp(text.Decrypt(), "nobody touches this one") == 0); // redundant call in between
        DRALYXOR_CHECK(text.Is_Content_Intact());

        text.Encrypt();
        text.Encrypt(); // redundant call in between
    }

    std::printf("Test_Untouched_Content_Survives_Many_Cycles_Without_False_Positives OK\n");
}

int main() {
    Test_Editing_Decrypted_Content_Is_Not_Served_Back_As_The_Secret();
    Test_Editing_Encrypted_Content_Never_Yields_The_Secret();
    Test_Untouched_Content_Survives_Many_Cycles_Without_False_Positives();

    std::printf("All tamper_detection tests passed\n");

    return 0;
}