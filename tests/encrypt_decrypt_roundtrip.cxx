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


// Decrypt()/Encrypt() aren't one-shot: a String can be decrypted, re-encrypted, and decrypted
// again any number of times, and calling either one when it's already in the state it would
// produce (Decrypt() while already decrypted, Encrypt() while already encrypted) is a
// harmless no-op rather than an error.

#include <cstdio>
#include <cstring>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

void Test_Multiple_Decrypt_Encrypt_Cycles_Preserve_Content() {
    auto text = DRALYXOR_OBFUSCATED("round trip me a few times");

    for (int cycle = 0; cycle < 5; ++cycle) {
        DRALYXOR_CHECK(std::strcmp(text.Decrypt(), "round trip me a few times") == 0);

        text.Encrypt();
    }

    std::printf("Test_Multiple_Decrypt_Encrypt_Cycles_Preserve_Content OK\n");
}

void Test_Decrypt_Is_Idempotent_Without_Encrypt_Between_Calls() {
    auto text = DRALYXOR_OBFUSCATED("idempotent decrypt");

    const char* first_pointer = text.Decrypt();
    const char* second_pointer = text.Decrypt();

    DRALYXOR_CHECK(first_pointer == second_pointer);
    DRALYXOR_CHECK(std::strcmp(second_pointer, "idempotent decrypt") == 0);

    std::printf("Test_Decrypt_Is_Idempotent_Without_Encrypt_Between_Calls OK\n");
}

void Test_Encrypt_Without_Pending_Decryption_Is_A_No_Op() {
    auto text = DRALYXOR_OBFUSCATED("never decrypted yet");

    text.Encrypt(); // no prior 'Decrypt()' call -- must not crash or corrupt anything
    text.Encrypt(); // calling it twice in a row must also be harmless

    DRALYXOR_CHECK(std::strcmp(text.Decrypt(), "never decrypted yet") == 0);

    std::printf("Test_Encrypt_Without_Pending_Decryption_Is_A_No_Op OK\n");
}

int main() {
    Test_Multiple_Decrypt_Encrypt_Cycles_Preserve_Content();
    Test_Decrypt_Is_Idempotent_Without_Encrypt_Between_Calls();
    Test_Encrypt_Without_Pending_Decryption_Is_A_No_Op();

    std::printf("All encrypt_decrypt_roundtrip tests passed\n");

    return 0;
}