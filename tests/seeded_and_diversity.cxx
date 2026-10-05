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


// Two properties that back the "identical literals never produce identical ciphertext"
// guarantee described in string.hxx and macros.hxx: an explicit seed changes the encrypted
// output, and so does the call site alone (file + line), even with the exact same text and
// the exact same explicit seed. This reaches into Payload::Builder::Build directly (instead of
// going through DRALYXOR_OBFUSCATED/Obfuscated::String) because the encrypted bytes aren't
// observable through the public String API -- by design.

#include <cstdio>
#include <cstring>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

template<typename Char_T, std::size_t N>
static bool Storage_Bytes_Differ(const Dralyxor::Payload::Types::Encrypted<Char_T, N>& a, const Dralyxor::Payload::Types::Encrypted<Char_T, N>& b) {
    for (std::size_t i = 0; i < N; ++i) {
        if (a.storage[i] != b.storage[i])
            return true;
    }

    return false;
}

void Test_Different_Explicit_Seeds_Produce_Different_Ciphertext() {
    constexpr auto with_seed_a = Dralyxor::Payload::Builder::Build<char, 15>("identical text", 111ULL);
    constexpr auto with_seed_b = Dralyxor::Payload::Builder::Build<char, 15>("identical text", 222ULL);

    DRALYXOR_CHECK(with_seed_a.base_seed != with_seed_b.base_seed);
    DRALYXOR_CHECK(Storage_Bytes_Differ(with_seed_a, with_seed_b));

    std::printf("Test_Different_Explicit_Seeds_Produce_Different_Ciphertext OK\n");
}

void Test_Call_Site_Alone_Produces_Different_Ciphertext() {
#if DRALYXOR_HAS_SOURCE_LOCATION
    // on C++20+, 'Build()' captures 'std::source_location::current()' as a default argument, so
    // simply calling it again on the next line already changes the effective seed
    constexpr auto at_first_line = Dralyxor::Payload::Builder::Build<char, 15>("identical text");
    constexpr auto at_second_line = Dralyxor::Payload::Builder::Build<char, 15>("identical text");
#else
    // Pre-C++20, that diversity comes from hashing '__FILE__/__LINE__' by hand -- exactly what
    // 'DRALYXOR_OBFUSCATED' does internally
    constexpr auto at_first_line = Dralyxor::Payload::Builder::Build<char, 15>("identical text", Dralyxor::Internal::Macros::Call_Site_Diversity(__FILE__, __LINE__));
    constexpr auto at_second_line = Dralyxor::Payload::Builder::Build<char, 15>("identical text", Dralyxor::Internal::Macros::Call_Site_Diversity(__FILE__, __LINE__));
#endif

    DRALYXOR_CHECK(at_first_line.base_seed != at_second_line.base_seed);
    DRALYXOR_CHECK(Storage_Bytes_Differ(at_first_line, at_second_line));

    std::printf("Test_Call_Site_Alone_Produces_Different_Ciphertext OK\n");
}

void Test_Seeded_Macro_Decrypts_Correctly() {
    auto text = DRALYXOR_OBFUSCATED_SEEDED("seeded through the macro", 0xC0FFEEULL);

    DRALYXOR_CHECK(std::strcmp(text.Decrypt(), "seeded through the macro") == 0);

    std::printf("Test_Seeded_Macro_Decrypts_Correctly OK\n");
}

int main() {
    Test_Different_Explicit_Seeds_Produce_Different_Ciphertext();
    Test_Call_Site_Alone_Produces_Different_Ciphertext();
    Test_Seeded_Macro_Decrypts_Correctly();

    std::printf("All seeded_and_diversity tests passed\n");

    return 0;
}