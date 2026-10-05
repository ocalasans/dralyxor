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


// Two identical literals obfuscated through separate DRALYXOR_OBFUSCATED calls -- even on
// different lines of the same file -- never end up encrypted with the same key: the macro
// automatically mixes the call site into the seed (via std::source_location on C++20+, or a
// file+line hash otherwise), so identical plaintext never produces identical ciphertext.
// DRALYXOR_OBFUSCATED_SEEDED additionally lets you fold in your own seed on top of that
// automatic diversity -- useful when you want the resulting ciphertext to also depend on
// something specific to your application (a build identifier, for instance).

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

int main() {
    auto first = DRALYXOR_OBFUSCATED("duplicate text");
    auto second = DRALYXOR_OBFUSCATED("duplicate text"); // same text, different line: different ciphertext
    auto with_custom_seed = DRALYXOR_OBFUSCATED_SEEDED("duplicate text", 0xC0FFEEULL);

    std::printf("first: %s\n", first.Decrypt());
    std::printf("second: %s\n", second.Decrypt());
    std::printf("with custom seed: %s\n", with_custom_seed.Decrypt());

    return 0;
}