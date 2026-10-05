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


// Dralyxor's real floor is C++14 -- this example is deliberately built as cxx_std_14 (see
// examples/CMakeLists.txt) to prove DRALYXOR_OBFUSCATED works identically there. C++14 has no
// 'consteval', so the direct-construction shown in direct_construction_in_cpp20.cxx isn't
// available: Obfuscated::String only exposes a constructor that takes an already-built
// Payload::Types::Encrypted here. DRALYXOR_OBFUSCATED hides that difference and, just as
// importantly, forces genuine compile-time evaluation itself -- calling
// Payload::Builder::Build by hand in C++14/17 is only 'constexpr', which permits but does not
// guarantee compile-time evaluation, and at least one mainstream compiler has been observed to
// leave the literal in plaintext in the compiled object at -O0 when the macro isn't used.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

int main() {
    auto message = DRALYXOR_OBFUSCATED("compiled as C++14, works exactly the same");

    std::printf("decrypted: %s\n", message.Decrypt());

    return 0;
}