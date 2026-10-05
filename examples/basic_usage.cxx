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


// DRALYXOR_OBFUSCATED is the entry point that works the same way on every
// supported C++ standard (14 through 23+): it hides the literal from the
// compiled binary and gives you back a Dralyxor::Obfuscated::String. Call
// Decrypt() to get a usable pointer, and Encrypt() once you're done with it
// so the plaintext doesn't linger in memory longer than necessary.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

int main() {
    auto greeting = DRALYXOR_OBFUSCATED("Hello from Dralyxor!");

    std::printf("decrypted: %s\n", greeting.Decrypt());
    std::printf("size (including null terminator): %zu\n", greeting.Size());

    greeting.Encrypt();

    std::printf("decrypted again after Encrypt(): %s\n", greeting.Decrypt());

    return 0;
}