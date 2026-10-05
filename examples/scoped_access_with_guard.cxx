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


// Accessor::Guard gives you a scoped, RAII-managed view into an obfuscated String: on
// construction it decrypts the owner just long enough to copy its content into a buffer of its
// own (re-encrypted with a different seed than the owner's), and immediately re-encrypts the
// owner -- so the owner spends as little time decrypted as possible. Get() decrypts the
// Guard's own copy on demand, and the destructor always wipes it securely, whether or not
// Get() was ever called.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

int main() {
    auto token = DRALYXOR_OBFUSCATED("scoped-access-token");

    {
        Dralyxor::Accessor::Guard guard(token); // 'CTAD' deduces the owner's type

        std::printf("inside the scope: %s\n", guard.Get());
        // 'token' is already re-encrypted again at this point -- 'guard.Get()' is reading from
        // its own separate copy, not from 'token' directly
    } // guard's own copy is securely wiped here, regardless of whether 'Get()' was called

    std::printf("token is still usable afterwards: %s\n", token.Decrypt());

    return 0;
}