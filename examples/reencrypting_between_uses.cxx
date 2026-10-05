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


// A Dralyxor::Obfuscated::String isn't a one-shot capsule: Decrypt() and Encrypt() can be
// called any number of times over the object's lifetime. Calling Encrypt() as soon as you're
// done with a value -- instead of holding it decrypted for the rest of the program -- shrinks
// the window during which the plaintext sits in memory, at the cost of paying the decryption
// routine again the next time it's needed.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

static void Use_Api_Key(Dralyxor::Obfuscated::String<char, 15>& key) {
    std::printf("using api key: %s\n", key.Decrypt());
    
    key.Encrypt(); // don't leave it decrypted once this function is done with it
}

int main() {
    auto api_key = DRALYXOR_OBFUSCATED("sk_live_abc123");

    Use_Api_Key(api_key);

    std::printf("still encrypted here; decrypting again for a second use\n");

    Use_Api_Key(api_key);

    return 0;
}