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


// Decrypt() never fails loudly under a debugger: if a reliable debugger signal is present at
// the moment of decryption, the effective key is silently corrupted and the returned pointer
// holds garbage instead of the original text -- there's no exception, no abort. Is_Content_Intact()
// and Last_Detection_Flags() are how you find out, after the fact, whether what you got back
// is trustworthy. Accessor::Guard exposes the same information about its owner through
// Was_Owner_Content_Intact() and Owner_Detection_Flags(). Running this example normally (with
// no debugger attached) should print a clean, intact result; attach a debugger before calling
// Decrypt() to see it flip.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>

int main() {
    auto secret = DRALYXOR_OBFUSCATED("only trust this after checking Is_Content_Intact()");

    const char* content = secret.Decrypt();

    if (secret.Is_Content_Intact())
        std::printf("content is intact: %s\n", content);
    else
        std::printf("content looks tampered with or was decrypted under a debugger -- discard it\n");

    if (secret.Last_Detection_Flags() == Dralyxor::Detection_Flag::None)
        std::printf("no debugger/instrumentation signal observed during that decryption\n");
    else
        std::printf("at least one detection flag was set during that decryption\n");

    Dralyxor::Accessor::Guard guard(secret);

    std::printf("via guard: %s\n", guard.Get());

    std::printf("owner was intact when the guard was built: %s\n", guard.Was_Owner_Content_Intact() ? "yes" : "no");

    return 0;
}