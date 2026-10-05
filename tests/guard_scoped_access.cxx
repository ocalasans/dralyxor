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


// Accessor::Guard: Get() must return the owner's real content, the owner must report itself as
// intact (and flag-free) under normal conditions when the Guard was built, and the owner must
// remain independently usable once the Guard's scope ends. The explicit template argument
// below (instead of CTAD) is deliberate, so this file also compiles under C++14, where Guard's
// implicit deduction guide isn't available yet.

#include <cstdio>
#include <cstring>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

void Test_Guard_Reads_Owner_Content() {
    auto owner = DRALYXOR_OBFUSCATED("guarded content");
    Dralyxor::Accessor::Guard<decltype(owner)> guard(owner);

    DRALYXOR_CHECK(std::strcmp(guard.Get(), "guarded content") == 0);

    std::printf("Test_Guard_Reads_Owner_Content OK\n");
}

void Test_Guard_Reports_Owner_Intact_And_No_Detection_Under_Normal_Conditions() {
    auto owner = DRALYXOR_OBFUSCATED("another guarded value");
    Dralyxor::Accessor::Guard<decltype(owner)> guard(owner);

    DRALYXOR_CHECK(guard.Was_Owner_Content_Intact());
    DRALYXOR_CHECK(guard.Owner_Detection_Flags() == Dralyxor::Detection_Flag::None);

    std::printf("Test_Guard_Reports_Owner_Intact_And_No_Detection_Under_Normal_Conditions OK\n");
}

void Test_Owner_Is_Usable_After_Guard_Scope_Ends() {
    auto owner = DRALYXOR_OBFUSCATED("still usable afterwards");

    {
        Dralyxor::Accessor::Guard<decltype(owner)> guard(owner);

        DRALYXOR_CHECK(std::strcmp(guard.Get(), "still usable afterwards") == 0);
    }

    DRALYXOR_CHECK(std::strcmp(owner.Decrypt(), "still usable afterwards") == 0);

    std::printf("Test_Owner_Is_Usable_After_Guard_Scope_Ends OK\n");
}

int main() {
    Test_Guard_Reads_Owner_Content();
    Test_Guard_Reports_Owner_Intact_And_No_Detection_Under_Normal_Conditions();
    Test_Owner_Is_Usable_After_Guard_Scope_Ends();

    std::printf("All guard_scoped_access tests passed\n");

    return 0;
}