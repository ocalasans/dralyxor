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


// Detection_Flag is a plain bitmask enum (None, |, &, |=, and the Has_Flag helper), fully
// testable on its own, plus the integration-level guarantee that a normal decryption with no
// debugger attached reports no flags and an intact checksum.

#include <cstdio>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

void Test_None_Is_The_Default_And_Empty_Value() {
    DRALYXOR_CHECK(Dralyxor::Detection_Flag::None == Dralyxor::Detection_Flag::None);
    DRALYXOR_CHECK(!Dralyxor::Anti_Debug::Types::Has_Flag(Dralyxor::Detection_Flag::None, Dralyxor::Detection_Flag::Peb_Being_Debugged));

    std::printf("Test_None_Is_The_Default_And_Empty_Value OK\n");
}

void Test_Bitwise_Or_Combines_Flags() {
    const auto combined = Dralyxor::Detection_Flag::Peb_Being_Debugged | Dralyxor::Detection_Flag::Hardware_Breakpoint;

    DRALYXOR_CHECK(Dralyxor::Anti_Debug::Types::Has_Flag(combined, Dralyxor::Detection_Flag::Peb_Being_Debugged));
    DRALYXOR_CHECK(Dralyxor::Anti_Debug::Types::Has_Flag(combined, Dralyxor::Detection_Flag::Hardware_Breakpoint));
    DRALYXOR_CHECK(!Dralyxor::Anti_Debug::Types::Has_Flag(combined, Dralyxor::Detection_Flag::Linux_Tracer_Pid));

    std::printf("Test_Bitwise_Or_Combines_Flags OK\n");
}

void Test_Bitwise_And_Extracts_Intersection() {
    const auto combined = Dralyxor::Detection_Flag::Debug_Port | Dralyxor::Detection_Flag::Timing_Anomaly;
    const auto mask = Dralyxor::Detection_Flag::Debug_Port | Dralyxor::Detection_Flag::Linux_Tracer_Pid;
    const auto intersection = combined & mask;

    DRALYXOR_CHECK(intersection == Dralyxor::Detection_Flag::Debug_Port);

    std::printf("Test_Bitwise_And_Extracts_Intersection OK\n");
}

void Test_Or_Assign_Accumulates_Flags() {
    auto accumulated = Dralyxor::Detection_Flag::None;

    accumulated |= Dralyxor::Detection_Flag::Linux_Tracer_Pid;
    accumulated |= Dralyxor::Detection_Flag::Debug_Flags;

    DRALYXOR_CHECK(Dralyxor::Anti_Debug::Types::Has_Flag(accumulated, Dralyxor::Detection_Flag::Linux_Tracer_Pid));
    DRALYXOR_CHECK(Dralyxor::Anti_Debug::Types::Has_Flag(accumulated, Dralyxor::Detection_Flag::Debug_Flags));

    std::printf("Test_Or_Assign_Accumulates_Flags OK\n");
}

void Test_Fresh_Decrypt_Reports_No_Detection_Under_Normal_Conditions() {
    // "Timing_Anomaly" is documented as unreliable (never part of the "trustworthy" mask), so in
    // principle a heavily loaded machine could make this flaky. If this test ever starts
    // failing intermittently under CI load, that's the flag to suspect first.
    auto text = DRALYXOR_OBFUSCATED("nobody is debugging this test");
    const char* decrypted = text.Decrypt();

    DRALYXOR_CHECK(decrypted[0] == 'n');
    DRALYXOR_CHECK(text.Is_Content_Intact());
    DRALYXOR_CHECK(text.Last_Detection_Flags() == Dralyxor::Detection_Flag::None);

    std::printf("Test_Fresh_Decrypt_Reports_No_Detection_Under_Normal_Conditions OK\n");
}

int main() {
    Test_None_Is_The_Default_And_Empty_Value();
    Test_Bitwise_Or_Combines_Flags();
    Test_Bitwise_And_Extracts_Intersection();
    Test_Or_Assign_Accumulates_Flags();
    Test_Fresh_Decrypt_Reports_No_Detection_Under_Normal_Conditions();

    std::printf("All detection_flags tests passed\n");

    return 0;
}