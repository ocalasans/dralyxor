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

#include <cstdio>
//
#include "scenarios/anti_debug_check_cost.hxx"
#include "scenarios/consteval_vs_macro_parity.hxx"
#include "scenarios/decrypt_cost_by_length.hxx"
#include "scenarios/guard_vs_direct_access.hxx"

using namespace Dralyxor::Benchmark;

int main() {
    std::printf("Dralyxor Benchmark\n");

    Scenarios::Run_Decrypt_Cost_By_Length();
    Scenarios::Run_Anti_Debug_Check_Cost();
    Scenarios::Run_Consteval_Vs_Macro_Parity();
    Scenarios::Run_Guard_Vs_Direct_Access();

    std::printf("\nDone.\n");

    return 0;
}
