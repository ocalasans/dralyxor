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


// Next_Below(bound) must stay inside [0, bound), treat 0 as "no range", and must not favour low
// values when the bound does not divide 2^64 evenly (the classic modulo bias). It also has to keep
// working in constant evaluation, because the micro-program is generated at compile time.

#include <cstdint>
#include <cstdio>
//
#include <dralyxor/internal/prng/splitmix64.hxx>
//
#include "check.hxx"

constexpr std::uint64_t Next_Below_At_Compile_Time(std::uint64_t seed, std::uint64_t bound) {
    Dralyxor::Prng::Splitmix64 generator { seed };

    return generator.Next_Below(bound);
}

void Test_Results_Stay_Inside_The_Requested_Range() {
    Dralyxor::Prng::Splitmix64 generator {
        12345ULL
    };

    const std::uint64_t bounds[] = {
        1,
        2,
        3,
        5,
        7,
        8,
        100,
        255,
        256,
        1000,
        65537
    };

    for (const std::uint64_t bound : bounds) {
        for (int sample = 0; sample < 2000; ++sample)
            DRALYXOR_CHECK(generator.Next_Below(bound) < bound);
    }

    std::printf("Test_Results_Stay_Inside_The_Requested_Range OK\n");
}

void Test_Zero_Bound_Returns_Zero() {
    Dralyxor::Prng::Splitmix64 generator { 1ULL };

    DRALYXOR_CHECK(generator.Next_Below(0) == 0);

    std::printf("Test_Zero_Bound_Returns_Zero OK\n");
}

void Test_Distribution_Is_Even_For_A_Bound_That_Does_Not_Divide_The_Range() {
    constexpr std::uint64_t BOUND = 3;
    constexpr int SAMPLES = 300000;

    Dralyxor::Prng::Splitmix64 generator {
        0xC0FFEEULL
    };

    int counts[BOUND] = {};

    for (int sample = 0; sample < SAMPLES; ++sample)
        ++counts[generator.Next_Below(BOUND)];

    const int expected = SAMPLES / static_cast<int>(BOUND);
    const int tolerance = expected / 50;

    for (std::uint64_t value = 0; value < BOUND; ++value) {
        const int deviation = counts[value] > expected ? counts[value] - expected : expected - counts[value];

        DRALYXOR_CHECK(deviation < tolerance);
    }

    std::printf("Test_Distribution_Is_Even_For_A_Bound_That_Does_Not_Divide_The_Range OK\n");
}

void Test_Works_In_Constant_Evaluation() {
    constexpr std::uint64_t at_compile_time = Next_Below_At_Compile_Time(99ULL, 1000);

    static_assert(at_compile_time < 1000, "Next_Below must be usable in constant evaluation and stay in range");

    DRALYXOR_CHECK(at_compile_time == Next_Below_At_Compile_Time(99ULL, 1000));

    std::printf("Test_Works_In_Constant_Evaluation OK\n");
}

int main() {
    Test_Results_Stay_Inside_The_Requested_Range();
    Test_Zero_Bound_Returns_Zero();
    Test_Distribution_Is_Even_For_A_Bound_That_Does_Not_Divide_The_Range();
    Test_Works_In_Constant_Evaluation();

    std::printf("All splitmix64_bounds tests passed\n");

    return 0;
}