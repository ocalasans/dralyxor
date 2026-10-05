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

#pragma once

#include <cstdint>

namespace Dralyxor {
    namespace Seed {
        struct Types {
            enum class Domain : std::uint64_t {
                Program_Selection = 0x9E3779B97F4A7C15ULL,
                Program_Scramble = 0xC2B2AE3D27D4EB4FULL,
                Element_Applier_Choice = 0x165667B19E3779F9ULL,
                Element_Key_Primary = 0x27D4EB2F165667C5ULL,
                Element_Key_Secondary = 0xFF51AFD7ED558CCDULL,
                Checksum_Scramble = 0xC4CEB9FE1A85EC53ULL,
                Canary = 0x2545F4914F6CDD1DULL,
            };
        };
    }
}