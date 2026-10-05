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

#include "../attributes.hxx"
#include "../prng/splitmix64.hxx"

namespace Dralyxor {
    namespace Anti_Debug {
        namespace Internal {
            DRALYXOR_CONSTEXPR Types::Detection_Flag Reliable_Poison_Mask() noexcept {
                return Types::Detection_Flag::Peb_Being_Debugged
                    | Types::Detection_Flag::Peb_Nt_Global_Flag
                    | Types::Detection_Flag::Debug_Object_Handle
                    | Types::Detection_Flag::Debug_Port
                    | Types::Detection_Flag::Debugger_Present_Api
                    | Types::Detection_Flag::Remote_Debugger_Api
                    | Types::Detection_Flag::Hardware_Breakpoint
                    | Types::Detection_Flag::Linux_Tracer_Pid
                    | Types::Detection_Flag::Debug_Flags
                    | Types::Detection_Flag::Invalid_Handle_Exception;
            }
        }

        DRALYXOR_NODISCARD inline Types::Runtime_Key_Result Runtime_Key::Calculate(std::uint64_t base_seed) noexcept {
            Types::Detection_Flag flags = Types::Detection_Flag::None;

            flags |= Presence::Check();
            flags |= Timing::Check();
            flags |= Hardware_Breakpoints::Check();

            const bool has_reliable_signal = Types::Has_Flag(flags, Internal::Reliable_Poison_Mask());

            if (!has_reliable_signal) {
                return Types::Runtime_Key_Result {
                    base_seed,
                    flags
                };
            }

            const std::uint64_t corrupted_seed = Prng::Splitmix64 {
                base_seed ^ static_cast<std::uint64_t>(flags)
            }.Next();

            return Types::Runtime_Key_Result {
                corrupted_seed,
                flags
            };
        }
    }
}