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
//
#include "../attributes.hxx"

namespace Dralyxor {
    namespace Anti_Debug {
        struct Types {
            enum class Detection_Flag : std::uint32_t {
                None,
                Peb_Being_Debugged = 1u << 0, // Reliable (Windows, via PEB->BeingDebugged).
                Peb_Nt_Global_Flag = 1u << 1, // Reliable (Windows, via PEB->NtGlobalFlag).
                Debug_Object_Handle = 1u << 2, // Reliable (Windows, via NtQuerySystemInformation/debug object handle).
                Debug_Port = 1u << 3, // Reliable (Windows, via NtQueryInformationProcess/ProcessDebugPort).
                Debugger_Present_Api = 1u << 4, // Reliable (Windows, via IsDebuggerPresent).
                Remote_Debugger_Api = 1u << 5, // Reliable (Windows, via CheckRemoteDebuggerPresent).
                Hardware_Breakpoint = 1u << 6, // Reliable (Windows and Linux, via debug registers Dr0-Dr7).
                Timing_Anomaly = 1u << 7, // NOT reliable: timing anomalies have too many legitimate causes (system load, thermal throttling, slow virtual machine) to serve as a standalone signal; never included in the reliable mask.
                Linux_Tracer_Pid = 1u << 8, // Reliable (Linux, via TracerPid in /proc/self/status).
                Debug_Flags = 1u << 9, // Reliable (Windows, via NtQueryInformationProcess/ProcessDebugFlags).
                Invalid_Handle_Exception = 1u << 10, // Reliable (Windows, requires SEH — DRALYXOR_HAS_SEH — via an exception when closing an invalid handle).
            };

            struct Runtime_Key_Result {
                std::uint64_t effective_seed;
                Detection_Flag detected_flags;
            };

            DRALYXOR_NODISCARD static DRALYXOR_CONSTEXPR bool Has_Flag(Detection_Flag flags, Detection_Flag flag_to_check) noexcept {
                return (static_cast<std::uint32_t>(flags) & static_cast<std::uint32_t>(flag_to_check)) != 0;
            }
        };

        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Types::Detection_Flag operator|(Types::Detection_Flag lhs, Types::Detection_Flag rhs) noexcept {
            return static_cast<Types::Detection_Flag>(static_cast<std::uint32_t>(lhs) | static_cast<std::uint32_t>(rhs));
        }

        DRALYXOR_NODISCARD DRALYXOR_CONSTEXPR Types::Detection_Flag operator&(Types::Detection_Flag lhs, Types::Detection_Flag rhs) noexcept {
            return static_cast<Types::Detection_Flag>(static_cast<std::uint32_t>(lhs) & static_cast<std::uint32_t>(rhs));
        }

        DRALYXOR_CONSTEXPR Types::Detection_Flag& operator|=(Types::Detection_Flag& lhs, Types::Detection_Flag rhs) noexcept {
            lhs = lhs | rhs;

            return lhs;
        }
    }
}