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
#include "../platform.hxx"
//
#if DRALYXOR_WINDOWS && DRALYXOR_USER_MODE
    #define WIN32_LEAN_AND_MEAN

    #include <windows.h>
    #include <winternl.h>
#elif DRALYXOR_LINUX && DRALYXOR_USER_MODE
    #include <cstdio>
    #include <cstring>
#endif

namespace Dralyxor {
    namespace Anti_Debug {
#if DRALYXOR_WINDOWS && DRALYXOR_USER_MODE
        namespace Internal {
            using Nt_Query_Information_Process_Fn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

            constexpr ULONG PROCESS_DEBUG_PORT_CLASS = 7;
            constexpr ULONG PROCESS_DEBUG_OBJECT_HANDLE_CLASS = 30;
            constexpr ULONG PROCESS_DEBUG_FLAGS_CLASS = 31;

            DRALYXOR_NODISCARD inline Nt_Query_Information_Process_Fn Resolve_Nt_Query() noexcept {
                static const Nt_Query_Information_Process_Fn fn = []() -> Nt_Query_Information_Process_Fn {
                    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

                    if (ntdll == nullptr)
                        return nullptr;

                    return reinterpret_cast<Nt_Query_Information_Process_Fn>(reinterpret_cast<void*>(GetProcAddress(ntdll, "NtQueryInformationProcess")));
                }();

                return fn;
            }

#if DRALYXOR_GCC
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Warray-bounds"
    #pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif

            inline bool Check_Peb_Being_Debugged() noexcept {
                const PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;

                return peb != nullptr && peb->BeingDebugged != 0;
            }

            inline bool Check_Peb_Nt_Global_Flag() noexcept {
                const PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;

                if (peb == nullptr)
                    return false;

                constexpr std::ptrdiff_t nt_global_flag_offset = (sizeof(void*) == 8) ? 0xBC : 0x68;
                const auto nt_global_flag = *reinterpret_cast<const std::uint32_t*>(reinterpret_cast<const unsigned char*>(peb) + nt_global_flag_offset);

                constexpr std::uint32_t debug_heap_flags_mask = 0x70;

                return (nt_global_flag & debug_heap_flags_mask) == debug_heap_flags_mask;
            }

#if DRALYXOR_GCC
    #pragma GCC diagnostic pop
#endif

            inline bool Check_Debug_Object_Handle() noexcept {
                const auto query_fn = Resolve_Nt_Query();

                if (query_fn == nullptr)
                    return false;

                HANDLE debug_object_handle = nullptr;
                ULONG returned_length = 0;
                const LONG status = query_fn(GetCurrentProcess(), PROCESS_DEBUG_OBJECT_HANDLE_CLASS, &debug_object_handle, sizeof(debug_object_handle), &returned_length);

                return status == 0 && debug_object_handle != nullptr;
            }

            inline bool Check_Debug_Port() noexcept {
                const auto query_fn = Resolve_Nt_Query();

                if (query_fn == nullptr)
                    return false;

                ULONG_PTR debug_port_value = 0;
                ULONG returned_length = 0;
                const LONG status = query_fn(GetCurrentProcess(), PROCESS_DEBUG_PORT_CLASS, &debug_port_value, sizeof(debug_port_value), &returned_length);

                return status == 0 && debug_port_value != 0;
            }

            inline bool Check_Debug_Flags() noexcept {
                const auto query_fn = Resolve_Nt_Query();

                if (query_fn == nullptr)
                    return false;

                DWORD debug_flags = 0;
                ULONG returned_length = 0;
                const LONG status = query_fn(GetCurrentProcess(), PROCESS_DEBUG_FLAGS_CLASS, &debug_flags, sizeof(debug_flags), &returned_length);

                return status == 0 && debug_flags == 0;
            }

#if DRALYXOR_HAS_SEH
            inline bool Check_Invalid_Handle_Exception() noexcept {
                __try {
                    return (CloseHandle(reinterpret_cast<HANDLE>(static_cast<UINT_PTR>(0xDEADBEEF))), false);
                }
                __except (GetExceptionCode() == static_cast<DWORD>(EXCEPTION_INVALID_HANDLE) ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                    return true;
                }
            }
#endif
        }

        DRALYXOR_NODISCARD inline Types::Detection_Flag Presence::Check() noexcept {
            Types::Detection_Flag flags = Types::Detection_Flag::None;

            if (IsDebuggerPresent())
                flags |= Types::Detection_Flag::Debugger_Present_Api;

            BOOL remote_debugger_present = FALSE;

            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger_present) && remote_debugger_present)
                flags |= Types::Detection_Flag::Remote_Debugger_Api;

            if (Internal::Check_Peb_Being_Debugged())
                flags |= Types::Detection_Flag::Peb_Being_Debugged;

            if (Internal::Check_Peb_Nt_Global_Flag())
                flags |= Types::Detection_Flag::Peb_Nt_Global_Flag;

            if (Internal::Check_Debug_Object_Handle())
                flags |= Types::Detection_Flag::Debug_Object_Handle;

            if (Internal::Check_Debug_Port())
                flags |= Types::Detection_Flag::Debug_Port;

            if (Internal::Check_Debug_Flags())
                flags |= Types::Detection_Flag::Debug_Flags;

#if DRALYXOR_HAS_SEH
            if (Internal::Check_Invalid_Handle_Exception())
                flags |= Types::Detection_Flag::Invalid_Handle_Exception;
#endif

            return flags;
        }
#elif DRALYXOR_LINUX && DRALYXOR_USER_MODE
        namespace Internal {
            inline bool Check_Tracer_Pid() noexcept {
                std::FILE* status_file = std::fopen("/proc/self/status", "r");

                if (status_file == nullptr)
                    return false;

                char line[256];
                bool tracer_found = false;

                while (std::fgets(line, sizeof(line), status_file) != nullptr) {
                    if (std::strncmp(line, "TracerPid:", 10) == 0) {
                        int tracer_pid = 0;

                        if (std::sscanf(line + 10, "%d", &tracer_pid) == 1 && tracer_pid != 0)
                            tracer_found = true;

                        break;
                    }
                }

                std::fclose(status_file);

                return tracer_found;
            }
        }

        DRALYXOR_NODISCARD inline Types::Detection_Flag Presence::Check() noexcept {
            Types::Detection_Flag flags = Types::Detection_Flag::None;

            if (Internal::Check_Tracer_Pid())
                flags |= Types::Detection_Flag::Linux_Tracer_Pid;

            return flags;
        }
#else
        DRALYXOR_NODISCARD inline Types::Detection_Flag Presence::Check() noexcept {
            return Types::Detection_Flag::None;
        }
#endif
    }
}