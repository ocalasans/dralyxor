/* ============================================================================= *
 * Dralyxor - The Definitive C++ String Obfuscator ↓                             *
 * An advanced, header-only C++ library for compile-time string obfuscation.     *
 * ============================================================================= *
 *                                                                               *
 * Copyright (c) 2025, Calasans | All rights reserved.                           *
 *                                                                               *
 * Developed by: Calasans                                                        *
 * Repository: https://github.com/ocalasans/dralyxor                             *
 *                                                                               *
 * ============================================================================= *
 *                                                                               *
 * Licensed under the MIT License (MIT);                                         *
 * you may not use this file except in compliance with the License.              *
 * You may obtain a copy of the License at:                                      *
 *                                                                               *
 *     https://opensource.org/licenses/MIT                                       *
 *                                                                               *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR    *
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,      *
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE   *
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER        *
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, *
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN     *
 * THE SOFTWARE.                                                                 *
 *                                                                               *
 * ============================================================================= */

#pragma once

#include <cstdint>
#include <chrono>

#if defined(_WIN32) || defined(_WIN64)
    #if !defined(_KERNEL_MODE)
        #include <windows.h>
        #include <winternl.h>

        #ifndef DRALYXOR_NTSTATUS
            #define DRALYXOR_NTSTATUS LONG
        #endif

        typedef DRALYXOR_NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE ProcessHandle, ULONG ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    #endif
#elif defined(__linux__)
    #include <fstream>
    #include <string>
#elif defined(__APPLE__) && defined(__MACH__)
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <unistd.h>

    #if !defined(P_TRACED) && defined(KERN_PROC_PID)
        #include <sys/proc.h>
    #endif
#endif
//
#include "detection.hpp"
#include "integrity_constants.hpp"

namespace Dralyxor {
    namespace Detail {
        constexpr uint64_t mod_is_debugger_present_rt = 0xA100000000000001ULL;
        constexpr uint64_t mod_timing_check_generic_rt = 0xA300000000000003ULL;
        constexpr uint64_t mod_output_debug_string_trick_rt = 0xA400000000000004ULL;

        _DRALYXOR_CONSTEXPR_FUNC uint8_t Canary_Function_For_Breakpoint_Check() {
            uint8_t val = 0xCC;

            return val;
        }

        inline bool Is_Debugger_Present_Tracer_Pid_Sysctl() noexcept {
#if defined(_WIN32) && !defined(_KERNEL_MODE)
            if (IsDebuggerPresent() != 0)
                return true;

            HMODULE hNtDll = GetModuleHandleA("ntdll.dll");

            if (hNtDll) {
                auto ntQueryInfoProc = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

                if (ntQueryInfoProc) {
                    DWORD_PTR dwIsDebuggerPresent = 0;

                    if (ntQueryInfoProc(GetCurrentProcess(), 0x07, &dwIsDebuggerPresent, sizeof(DWORD_PTR), NULL) == 0 && dwIsDebuggerPresent != 0)
                        return true;

                    ULONG_PTR ulProcessDebugFlags = 1;

                    if (ntQueryInfoProc(GetCurrentProcess(), 0x1F, &ulProcessDebugFlags, sizeof(ULONG_PTR), NULL) == 0 && ulProcessDebugFlags == 0)
                        return true;
                }
            }
#elif defined(__linux__)
            std::ifstream status_file("/proc/self/status");
            std::string line_content;

            if (status_file.is_open()) {
                while (std::getline(status_file, line_content)) {
                    if (line_content.rfind("TracerPid:", 0) == 0) {
                        size_t first_digit_pos = line_content.find_first_of("0123456789");

                        if (first_digit_pos != std::string::npos) {
                            int tracer_pid_val = 0;

                            try {
                                tracer_pid_val = std::stoi(line_content.substr(first_digit_pos));
                            }
                            catch (const std::exception&) {
                                tracer_pid_val = 0;
                            }

                            if (tracer_pid_val != 0)
                                return true;
                        }

                        break;
                    }
                }
            }
#elif defined(__APPLE__) && defined(__MACH__)
            int mib_val[4];
            struct kinfo_proc info_proc_val;
            size_t size_val = sizeof(info_proc_val);

            mib_val[0] = CTL_KERN;
            mib_val[1] = KERN_PROC;
            mib_val[2] = KERN_PROC_PID;
            mib_val[3] = getpid();

            if (sysctl(mib_val, sizeof(mib_val) / sizeof(*mib_val), &info_proc_val, &size_val, NULL, 0) == 0) {
                if ((info_proc_val.kp_proc.p_flag & P_TRACED) != 0)
                    return true;
            }
#endif
            return false;
        }
        
        inline bool Perform_Timing_Check_Generic() noexcept {
            volatile uint64_t dummy_op_counter = 0;
            auto time_start = std::chrono::high_resolution_clock::now();
            
            for (volatile int i = 0; i < 20000; ++i) {
                dummy_op_counter = (dummy_op_counter + i) ^ (uint64_t)0x5A5A5A5A5A5A5A5AULL;

                if ((i & 0xFFF) == 0 && Is_Debugger_Present_Tracer_Pid_Sysctl())
                    return true;
            }

            dummy_op_counter ^= Canary_Function_For_Breakpoint_Check();

            auto time_end = std::chrono::high_resolution_clock::now();
            auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(time_end - time_start).count();

            constexpr long long timing_threshold_milliseconds = 75;

            if (duration_ms > timing_threshold_milliseconds)
                return true;

            return false;
        }
#if defined(_WIN32) && !defined(_KERNEL_MODE)
        inline bool Perform_Output_Debug_String_Trick() noexcept {
            DWORD last_err_val = GetLastError();
            OutputDebugStringA("DRLX_DBGCHK_A");

            if (GetLastError() != last_err_val) {
                SetLastError(0);
                OutputDebugStringW(L"DRLX_DBGCHK_W");

                if (GetLastError() != 0) {
                    return (SetLastError(last_err_val), true);
                }
            }

            SetLastError(last_err_val);

            return false;
        }
#endif
        inline uint64_t Calculate_Runtime_Key_Modifier(uint32_t current_canary1, uint32_t current_canary2) noexcept {
            uint64_t rt_modifier = 0;

            if (current_canary1 != integrity_canary_value || current_canary2 != ~integrity_canary_value)
                return integrity_compromised_magic;

            if (Is_Debugger_Present_Tracer_Pid_Sysctl())
                rt_modifier ^= mod_is_debugger_present_rt;

            if (Perform_Timing_Check_Generic())
                rt_modifier ^= mod_timing_check_generic_rt;
#if defined(_WIN32) && !defined(_KERNEL_MODE)
            if (Perform_Output_Debug_String_Trick())
                rt_modifier ^= mod_output_debug_string_trick_rt;
#endif
            if (current_canary1 != integrity_canary_value || current_canary2 != ~integrity_canary_value)
                return integrity_compromised_magic;

            return rt_modifier;
        }
    }
}