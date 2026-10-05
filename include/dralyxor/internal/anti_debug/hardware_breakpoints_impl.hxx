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
#elif DRALYXOR_LINUX && DRALYXOR_USER_MODE
    #include <cerrno>
    #include <csignal>
    #include <cstddef>
    #include <cstdint>
    #include <sys/ptrace.h>
    #include <sys/user.h>
    #include <sys/wait.h>
    #include <unistd.h>
#endif

namespace Dralyxor {
    namespace Anti_Debug {
#if DRALYXOR_WINDOWS && DRALYXOR_USER_MODE
        DRALYXOR_NODISCARD inline Types::Detection_Flag Hardware_Breakpoints::Check() noexcept {
            CONTEXT thread_context {};

            thread_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

            if (!GetThreadContext(GetCurrentThread(), &thread_context))
                return Types::Detection_Flag::None;

            const bool any_breakpoint_address_set = thread_context.Dr0 != 0 || thread_context.Dr1 != 0 || thread_context.Dr2 != 0 || thread_context.Dr3 != 0;

            const bool dr7_set = thread_context.Dr7 != 0;

            return (any_breakpoint_address_set || dr7_set) ? Types::Detection_Flag::Hardware_Breakpoint : Types::Detection_Flag::None;
        }
#elif DRALYXOR_LINUX && DRALYXOR_USER_MODE
        namespace Internal {
            DRALYXOR_NODISCARD inline bool Wait_For_Child_With_Timeout(pid_t child_pid, int& exit_status) noexcept {
                constexpr std::uint64_t TOTAL_BUDGET_US = 50000;
                constexpr useconds_t INITIAL_POLL_INTERVAL_US = 20;
                constexpr useconds_t MAX_POLL_INTERVAL_US = 2000;

                std::uint64_t elapsed_us = 0;
                useconds_t poll_interval_us = INITIAL_POLL_INTERVAL_US;

                while (elapsed_us < TOTAL_BUDGET_US) {
                    const pid_t wait_result = waitpid(child_pid, &exit_status, WNOHANG);

                    if (wait_result == child_pid)
                        return true;

                    if (wait_result < 0 && errno != EINTR)
                        return false;

                    usleep(poll_interval_us);

                    elapsed_us += poll_interval_us;
                    poll_interval_us = (poll_interval_us < MAX_POLL_INTERVAL_US / 2) ? (poll_interval_us * 2) : MAX_POLL_INTERVAL_US;
                }

                kill(child_pid, SIGKILL);
                waitpid(child_pid, &exit_status, 0);

                return false;
            }

            inline bool Child_Reports_Debug_Register_Set(pid_t parent_pid) noexcept {
                const pid_t child_pid = fork();

                if (child_pid < 0)
                    return false;

                if (child_pid == 0) {
                    if (ptrace(PTRACE_ATTACH, parent_pid, nullptr, nullptr) != 0)
                        _exit(2);

                    int wait_status = 0;

                    waitpid(parent_pid, &wait_status, 0);

                    const long dr7_value = ptrace(PTRACE_PEEKUSER, parent_pid, reinterpret_cast<void*>(offsetof(struct user, u_debugreg[7])), nullptr);

                    ptrace(PTRACE_DETACH, parent_pid, nullptr, nullptr);
                    _exit(dr7_value != 0 ? 1 : 0);
                }

                int child_exit_status = 0;

                if (!Wait_For_Child_With_Timeout(child_pid, child_exit_status))
                    return false;

                return WIFEXITED(child_exit_status) && WEXITSTATUS(child_exit_status) == 1;
            }
        }

        DRALYXOR_NODISCARD inline Types::Detection_Flag Hardware_Breakpoints::Check() noexcept {
            return Internal::Child_Reports_Debug_Register_Set(getpid()) ? Types::Detection_Flag::Hardware_Breakpoint : Types::Detection_Flag::None;
        }
#else
        DRALYXOR_NODISCARD inline Types::Detection_Flag Hardware_Breakpoints::Check() noexcept {
            return Types::Detection_Flag::None;
        }
#endif
    }
}