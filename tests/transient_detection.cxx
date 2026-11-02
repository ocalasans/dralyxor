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


// A debugger that shows up and later goes away must not cost the caller the secret:
//  - content decrypted while a debugger is present is corrupted on purpose, but Encrypt() has to
//      invert exactly what Decrypt() applied, so the original comes back once the debugger is gone;
//  - a debugger attached AFTER a successful Decrypt() must be noticed by the next Decrypt() call
//      instead of being served the cached plaintext.
//
// A real debugger is needed to exercise this honestly:
//  - Linux: a helper process attaches to this one with ptrace (PTRACE_SEIZE) and detaches again.
//      If the environment forbids ptrace (some containers/CI sandboxes), the test is skipped.
//  - Windows: PEB->BeingDebugged is toggled in this process; it is the very field IsDebuggerPresent()
//      and the library's own PEB check read, so it drives the real detection path.
//  - Other platforms: skipped, there is no detection to exercise.

#include <cstdio>
#include <cstring>
//
#include <dralyxor/dralyxor.hxx>
//
#include "check.hxx"

#if defined(_WIN32)
    #define WIN32_LEAN_AND_MEAN

    #include <windows.h>
    #include <winternl.h>

    #define DRALYXOR_TEST_HAS_DEBUGGER_SIMULATION 1

    #if DRALYXOR_GCC
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Warray-bounds"
    #endif

class Debugger_Simulation {
    public:
        bool Attach() {
            return (NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged = 1, true);
        }

        void Detach() {
            NtCurrentTeb()->ProcessEnvironmentBlock->BeingDebugged = 0;
        }
};

    #if DRALYXOR_GCC
        #pragma GCC diagnostic pop
    #endif
#elif defined(__linux__)
    #include <cerrno>
    #include <cstdlib>
    //
    #include <fcntl.h>
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <unistd.h>

    #define DRALYXOR_TEST_HAS_DEBUGGER_SIMULATION 1

class Debugger_Simulation {
    public:
        // returns false when this environment does not let a helper process trace us
        bool Attach() {
            int command_pipe[2] = {};

            if (pipe(command_pipe) != 0)
                return false;

            const pid_t target_process_id = getpid();
            const pid_t helper_process_id = fork();

            if (helper_process_id < 0)
                return false;

            if (helper_process_id == 0) {
                close(command_pipe[1]);
                fcntl(command_pipe[0], F_SETFL, O_NONBLOCK);

                alarm(30); // never outlive a stuck test

                if (ptrace(PTRACE_SEIZE, target_process_id, nullptr, nullptr) != 0)
                    _exit(10);

                for (;;) {
                    int wait_status = 0;

                    if (waitpid(target_process_id, &wait_status, __WALL | WNOHANG) == target_process_id) {
                        if (WIFEXITED(wait_status) || WIFSIGNALED(wait_status))
                            _exit(0);

                        if (WIFSTOPPED(wait_status)) {
                            const int stop_signal = WSTOPSIG(wait_status);
                            const bool is_event_stop = (wait_status >> 16) != 0;

                            ptrace(PTRACE_CONT, target_process_id, nullptr, reinterpret_cast<void*>(static_cast<long>((!is_event_stop && stop_signal != SIGTRAP) ? stop_signal : 0)));
                        }
                    }

                    char command = 0;

                    if (read(command_pipe[0], &command, 1) == 1) {
                        int interrupt_status = 0;

                        ptrace(PTRACE_INTERRUPT, target_process_id, nullptr, nullptr);
                        waitpid(target_process_id, &interrupt_status, __WALL);
                        ptrace(PTRACE_DETACH, target_process_id, nullptr, nullptr);

                        _exit(0);
                    }

                    usleep(200);
                }
            }

            close(command_pipe[0]);

            _command_pipe_write_end = command_pipe[1];
            _helper_process_id = helper_process_id;

            if (!Wait_For_Tracer_State(true))
                return (Detach(), false);

            return true;
        }

        void Detach() {
            if (_helper_process_id <= 0)
                return;

            const char command = 'x';

            if (write(_command_pipe_write_end, &command, 1) != 1)
                std::abort();

            close(_command_pipe_write_end);

            int wait_status = 0;

            waitpid(_helper_process_id, &wait_status, 0);

            _helper_process_id = -1;

            DRALYXOR_CHECK(Wait_For_Tracer_State(false));
        }

    private:
        static int Read_Tracer_Pid() {
            const int descriptor = open("/proc/self/status", O_RDONLY);

            if (descriptor < 0)
                return -1;

            char buffer[4096] = {};
            const ssize_t bytes_read = read(descriptor, buffer, sizeof(buffer) - 1);

            close(descriptor);

            const char* marker = bytes_read > 0 ? std::strstr(buffer, "TracerPid:") : nullptr;

            return marker != nullptr ? std::atoi(marker + 10) : -1;
        }

        static bool Wait_For_Tracer_State(bool expect_attached) {
            for (int waited_milliseconds = 0; waited_milliseconds < 3000; ++waited_milliseconds) {
                if ((Read_Tracer_Pid() > 0) == expect_attached)
                    return true;

                usleep(1000);
            }

            return false;
        }

        pid_t _helper_process_id = -1;
        int _command_pipe_write_end = -1;
};
#endif

#if defined(DRALYXOR_TEST_HAS_DEBUGGER_SIMULATION)

static const char* const SECRET = "the secret must survive a transient debugger";

// returns false (test skipped) when no debugger can be attached in this environment
bool Test_Secret_Survives_A_Debugger_That_Comes_And_Goes() {
    auto text = DRALYXOR_OBFUSCATED("the secret must survive a transient debugger");
    Debugger_Simulation debugger;

    if (!debugger.Attach())
        return false;

    const char* under_debugger = text.Decrypt();

    DRALYXOR_CHECK(std::strcmp(under_debugger, SECRET) != 0);
    DRALYXOR_CHECK(!text.Is_Content_Intact());
    DRALYXOR_CHECK(text.Last_Detection_Flags() != Dralyxor::Detection_Flag::None);

    text.Encrypt();

    debugger.Detach();

    DRALYXOR_CHECK(std::strcmp(text.Decrypt(), SECRET) == 0);
    DRALYXOR_CHECK(text.Is_Content_Intact());

    std::printf("Test_Secret_Survives_A_Debugger_That_Comes_And_Goes OK\n");

    return true;
}

bool Test_Debugger_Attached_After_First_Decrypt_Is_Noticed() {
    auto text = DRALYXOR_OBFUSCATED("the secret must survive a transient debugger");
    Debugger_Simulation debugger;

    DRALYXOR_CHECK(std::strcmp(text.Decrypt(), SECRET) == 0); // no debugger yet, content is cached from here on

    if (!debugger.Attach())
        return false;

    const char* with_debugger = text.Decrypt(); // no Encrypt() in between: this used to return the cached plaintext

    DRALYXOR_CHECK(std::strcmp(with_debugger, SECRET) != 0);
    DRALYXOR_CHECK(text.Last_Detection_Flags() != Dralyxor::Detection_Flag::None);

    debugger.Detach();

    DRALYXOR_CHECK(std::strcmp(text.Decrypt(), SECRET) == 0); // and nothing was lost along the way
    DRALYXOR_CHECK(text.Is_Content_Intact());

    std::printf("Test_Debugger_Attached_After_First_Decrypt_Is_Noticed OK\n");

    return true;
}

int main() {
    const bool first_ran = Test_Secret_Survives_A_Debugger_That_Comes_And_Goes();
    const bool second_ran = Test_Debugger_Attached_After_First_Decrypt_Is_Noticed();

    if (!first_ran || !second_ran)
        std::printf("transient_detection SKIPPED: this environment does not allow attaching a debugger (ptrace)\n");
    else
        std::printf("All transient_detection tests passed\n");

    return 0;
}
#else
int main() {
    std::printf("transient_detection SKIPPED: no debugger detection on this platform\n");

    return 0;
}
#endif