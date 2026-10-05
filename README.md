# Dralyxor

Compile-time string obfuscation for C++, with runtime reaction to debuggers and instrumentation. `Dralyxor::Obfuscated::String` keeps your literals out of the compiled binary and out of the data section: not in a `.rodata` entry `strings` can read, not as plaintext sitting in memory for longer than it has to be.

```cpp
#include <dralyxor/dralyxor.hxx>

auto api_key = DRALYXOR_OBFUSCATED("calasans_51H8xyz9secretApiKey0000000001");

const char* key = api_key.Decrypt(); // the literal never appears in cleartext in the binary

Use_Api_Key(key);

api_key.Encrypt(); // wipe it from memory as soon as you're done with it
```

## Why

A string literal baked into a binary (an API key, an internal URL, a signing secret) is as easy to read as running `strings` on the executable. Dralyxor encrypts each literal at compile time (the plaintext is never written to the object file, not even in a debug build) and decrypts it on demand at runtime, reacting to the presence of a debugger or similar instrumentation when it does: under a reliably-detected signal, `Decrypt()` silently returns corrupted content instead of the real value, rather than failing loudly.

See [Threat model](#threat-model-what-this-does-and-doesnt-protect-against) below for exactly what this protects against and what it doesn't.

## What you get

- **`DRALYXOR_OBFUSCATED(literal)`/`DRALYXOR_OBFUSCATED_SEEDED(literal, seed)`**: the portable entry point. Works identically on C++14 through C++23+, genuinely compile-time regardless of standard, compiler, or optimization level. (Constructing a `String` by hand from `Payload::Builder::Build` without going through the macro does *not* carry that guarantee on pre-C++20 toolchains: at least one mainstream compiler has been observed leaving the literal in plaintext in the compiled object at `-O0` when the macro isn't used. Use the macro.)
- **Direct construction via CTAD** (`Obfuscated::String s("literal");`) on a C++20-or-newer compiler with real `consteval` support, as a convenience, with identical runtime behavior and cost to the macro (measured, see [`benchmark/README.md`](benchmark/README.md)), just less portable.
- **Reacts to live debugging, not just static analysis.** `Decrypt()` doesn't throw or abort under a detected debugger; it returns corrupted content, and `Is_Content_Intact()`/`Last_Detection_Flags()` tell you afterward whether what you got back is trustworthy.
- **`Accessor::Guard`**: an RAII scoped view that decrypts the owner just long enough to copy it into its own, separately re-encrypted buffer, re-encrypts the owner immediately, and securely wipes its own copy when the scope ends.
- **Any 1/2/4/8-byte character type**: `char`, `wchar_t`, `char16_t`, `char32_t` all work the same way.

## Threat model: what this does and doesn't protect against

- **Static analysis**: the plaintext literal is never written to the compiled binary, including against tools that go beyond a plain `strings`/`objdump` pass and decode obfuscated strings through code emulation (such as `flare-floss`), across GCC and Clang at every optimization level from `-O0` to `-O3`.
- **A live debugger attached to the process**: a debugger attached via `ptrace` on Linux is detected, and the seed is poisoned before decryption completes. This holds even in a hostile scenario where a tool arms a real hardware breakpoint and detaches without clearing it first (unlike a well-behaved debugger, which clears it on detach): `Hardware_Breakpoints::Check()` still detects the orphaned breakpoint with no live tracer present at all.
- **What it does *not* protect against**: `Is_Content_Intact()` is tamper-*evidence* against accidental corruption and against the seed-poisoning this library triggers itself. It is not cryptographic authentication, and it should not be treated as proof against a deliberate attacker who already has read/write access to your process's memory. Likewise, a sufficiently skilled and patient reverse engineer, given enough time with a disassembler, can eventually reconstruct the decryption routine by hand: this is real, nontrivial work against a stripped binary, not a quick lookup, but it is not impossible either. Like any protection that is pure software with no secure hardware behind it, this raises the cost and the skill required to extract a secret; it does not make extraction impossible.
- **Not thread-safe for a shared instance.** Calling `Decrypt()`/`Encrypt()`/`Is_Content_Intact()` on the *same* `String` from different threads without external synchronization is a real data race. Give each thread its own instance (see `examples/one_instance_per_thread.cxx`) or protect shared access with a mutex yourself.

## Performance

See [`benchmark/README.md`](benchmark/README.md) for the methodology and the real, measured numbers. In short: the cipher itself is cheap and barely scales with the secret's length. Almost the entire cost of a `Decrypt()` call is the anti-debug scan that runs before it, every time, by design. On Linux specifically, most of that scan's cost is a single check that has to `fork()` a child process to read hardware debug registers; on Windows the equivalent check is much cheaper. Choosing the macro over direct `consteval` construction (or vice versa) costs nothing at runtime either way: that difference is compile-time only, and the benchmark confirms it rather than assuming it.

## Requirements

- A C++14-or-newer compiler. (Direct `consteval` construction needs C++20+; `DRALYXOR_OBFUSCATED` works identically on all of them.)
- CMake 3.25+, only to build `examples/`/`tests/`/`benchmark/`, or to consume Dralyxor via `find_package`. The library itself is just headers.

## Building

```sh
cmake -S . -B build
cmake --build build
ctest --test-dir build
```

| Option | Default | Effect |
|---|---|---|
| `DRALYXOR_BUILD_EXAMPLES` | `ON` | Build the programs under `examples/`. |
| `DRALYXOR_BUILD_TESTS` | `ON` | Build the test suite and register it with CTest; each test is compiled and run once per supported standard (C++14/17/20/23). |
| `DRALYXOR_BUILD_BENCHMARK` | `OFF` | Build the benchmark under `benchmark/` (not part of CTest, run manually). |

See [`benchmark/README.md`](benchmark/README.md) for how to run the benchmark and what it measures.

## Using it in your own CMake project

Vendored via `add_subdirectory` or `FetchContent`:

```cmake
add_subdirectory(dralyxor)
target_link_libraries(your_target PRIVATE Dralyxor::dralyxor)
```

Or after installing (`cmake --install build`):

```cmake
find_package(Dralyxor 1.0 REQUIRED)
target_link_libraries(your_target PRIVATE Dralyxor::dralyxor)
```

Both forms give you the same `Dralyxor::dralyxor` target, so switching between them later doesn't require changing anything else in your build.

## License

Copyright (©) 2026 **Calasans**

This software is licensed under the terms of the MIT License ("License"); you may use this software according to the conditions of the License. A copy of the License can be obtained at: [MIT License](https://opensource.org/licenses/MIT)

### Terms and Conditions of Use

#### 1. Granted Permissions

The present license grants, free of charge, to any person obtaining a copy of this software and associated documentation files, the following rights:
* To use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the software without restriction
* To permit persons to whom the software is furnished to do so, subject to the following conditions

#### 2. Mandatory Conditions

All copies or substantial portions of the software must include:
* The above copyright notice
* This permission notice
* The disclaimer notice below

#### 3. Copyright

The software and all associated documentation are protected by copyright laws. **Calasans** retains ownership of the original copyright of the software.

#### 4. Disclaimer of Warranties and Limitation of Liability

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

For detailed information about the MIT License, visit: https://opensource.org/licenses/MIT