# Dralyxor

**Dralyxor** is a modern, `header-only`, high-performance, and multi-layered **C++** library designed for compile-time string obfuscation and robust runtime protection. Its fundamental mission is to shield your application's intrinsic secrets—such as API keys, passwords, internal URLs, debug messages, and any sensitive string literal—against exposure through static analysis, reverse engineering, and dynamic memory inspection. By encrypting and transforming strings at compile-time and securely managing their access at runtime, **Dralyxor** ensures that no critical string literal exists as plain text in your final binary or remains unprotected in memory for longer than strictly necessary.

Built upon the foundations of modern **C++** (requiring **C++14** and intelligently adapting to **C++17** and **C++20** features), its advanced architecture features a sophisticated transformation engine based on "micro-programs," obfuscation of the transformation program itself, data integrity mechanisms, anti-debugging defenses, and a **RAII-based Secure Scope Accessor** for "just-in-time" decryption and automatic re-obfuscation. This drastically minimizes data exposure in **RAM** and provides professional-level defense-in-depth.

## Languages

- Português: [README](../../)
- Deutsch: [README](../Deutsch/README.md)
- Español: [README](../Espanol/README.md)
- Français: [README](../Francais/README.md)
- Italiano: [README](../Italiano/README.md)
- Polski: [README](../Polski/README.md)
- Русский: [README](../Русский/README.md)
- Svenska: [README](../Svenska/README.md)
- Türkçe: [README](../Turkce/README.md)

## Table of Contents

- [Dralyxor](#dralyxor)
  - [Languages](#languages)
  - [Table of Contents](#table-of-contents)
  - [Quick Integration and Usage Guide](#quick-integration-and-usage-guide)
    - [Installation](#installation)
    - [Compiler Requirements](#compiler-requirements)
    - [Essential Usage Patterns](#essential-usage-patterns)
      - [Pattern 1: Local (Stack) Obfuscation](#pattern-1-local-stack-obfuscation)
      - [Pattern 2: Static (Global) Obfuscation](#pattern-2-static-global-obfuscation)
      - [Pattern 3: Obfuscation with a User-Provided Key](#pattern-3-obfuscation-with-a-user-provided-key)
    - [Error Handling and Integrity](#error-handling-and-integrity)
  - [Detailed Design Philosophy and Architecture](#detailed-design-philosophy-and-architecture)
    - [The Persistent Threat: Vulnerability of Literal Strings](#the-persistent-threat-vulnerability-of-literal-strings)
    - [Dralyxor's Multilayered Architectural Solution](#dralyxors-multilayered-architectural-solution)
  - [In-Depth Analysis of Architectural Components](#in-depth-analysis-of-architectural-components)
    - [Component 1: The Micro-Program Transformation Engine](#component-1-the-micro-program-transformation-engine)
      - [The Power of `consteval` and `constexpr` for Compile-Time Generation](#the-power-of-consteval-and-constexpr-for-compile-time-generation)
      - [Anatomy of a **Dralyxor** Micro-Program](#anatomy-of-a-dralyxor-micro-program)
        - [Randomized Instruction Generation and Applier Selection](#randomized-instruction-generation-and-applier-selection)
        - [Variable and Logical NOPs for Entropy](#variable-and-logical-nops-for-entropy)
      - [Obfuscation of the Micro-Program Itself](#obfuscation-of-the-micro-program-itself)
      - [The Static Obfuscation Lifecycle](#the-static-obfuscation-lifecycle)
    - [Component 2: Secure Access and Minimizing **RAM** Exposure](#component-2-secure-access-and-minimizing-ram-exposure)
      - [The `Secure_Accessor` and the RAII Principle](#the-secure_accessor-and-the-raii-principle)
      - [Memory Fragmentation in the `Secure_Accessor`](#memory-fragmentation-in-the-secure_accessor)
      - [Secure Memory Clearing](#secure-memory-clearing)
    - [Component 3: Runtime Defenses (Anti-Debugging and Anti-Tampering)](#component-3-runtime-defenses-anti-debugging-and-anti-tampering)
      - [Multi-Platform Debugger Detection](#multi-platform-debugger-detection)
      - [Impact on Operation in Case of Detection or Integrity Violation](#impact-on-operation-in-case-of-detection-or-integrity-violation)
      - [Object Integrity Canaries](#object-integrity-canaries)
      - [String Content Checksum](#string-content-checksum)
    - [Component 4: Generation of Unique and Unpredictable Keys and Seeds](#component-4-generation-of-unique-and-unpredictable-keys-and-seeds)
      - [Sources of Entropy for the `compile_time_seed`](#sources-of-entropy-for-the-compile_time_seed)
      - [Derived Seeds for Content Transformations](#derived-seeds-for-content-transformations)
      - [Immunity Against "Replay" Attacks and Pattern Analysis](#immunity-against-replay-attacks-and-pattern-analysis)
  - [Complete Public API Reference](#complete-public-api-reference)
    - [Obfuscation Macros](#obfuscation-macros)
      - [`DRALYXOR(str_literal)`](#dralyxorstr_literal)
      - [`DRALYXOR_LOCAL(str_literal)`](#dralyxor_localstr_literal)
      - [`DRALYXOR_KEY(str_literal, key_literal)`](#dralyxor_keystr_literal-key_literal)
      - [`DRALYXOR_KEY_LOCAL(str_literal, key_literal)`](#dralyxor_key_localstr_literal-key_literal)
    - [Secure Access Macro](#secure-access-macro)
      - [`DRALYXOR_SECURE(obfuscated_var)`](#dralyxor_secureobfuscated_var)
  - [Advanced Features and Best Practices](#advanced-features-and-best-practices)
    - [Full Unicode Support (Wide Strings - `wchar_t`)](#full-unicode-support-wide-strings---wchar_t)
    - [Intelligent Adaptation to C++ Standards and Environments (Kernel Mode)](#intelligent-adaptation-to-c-standards-and-environments-kernel-mode)
    - [Performance Considerations and Overhead](#performance-considerations-and-overhead)
    - [Integration into a Layered Security Strategy](#integration-into-a-layered-security-strategy)
  - [License](#license)
    - [Conditions:](#conditions)

## Quick Integration and Usage Guide

### Installation

**Dralyxor** is a **header-only** library. No prior compilation or linking of libraries (`.lib`/`.a`) is necessary.

1. **Copy the `Dralyxor` Directory:** Get the latest version of the library (clone the repository or download the zip) and copy the entire `Dralyxor` directory (containing all `.hpp` files) to a location accessible by your project (e.g., a `libs/`, `libraries/`, or `vendor/` folder).
2. **Include the Main Header:** In your source code, include the main header `dralyxor.hpp`:
   ```cpp
   #include "path/to/Dralyxor/dralyxor.hpp"
   ```

A typical project structure:
```
/MyProject/
|-- src/
|   |-- main.cpp
|   `-- utils.cpp
`-- libraries/
    `-- Dralyxor/ <-- Dralyxor here
        |-- dralyxor.hpp            (Main entry point)
        |-- obfuscated_string.hpp   (Obfuscated_String Class)
        |-- secure_accessor.hpp     (Secure_Accessor Class)
        |-- algorithms.hpp          (Transformation engine and micro-programs)
        |-- anti_debug.hpp          (Runtime detections)
        |-- prng.hpp                (Compile-time pseudo-random number generator)
        |-- integrity_constants.hpp (Constants for integrity checks)
        |-- secure_memory.hpp       (Secure memory clearing)
        |-- detection.hpp           (Compiler/C++ standard detection macros)
        `-- env_traits.hpp          (Type_traits adaptations for restricted environments)
```

### Compiler Requirements

> [!IMPORTANT]
> **Dralyxor** was designed with a focus on modern **C++** for maximum security and compile-time efficiency.
>
> - **Minimum C++ Standard: C++14**. The library uses features like generalized `constexpr` and adapts for `if constexpr` (when available via `_DRALYXOR_IF_CONSTEXPR`).
> - **Adaptation to Higher Standards:** Detects and uses optimizations or syntaxes from **C++17** and **C++20** (like `consteval`, `_v` suffixes for `type_traits`) if the project is compiled with these standards. `_DRALYXOR_CONSTEVAL` maps to `consteval` in C++20 and `constexpr` in C++14/17, ensuring compile-time execution where possible.
> - **Supported Compilers:** Primarily tested with recent versions of MSVC, GCC, and Clang.
> - **Execution Environment:** Fully compatible with **User Mode** applications and **Kernel Mode** environments (e.g., Windows drivers). In Kernel Mode, where the STL may not be available, **Dralyxor** uses internal implementations for necessary `type traits` (see `env_traits.hpp`).

### Essential Usage Patterns

#### Pattern 1: Local (Stack) Obfuscation

Ideal for temporary strings confined to a function's scope. The memory is automatically managed and cleared.

```cpp
#include "Dralyxor/dralyxor.hpp" // Adjust the path as needed
#include <iostream>

void Configure_Logging() {
    // Log formatting key, used only locally.
    auto log_format_key = DRALYXOR_LOCAL("Timestamp={ts}, Level={lvl}, Msg={msg}");

    // Secure access within a limited scope
    {
        // The Secure_Accessor temporarily deobfuscates 'log_format_key' during its construction
        // (and re-obfuscates 'log_format_key' immediately after copying it to its internal buffers),
        // allows access, and clears its own buffers upon destruction.
        auto accessor = DRALYXOR_SECURE(log_format_key);

        if (accessor.Get()) { // Always check if Get() does not return nullptr
            std::cout << "Using log format: " << accessor.Get() << std::endl;
            // Ex: logger.SetFormat(accessor.Get());
        }
        else
            std::cerr << "Failed to decrypt log_format_key (possible tampering or debugger detection?)" << std::endl;
    } // accessor is destroyed, its internal buffers are cleared. log_format_key remains obfuscated.
      // log_format_key will be destroyed at the end of the Configure_Logging function.
}
```

#### Pattern 2: Static (Global) Obfuscation

For constants that need to persist throughout the program's lifetime and be accessed globally.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>
#include <vector>
#include <iostream> // For the example

// License API URL, a persistent secret.
// The DRALYXOR() macro creates a static object.
// The Get_License_Server_URL() function returns a reference to this static object.
static auto& Get_License_Server_URL() {
    static auto& license_url = DRALYXOR("https://auth.mysoft.com/api/v1/licenses");

    return license_url;
}

bool Verify_License(const std::string& user_key) {
    auto& url_obj_ref = Get_License_Server_URL(); // url_obj_ref is a reference to the static Obfuscated_String.
    bool success = false;
    {
        auto accessor = DRALYXOR_SECURE(url_obj_ref); // Creates a Secure_Accessor for url_obj_ref.

        if (accessor.Get()) {
            std::cout << "Contacting license server at: " << accessor.Get() << std::endl;
            // Ex: success = http_client.Check(accessor.Get(), user_key);
            success = true; // Simulating success for the example
        }
        else
            std::cerr << "Failed to decrypt license server URL (possible tampering or debugger detection?)." << std::endl;
    } // accessor is destroyed, its buffers are cleared. url_obj_ref (the original Obfuscated_String) remains obfuscated.

    return success;
}
```

#### Pattern 3: Obfuscation with a User-Provided Key

For the maximum level of security, you can provide your own secret key string. This makes the obfuscation dependent on a secret that only you know, making it resilient.

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <string>

// The key should never be in plaintext in production code,
// ideally it should come from a build script, environment variable, etc.
#define MY_SUPER_SECRET_KEY "b1d03c4f-a20c-4573-8a39-29c32f3c3a4d"

void Send_Data_To_Secure_Endpoint() {
    // Obfuscates a URL using the secret key. The macro ends with _KEY.
    auto secure_endpoint = DRALYXOR_KEY_LOCAL("https://internal.api.mycompany.com/report", MY_SUPER_SECRET_KEY);

    // Usage with Secure_Accessor remains the same.
    {
        auto accessor = DRALYXOR_SECURE(secure_endpoint);

        if (accessor.Get())
            // httpClient.Post(accessor.Get(), ...);
    }
}
```

### Error Handling and Integrity

The `Obfuscated_String::Decrypt()` and `Encrypt()` functions return a `uint64_t`:
- `0` indicates success.
- `Dralyxor::Detail::integrity_compromised_magic` (a constant value defined in `integrity_constants.hpp`) indicates that an integrity check has failed. This could be due to corrupted object canaries, an inconsistent content checksum, or the detection of a debugger signaling a hostile environment.

Similarly, `Secure_Accessor::Get()` (or its implicit conversion to `const CharT*`) will return `nullptr` if the `Secure_Accessor` fails to initialize (for example, if the original `Obfuscated_String` fails to decrypt) or if the integrity of the `Secure_Accessor` (its own canaries or internal checksums) is compromised during its lifetime.

**It is crucial that your code checks these returns to ensure the application's robustness and security.**

```cpp
#include "Dralyxor/dralyxor.hpp"
#include <iostream>

void Example_Error_Handling() {
    auto my_secret = DRALYXOR_LOCAL("Important Data!");

    // You generally would NOT call Decrypt() and Encrypt() directly,
    // as Secure_Accessor manages this. But if you need to for some reason:
    if (my_secret.Decrypt() != 0) {
        std::cerr << "WARNING: Failed to decrypt 'my_secret' or integrity compromised during Decrypt()!" << std::endl;
        // Take appropriate action: terminate, log securely, etc.
        // The my_secret.storage_ object might be in an invalid or garbage state.
        return; // Avoid using my_secret if Decrypt() fails.
    }

    // If Decrypt() was successful, my_secret.storage_ contains the decrypted data.
    // **DIRECT ACCESS TO storage_ IS STRONGLY DISCOURAGED IN PRODUCTION.**
    // std::cout << "Data in my_secret.storage_ (DO NOT DO THIS): " << my_secret.storage_ << std::endl;

    // It is your responsibility to re-encrypt if you have manually called Decrypt():
    if (my_secret.Encrypt() != 0) {
        std::cerr << "WARNING: Failed to re-encrypt 'my_secret' or integrity compromised during Encrypt()!" << std::endl;
        // Uncertain state, potentially dangerous.
    }

    // RECOMMENDED USAGE with Secure_Accessor:
    auto another_secret = DRALYXOR_LOCAL("Another Piece of Data!");
    {
        // The Secure_Accessor's constructor calls another_secret.Decrypt(), copies the data, and then another_secret.Encrypt().
        auto accessor = DRALYXOR_SECURE(another_secret);
        const char* data_ptr = accessor.Get(); // Or: const char* data_ptr = accessor;

        if (data_ptr) {
            std::cout << "Secret data via Secure_Accessor: " << data_ptr << std::endl;
            // Use data_ptr here
        }
        else {
            std::cerr << "WARNING: Secure_Accessor failed to initialize or get pointer for 'another_secret'!" << std::endl;
            // This indicates that Decrypt() inside the accessor's constructor failed,
            // or there was tampering on the accessor (canaries, internal checksums).
        }
    } // accessor is destroyed. Its buffers are cleared. another_secret remains obfuscated.
}
```

## Detailed Design Philosophy and Architecture

**Dralyxor** is not merely a XOR cipher; it's a defense-in-depth system for literal strings. Its architecture is founded on the premise that effective security requires multiple interconnected layers and resilience against various analysis techniques.

### The Persistent Threat: Vulnerability of Literal Strings

Literal strings, like `"api.example.com/data?key="`, when embedded directly in code, are written legibly (plain text) into the compiled binary. Tools like `strings`, disassemblers (IDA Pro, Ghidra), and hex editors can extract them trivially. This exposure facilitates:
- **Reverse Engineering:** Understanding the program's internal logic and flow.
- **Endpoint Identification:** Discovery of backend servers and APIs.
- **Secret Extraction:** API keys, embedded passwords, private URLs, SQL queries, etc.
- **Dynamic Memory Analysis:** Even if a program decrypts a string for use, if it remains in plain text in **RAM** for too long, an attacker with access to the process's memory (via debugger or memory dump) can find it.

**Dralyxor** attacks these vulnerabilities both at compile-time (for the binary on disk) and at runtime (for **RAM** memory).

### Dralyxor's Multilayered Architectural Solution

The robustness of **Dralyxor** stems from the synergy of its key components:

| Architectural Component                   | Primary Objective                                                                          | Key Technologies/Techniques Employed                                                                                                                              |
| :---------------------------------------- | :----------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Micro-Program Transformation Engine**   | Eliminate plain text strings from the binary; create complex, dynamic, and non-trivial obfuscation. | `_DRALYXOR_CONSTEVAL` (`consteval`/`constexpr`), PRNG, multiple operations (XOR, ADD, ROT, etc.), variable and logical NOPs, variable applier styles.         |
| **Secure Access and Exposure Minimization** | Drastically reduce the time a secret remains decrypted in RAM.                              | RAII Pattern (`Secure_Accessor`), memory fragmentation, secure buffer wiping (`Secure_Clear_Memory`, `RtlSecureZeroMemory`).                                  |
| **Runtime Defenses**                      | Detect and react to hostile analysis environments and memory tampering.                    | Debugger Detection (OS-specific APIs, timing, OutputDebugString), object integrity canaries, string content checksum.                                              |
| **Unique Key and Seed Generation**        | Ensure each obfuscated string and usage instance are cryptographically distinct.               | `__DATE__`, `__TIME__`, `__COUNTER__`, string length, FNV-1a hashing for `compile_time_seed`, derived seeds for operand modifiers and selectors.            |

## In-Depth Analysis of Architectural Components

### Component 1: The Micro-Program Transformation Engine

The heart of **Dralyxor's** static and dynamic obfuscation lies in its transformation engine that uses unique "micro-programs" for each string and context.

#### The Power of `consteval` and `constexpr` for Compile-Time Generation

Modern **C++**, with `consteval` (**C++20**) and `constexpr` (**C++11** onwards), allows complex code to be executed *during compilation*. **Dralyxor** uses `_DRALYXOR_CONSTEVAL` (which maps to `consteval` or `constexpr` depending on the **C++** standard) for the `Obfuscated_String` constructor and for the micro-program generation.

This means that the entire process of:
1. Generating a pseudo-random sequence of transformation instructions (the micro-program).
2. Obfuscating the micro-program itself for storage.
3. Applying this micro-program (in a temporarily de-obfuscated form) to transform the original string, resulting in its obfuscated form.
All of this happens at compile-time, before the binary is even generated.

#### Anatomy of a **Dralyxor** Micro-Program

Each `Obfuscated_String` object stores a small array of `Dralyxor::Detail::Micro_Instruction`. A `Micro_Instruction` is a simple struct defined in `algorithms.hpp`:
```cpp
// In Dralyxor::Detail (algorithms.hpp)
enum class Micro_Operation_Code : uint8_t {
    NOP,
    XOR,
    ADD,
    SUB,
    ROTR,
    ROTL,
    SWAP_NIB,
    END_OF_PROGRAM
};

struct Micro_Instruction {
    Micro_Operation_Code op_code{}; // Default initializer {} to zero-out
    uint8_t operand{};             // Default initializer {} to zero-out
};

// Maximum number of instructions a micro-program can contain.
static constexpr size_t max_micro_instructions = 8;
```
The function `_DRALYXOR_CONSTEVAL void Obfuscated_String::Generate_Micro_Program_Instructions(uint64_t prng_seed)` is responsible for filling this array.

##### Randomized Instruction Generation and Applier Selection

- **Instruction Generation:** Using a `Dralyxor::Detail::Constexpr_PRNG` (seeded with a combination of the `compile_time_seed` and `0xDEADBEEFC0FFEEULL`), the `Generate_Micro_Program_Instructions` function probabilistically chooses a sequence of operations:
   - `XOR`: Bitwise XOR with the operand.
   - `ADD`: Modular addition with the operand.
   - `SUB`: Modular subtraction with the operand.
   - `ROTR`/`ROTL`: Bit rotation. The operand (after a modulo operation) defines the number of shifts (1 to 7).
   - `SWAP_NIB`: Swaps the lower 4 bits with the upper 4 bits of a byte (operand is ignored).
    The operands for these instructions are also pseudo-randomly generated by the PRNG.

- **Operand Modification and Applier Selection at Transformation Time:** During the application of the micro-program (by `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`), both during initial obfuscation and runtime de-obfuscation:
   - A `Constexpr_PRNG prng_operand_modifier` (seeded with `base_seed`) generates a `prng_key_for_ops_in_elem` for each character of the string. The micro-instruction's operand (`instr_orig.operand`) is XORed with this key before being used. This ensures that the same micro-program applies slightly different transformations to each character.
   - A `Constexpr_PRNG prng_applier_selector` (seeded with `base_seed ^ 0xAAAAAAAAAAAAAAAAULL`) chooses a `Byte_Transform_Applier` for each character. There are currently two styles:
      - `Applier_Style_Direct`: Applies the operation directly (inverting it for decryption, like ADD becomes SUB).
      - `Applier_Style_DoubleLayer`: Applies the operation twice (or the operation and its inverse, depending on the encryption/decryption mode) with different operands, making the reversal slightly more complex to analyze.

##### Variable and Logical NOPs for Entropy

To increase the difficulty of manual analysis of the micro-program, **Dralyxor** inserts:
- **Explicit NOPs:** `Micro_Operation_Code::NOP` instructions that do nothing.
- **Logical NOPs:** Pairs of instructions that cancel each other out, such as `ADD K` followed by `SUB K`, or `ROTL N_BITS` followed by `ROTR N_BITS`. The operand used in the pair is the same.

These NOPs are inserted probabilistically by `Generate_Micro_Program_Instructions`, filling the `micro_program_` array and making it harder to discern effective transformations from "noise" operations.

#### Obfuscation of the Micro-Program Itself

After the micro-program is generated and before the initial string obfuscation in the `consteval` constructor, the `micro_program_` array (contained within the `Obfuscated_String` object) is itself obfuscated. Each `op_code` and `operand` in every `Micro_Instruction` is XORed with a key derived from the `compile_time_seed` (using `Detail::Get_Micro_Program_Obfuscation_Key` and `Detail::Obfuscate_Deobfuscate_Instruction`).
This means that even if an attacker manages to dump the memory of the `Obfuscated_String` object, the micro-program will not be in its directly readable/applicable form.

When `Obfuscated_String::Decrypt()` or `Encrypt()` are called (or indirectly by the `Secure_Accessor`), the central `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent` function receives this *obfuscated* micro-program. It then:
1. Creates a temporary copy of the micro-program (`local_plain_program`) on the stack.
2. It de-obfuscates this local copy using the same key (`program_obf_key`) derived from the passed base seed (which is ultimately the `compile_time_seed`).
3. It uses this `local_plain_program` to transform the string data.
The local copy on the stack is destroyed at the end of the function, and the stored `micro_program_` in the `Obfuscated_String` object remains obfuscated.

#### The Static Obfuscation Lifecycle

1. **Source Code:** `auto api_key_obj = DRALYXOR_LOCAL("SECRET_API_KEY");`
2. **Preprocessing:** The macro expands into a `Dralyxor::Obfuscated_String<char, 15, __COUNTER__>("SECRET_API_KEY");` instantiation. (The size 15 includes the null terminator).
3. **`_DRALYXOR_CONSTEVAL` Evaluation:**
   - The compiler executes the `Obfuscated_String` constructor.
   - `Initialize_Internal_Canaries()` sets the integrity canaries.
   - `Generate_Micro_Program_Instructions()` (seeded with `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`) creates a sequence of `Micro_Instruction` and stores it in `this->micro_program_` (e.g., `[ADD 0x12, XOR 0xAB, NOP, ROTL 3, ...]`). The actual number of instructions is stored in `num_actual_instructions_in_program_`.
   - The original string "SECRET\_API\_KEY" is copied into `this->storage_`.
   - A checksum of the original string "SECRET\_API\_KEY" (excluding the null) is calculated by `Detail::Calculate_String_Content_Checksum` and then obfuscated by `Detail::Obfuscate_Deobfuscate_Short_Value` (using `compile_time_seed` and `content_checksum_obf_salt`) and stored in `this->_content_checksum_obfuscated`.
   - `Obfuscate_Internal_Micro_Program()` is called: `this->micro_program_` is obfuscated in-place (each instruction XORed with `Detail::Get_Micro_Program_Obfuscation_Key(compile_time_seed)`).
   - `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, this->micro_program_, num_actual_instructions_in_program_, compile_time_seed, false)` is called. This function:
      - Creates a de-obfuscated copy of `this->micro_program_` on the stack.
      - For each character in `storage_` (except the null):
         - Generates `prng_key_for_ops_in_elem` and selects a `Byte_Transform_Applier`.
         - Applies the sequence of micro-instructions (from the de-obfuscated copy) to the character, using the applier and the modified operand.
      - At the end, `storage_` contains the obfuscated string (e.g., `[CF, 3A, D1, ..., 0x00]`).
4. **Code Generation:** The compiler allocates space for `api_key_obj` and initializes it directly with:
   - `storage_`: `[CF, 3A, D1, ..., 0x00]` (obfuscated string).
   - `micro_program_`: The *already obfuscated* micro-program.
   - `_content_checksum_obfuscated`: The original content checksum, *obfuscated*.
   - `_internal_integrity_canary1/2`, `decrypted_`, `moved_from_`, `num_actual_instructions_in_program_`.
    The literal `"SECRET_API_KEY"` no longer exists in the binary.

### Component 2: Secure Access and Minimizing **RAM** Exposure

#### The `Secure_Accessor` and the RAII Principle

Compile-time protection is only half the battle. Once the string needs to be used, it must be decrypted. If this decrypted string remains in **RAM** for a prolonged period, it becomes a target for dynamic analysis (memory dumps, debuggers).

**Dralyxor** addresses this with `Dralyxor::Secure_Accessor`, a class that implements the **RAII** (Resource Acquisition Is Initialization) pattern:
- **Acquired Resource:** Temporary access to the plaintext string, fragmented and managed by the accessor.
- **Managing Object:** The `Secure_Accessor` instance.

```cpp
// In secure_accessor.hpp (Dralyxor::Secure_Accessor)
// ...
public:
    explicit Secure_Accessor(Obfuscated_String_Type& obfuscated_string_ref) : parent_ref_(obfuscated_string_ref), current_access_ptr_(nullptr), initialization_done_successfully_(false), fragments_data_checksum_expected_(0), 
        fragments_data_checksum_reconstructed_(1) // Initialize differently to fail if not updated
    {
        Initialize_Internal_Accessor_Canaries();

        if (!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0; // Invalidates the accessor

            return;
        }

        // 1. Attempts to decrypt the original Obfuscated_String.
        if (parent_ref_.Decrypt() == Detail::integrity_compromised_magic) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        // 2. If decryption is successful, copies the plaintext string to the internal fragments.
        if constexpr (N_storage > 0) {
            const CharT* plain_text_source = parent_ref_.storage_; // storage_ is now in plaintext
            size_t source_idx = 0;

            for (size_t i = 0; i < fragment_count_val; ++i) { // fragment_count_val is at most 4
                size_t base_chars_in_frag = N_storage / fragment_count_val;
                size_t chars_for_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);
                
                for (size_t j = 0; j < fragment_buffer_size; ++j) {
                    if (j < chars_for_this_fragment && source_idx < N_storage)
                        fragments_storage_[i][j] = plain_text_source[source_idx++];
                    else
                        fragments_storage_[i][j] = (CharT)0; // Fills the rest of the fragment buffer with nulls
                }

                if (source_idx >= N_storage)
                    break;
            }

            fragments_data_checksum_expected_ = Calculate_Current_Fragments_Checksum(); // Checksum of the fragments
        }
        else
            fragments_data_checksum_expected_ = 0;

        // 3. IMMEDIATELY re-encrypts the original Obfuscated_String.
        if (parent_ref_.Encrypt() == Detail::integrity_compromised_magic || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return;
        }

        initialization_done_successfully_ = true;
    }
    
    ~Secure_Accessor() {
        Clear_All_Internal_Buffers(); // Clears fragments and the reconstructed buffer.
    }
    
    const CharT* Get() noexcept {
        if (!initialization_done_successfully_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) { // Verifies itself and the parent
            Clear_All_Internal_Buffers(); // Security measure
            _accessor_integrity_canary1 = 0; // Invalidates for future accesses

            return nullptr;
        }

        if (!current_access_ptr_) { // If this is the first call to Get() or if it has been cleared
            if constexpr (N_storage > 0) { // Only reconstructs if there is something to reconstruct
                size_t buffer_write_idx = 0;

                for (size_t i = 0; i < fragment_count_val; ++i) {
                    size_t base_chars_in_frag = N_storage / fragment_count_val;
                    size_t chars_in_this_fragment = base_chars_in_frag + (i < (N_storage % fragment_count_val) ? 1 : 0);

                    for (size_t j = 0; j < chars_in_this_fragment; ++j) {
                        if (j < fragment_buffer_size && buffer_write_idx < N_storage)
                            reconstructed_plain_buffer_[buffer_write_idx++] = fragments_storage_[i][j];
                        else
                            break;
                    }

                    if (buffer_write_idx >= N_storage)
                        break;
                }

                // Ensures null-termination, even if N_storage is exactly filled.
                if (buffer_write_idx < N_storage)
                    reconstructed_plain_buffer_[buffer_write_idx] = (CharT)0;
                else if (N_storage > 0)
                    reconstructed_plain_buffer_[N_storage - 1] = (CharT)0;
                
                fragments_data_checksum_reconstructed_ = Calculate_Current_Fragments_Checksum();
            }
            else { // For N_storage == 0 (empty string, theoretically), there are no checksums
                fragments_data_checksum_reconstructed_ = fragments_data_checksum_expected_; // To pass the check

                if (N_storage > 0)
                    reconstructed_plain_buffer_[0] = (CharT)0; // if N_storage was 0, this is safe if buffer is > 0
            }


            if (fragments_data_checksum_reconstructed_ != fragments_data_checksum_expected_ || !Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
                Clear_All_Internal_Buffers();
                _accessor_integrity_canary1 = 0;

                return nullptr;
            }

            current_access_ptr_ = reconstructed_plain_buffer_;
        }

        // Check again after any internal operation to ensure integrity.
        if(!Verify_Internal_Accessor_Canaries() || !parent_ref_.Verify_Parent_Canaries()) {
            Clear_All_Internal_Buffers();
            _accessor_integrity_canary1 = 0;

            return nullptr;
        }

        return current_access_ptr_;
    }
// ...
```

**Usage Flow with `DRALYXOR_SECURE`:**
1. `auto accessor = DRALYXOR_SECURE(my_obfuscated_string);`
   - The `Secure_Accessor`'s constructor is called.
   - It calls `my_obfuscated_string.Decrypt()`. This involves de-obfuscating the `micro_program_` (to a local copy), using it to decrypt `my_obfuscated_string.storage_`, and then verifying canaries and the checksum of the decrypted content against the expected one.
   - If successful, the content of `my_obfuscated_string.storage_` (now plaintext) is copied and split into the `Secure_Accessor`'s internal `fragments_storage_`.
   - A checksum of `fragments_storage_` (`fragments_data_checksum_expected_`) is calculated.
   - Crucially, `my_obfuscated_string.Encrypt()` is called *immediately afterward*, re-obfuscating `my_obfuscated_string.storage_`.
2. `const char* ptr = accessor.Get();` (or `const char* ptr = accessor;` due to implicit conversion)
   - `Secure_Accessor::Get()` is called.
   - It checks its own integrity canaries and those of the parent `Obfuscated_String`.
   - If it is the first access (`current_access_ptr_` is `nullptr`), it reconstructs the full string in `reconstructed_plain_buffer_` from the `fragments_storage_`.
   - It then checks `fragments_data_checksum_reconstructed_` against `fragments_data_checksum_expected_` to ensure the fragments have not been tampered with while the `Secure_Accessor` existed.
   - If all is correct, it returns a pointer to `reconstructed_plain_buffer_`.
3. The scope of the `accessor` ends (function returns, `{}` block ends, etc.).
   - The `Secure_Accessor`'s destructor is called automatically.
   - `Clear_All_Internal_Buffers()` is invoked, which securely clears (`Secure_Clear_Memory`) both `reconstructed_plain_buffer_` and `fragments_storage_`.

The result is that the plaintext string exists in its complete form only inside the `Secure_Accessor` (in `reconstructed_plain_buffer_`) and only after the first call to `Get()`, for the shortest possible time. The string in the original `Obfuscated_String` object is re-obfuscated as soon as the `Secure_Accessor` copies its content during construction.

#### Memory Fragmentation in the `Secure_Accessor`

To make locating the complete plaintext string in memory even more difficult, the `Secure_Accessor`, during its construction, not only copies the decrypted string but splits it:
1. The string from the parent `Obfuscated_String` is decrypted.
2. Its content is divided into up to `fragment_count_val` (currently 4, if the string is large enough) pieces, which are copied into `fragments_storage_[i]`.
3. The string in the parent `Obfuscated_String` object is re-obfuscated.

Only when `Secure_Accessor::Get()` is called for the first time are these fragments reassembled in `reconstructed_plain_buffer_`. This technique aims to "spread out" sensitive data, frustrating memory scans that look for contiguous strings.

#### Secure Memory Clearing

Both the `Obfuscated_String` destructor (via `Clear_Internal_Data`) and the `Secure_Accessor` destructor (via `Clear_All_Internal_Buffers`) use `Dralyxor::Detail::Secure_Clear_Memory`. This wrapper function ensures that buffers containing sensitive data are reliably zeroed out, preventing compiler optimizations:
- **On Windows:** It uses `SecureZeroMemory` (User Mode) or `RtlSecureZeroMemory` (Kernel Mode), which are operating system functions specifically designed not to be optimized away and to securely zero out memory.
- **On Other Platforms (Linux, macOS, etc.):** The implementation now uses `memset` to fill the memory block with zeros. `memset` operates at the byte level, making it ideal and safe for zeroing out both primitive types (like `char`, `int`) and complex types (like `structs`), avoiding type compatibility or assignment operator issues. To ensure that the call to `memset` is not optimized away by the compiler, the buffer's pointer is first cast to a volatile pointer.

This approach ensures that when the objects are destroyed, the sensitive content is overwritten, reducing the risk of data recovery from memory dump analysis.

### Component 3: Runtime Defenses (Anti-Debugging and Anti-Tampering)

**Dralyxor** does not rely solely on obfuscation. It employs a set of active runtime defenses, located primarily in `anti_debug.hpp` and integrated into the `Decrypt()` and `Encrypt()` methods of `Obfuscated_String`.

#### Multi-Platform Debugger Detection

The function `Detail::Is_Debugger_Present_Tracer_Pid_Sysctl()` (in `anti_debug.hpp`) checks for the presence of a debugger using operating-system-specific techniques:
- **Windows:** `IsDebuggerPresent()`, `NtQueryInformationProcess` for `ProcessDebugPort` (0x07) and `ProcessDebugFlags` (0x1F).
- **Linux:** Reading `/proc/self/status` and checking the value of `TracerPid:`. A value other than 0 indicates that the process is being traced.
- **macOS:** Using `sysctl` with `CTL_KERN`, `KERN_PROC`, `KERN_PROC_PID` to get `kinfo_proc` and checking the `P_TRACED` flag in `kp_proc.p_flag`.

Additionally, inside `Detail::Calculate_Runtime_Key_Modifier()`:
- `Detail::Perform_Timing_Check_Generic()`: Executes a loop of simple computational operations and measures the time. A significant slowdown (above `timing_threshold_milliseconds = 75ms`) can indicate that a debugger is single-stepping or that extensive breakpoints are active. Inside this loop, `Is_Debugger_Present_Tracer_Pid_Sysctl()` is called, and a "bait" function `Detail::Canary_Function_For_Breakpoint_Check()` (which simply returns `0xCC`, the instruction code for `int3` / software breakpoint) is called and its result is XORed, hindering optimization and providing a common place for breakpoints.
- `Detail::Perform_Output_Debug_String_Trick()` (Windows User Mode only): Uses the behavior of `OutputDebugStringA/W` and `GetLastError()`. If a debugger is attached, `GetLastError()` can be modified after the call to `OutputDebugString`.

#### Impact on Operation in Case of Detection or Integrity Violation

If any of the anti-debugging checks return `true`, or if the `Obfuscated_String`'s integrity canaries (`_internal_integrity_canary1/2`) are corrupted, the `Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2)` function will return `Detail::integrity_compromised_magic`.

This return value is crucial in the `Obfuscated_String::Decrypt()` and `Encrypt()` functions:
```cpp
// Simplified logic of Obfuscated_String::Decrypt()
uint64_t Obfuscated_String::Decrypt() noexcept {
    if (!Verify_Internal_Canaries()) { // Obfuscated_String canaries
        Clear_Internal_Data();
        decrypted_ = false;

        return Detail::integrity_compromised_magic;
    }

    if (!decrypted_) {
        uint64_t runtime_key_mod = Detail::Calculate_Runtime_Key_Modifier(_internal_integrity_canary1, _internal_integrity_canary2);

        if (runtime_key_mod == Detail::integrity_compromised_magic) {
            Clear_Internal_Data();
            decrypted_ = false;

            return Detail::integrity_compromised_magic;
        }
        // ... Check canaries again ...

        // IF runtime_key_mod IS NOT integrity_compromised_magic, IT IS NOT USED TO CHANGE THE DECRYPTION KEY.
        // The decryption key is always derived from the original 'compile_time_seed'.
        // The role of runtime_key_mod here is TO ACT AS A FLAG for a hostile environment.
        // If hostile, the function returns integrity_compromised_magic and the decryption does not proceed or is reversed.
        
        // Transform_Compile_Time_Consistent is called with compile_time_seed (and NOT with runtime_key_mod)
        Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(storage_, storage_n - 1, micro_program_, num_actual_instructions_in_program_, compile_time_seed, true /* decrypt mode */);
        
        // ... Check checksum and canaries again ...
        // If anything fails, Clear_Internal_Data() and returns integrity_compromised_magic.
        decrypted_ = true;
    }

    return 0; // Success
}
```

**Key Effect:** If `Calculate_Runtime_Key_Modifier` detects a problem (debugger or corrupted canary) and returns `integrity_compromised_magic`, the `Decrypt()` (and similarly `Encrypt()`) functions abort the operation, clear the internal data of the `Obfuscated_String` (including `storage_` and `micro_program_`), and return `integrity_compromised_magic`. This prevents the string from being correctly decrypted (or re-encrypted) in a hostile environment or if the object has been tampered with.
The string is not decrypted "incorrectly" (into garbage); the operation is simply prevented, and the `Obfuscated_String` object self-destructs in terms of its useful content.

#### Object Integrity Canaries

Both the `Obfuscated_String` and `Secure_Accessor` classes contain canary members (pairs of `uint32_t`):
- `Obfuscated_String`: `_internal_integrity_canary1` (initialized with `Detail::integrity_canary_value`) and `_internal_integrity_canary2` (initialized with `~Detail::integrity_canary_value`).
- `Secure_Accessor`: `_accessor_integrity_canary1` (initialized with `Detail::accessor_integrity_canary_seed`) and `_accessor_integrity_canary2` (initialized with `~Detail::accessor_integrity_canary_seed`).

These canaries are checked at critical points:
- Start and end of `Obfuscated_String::Decrypt()` and `Encrypt()`.
- Constructor, destructor, and `Get()` of `Secure_Accessor`.
- Before and after the anti-debug checks in `Calculate_Runtime_Key_Modifier`.

If these canary values are altered (e.g., by a buffer overflow, an indiscriminate memory patch, or a hook that overwrites adjacent memory), the check (`Verify_Internal_Canaries()` or `Verify_Internal_Accessor_Canaries()`) will fail.
In case of failure, operations are aborted, relevant internal data is cleared, and an error value (`Detail::integrity_compromised_magic` or `nullptr`) is returned, signaling tampering.

#### String Content Checksum

- A 16-bit checksum of the *original plaintext* string (excluding the null terminator) is calculated by `Detail::Calculate_String_Content_Checksum` at compile-time.
- This checksum is then obfuscated using `Detail::Obfuscate_Deobfuscate_Short_Value` (with `compile_time_seed` and `content_checksum_obf_salt`) and stored in `_content_checksum_obfuscated` in the `Obfuscated_String` object.
- **When Decrypting (`Decrypt()`):** After `storage_` is transformed (supposedly to plaintext), its checksum is calculated. The `_content_checksum_obfuscated` is de-obfuscated to get the reference checksum. If the two checksums do not match, it indicates that:
   - The decryption did not restore the original string (perhaps because the operation was aborted due to debugger detection before full transformation, or there was corruption of the seed/micro-program).
   - The `storage_` (when obfuscated) or the `_content_checksum_obfuscated` were tampered with in memory.
- **When Encrypting (`Encrypt()`):** Before `storage_` (which is in plaintext at this point) is transformed back into its obfuscated form, its checksum is calculated and compared with the reference one. A discrepancy here would mean that the plaintext string was altered *inside the `Obfuscated_String`'s `storage_` while it was decrypted*, which is a strong indication of memory tampering or misuse (since direct access to `storage_` should not be performed).

In both cases of checksum failure, `Clear_Internal_Data()` is called and `integrity_compromised_magic` is returned.

### Component 4: Generation of Unique and Unpredictable Keys and Seeds

The security of any encryption system rests on the strength and uniqueness of its keys and seeds. **Dralyxor** ensures that each obfuscated string uses a fundamentally unique set of encryption parameters.

#### Sources of Entropy for the `compile_time_seed`

The `static constexpr uint64_t Obfuscated_String::compile_time_seed` is the master seed for all pseudo-random operations related to that string instance. Its generation is now conditional, based on the presence of a user-provided key:

- **If a key is provided by the user (using `DRALYXOR_KEY` or `DRALYXOR_KEY_LOCAL`):**
   1. The provided `key_literal` is transformed into a 64-bit hash at compile-time using the FNV-1a algorithm.
   2. This hash becomes the basis of the `compile_time_seed`, combined with `__COUNTER__` (to ensure uniqueness between different uses of the same key) and the string's length.
      ```cpp
      // Simplified logic
      static constexpr uint64_t User_Seed = Dralyxor::Detail::fnv1a_hash(key_literal);
      static constexpr uint64_t compile_time_seed = User_Seed ^ ((uint64_t)Instance_Counter << 32) ^ storage_n;
      ```
      In this mode, the security of the obfuscation directly depends on the strength and secrecy of the provided key.

- **If no key is provided (using `DRALYXOR` or `DRALYXOR_LOCAL`):**
   - The `compile_time_seed` is generated using a combination of the following factors to maximize entropy and variability:
      ```cpp
      // Inside Obfuscated_String<CharT, storage_n, Instance_Counter>
      static constexpr uint64_t compile_time_seed =
          Detail::fnv1a_hash(__DATE__ __TIME__) ^     // Component 1: Variability between compilations
          ((uint64_t)Instance_Counter << 32) ^        // Component 2: Variability within a compilation unit
          storage_n;                                  // Component 3: Variability based on string length
      ```
   - **`Detail::fnv1a_hash(__DATE__ __TIME__)`**: The `__DATE__` (e.g., "Jan 01 2025") and `__TIME__` (e.g., "12:30:00") macros are strings provided by the preprocessor that change every time the file is compiled. The FNV-1a hash of these values creates a seed base that is different for each build of the project.
   - **`Instance_Counter` (fed by `__COUNTER__` in the macro)**: The `__COUNTER__` macro is a counter maintained by the preprocessor that increments each time it is used within a compilation unit. By passing this as a template argument, each use of the `DRALYXOR` or `DRALYXOR_LOCAL` macro will result in a different `Instance_Counter` and therefore a different `compile_time_seed`, even for identical string literals in the same source file.
   - **`storage_n` (string length)**: The length of the string is also XORed in, adding another factor of differentiation.

This `compile_time_seed` (whether derived from the user's key or auto-generated) is then used as the basis for:
1. Generating the `micro_program_` (seeding the PRNG with `compile_time_seed ^ 0xDEADBEEFC0FFEEULL`).
2. Deriving the obfuscation key for the `micro_program_` itself (via `Detail::Get_Micro_Program_Obfuscation_Key`).
3. Deriving the obfuscation key for the `_content_checksum_obfuscated` (via `Detail::Obfuscate_Deobfuscate_Short_Value`).
4. Serving as the `base_seed` for `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent`.

#### Derived Seeds for Content Transformations

Inside `Detail::Micro_Program_Cipher::Transform_Compile_Time_Consistent(CharT* data, ..., uint64_t base_seed, ...)`:
- A `Constexpr_PRNG prng_operand_modifier(base_seed)` is initialized. For each character of the string being transformed, `prng_operand_modifier.Key()` produces a `prng_key_for_ops_in_elem`. This key is XORed with the micro-instruction's operand before application, ensuring that the effect of the same micro-instruction is subtly different for each character.
- A `Constexpr_PRNG prng_applier_selector(base_seed ^ 0xAAAAAAAAAAAAAAAAULL)` is initialized. For each character, `prng_applier_selector.Key()` is used to choose between `Applier_Style_Direct` and `Applier_Style_DoubleLayer`.

This introduces additional dynamism to the transformation of each character, even if the underlying micro-program is the same for all characters of a given string.

#### Immunity Against "Replay" Attacks and Pattern Analysis

- **Inter-Compilation Uniqueness:** If an attacker analyzes the binary of version 1.0 of your software and, with great effort, manages to break the obfuscation of a string (in auto-key mode), that knowledge will likely be useless for version 1.1, as the `__DATE__ __TIME__` will have changed, resulting in completely different `compile_time_seed`s and micro-programs.
- **Intra-Compilation Uniqueness:** If you use `DRALYXOR("AdminPassword")` in two different places in your code (or in the same .cpp file), `__COUNTER__` will ensure that the resulting `Obfuscated_String` objects, and therefore their obfuscated representations in the binary, are different. This prevents an attacker from finding one obfuscated pattern and using it to locate all other occurrences of the same original string.

This robust seed generation is a cornerstone of **Dralyxor's** security against attacks that rely on discovering a "master secret" or exploiting the repetition of ciphers and transformations.

## Complete Public API Reference

### Obfuscation Macros

These are the main entry points for creating obfuscated strings.

#### `DRALYXOR(str_literal)`

- **Purpose:** Creates an `Obfuscated_String` object with a static lifetime (exists for the entire program execution). Ideal for global constants or strings that need to be accessed from multiple locations and persist.
- **Storage:** Static memory (usually in the program's data section).
- **Implementation:**
   ```cpp
   #define DRALYXOR(str_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal); \
           return obfuscated_static_string; \
       }()
   ```
- **Parameters:**
   - `str_literal`: A C-style string literal (e.g., `"Hello World"`, `L"Unicode String"`).
- **Return:** A reference (`auto&`) to the static `Obfuscated_String` object, created inside an immediately-invoked lambda expression.
- **Example:**
   ```cpp
   static auto& api_endpoint_url = DRALYXOR("https://service.example.com/api");
   // api_endpoint_url is a reference to a static Obfuscated_String.
   ```

#### `DRALYXOR_LOCAL(str_literal)`

- **Purpose:** Creates an `Obfuscated_String` object with automatic lifetime (usually on the stack, if used inside a function). Ideal for temporary secrets confined to a scope.
- **Storage:** Automatic (stack for local function variables).
- **Implementation:**
   ```cpp
   #define DRALYXOR_LOCAL(str_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__>(str_literal)
   ```
- **Parameters:**
   - `str_literal`: A C-style string literal.
- **Return:** An `Obfuscated_String` object by value (which can be optimized with RVO/NRVO by the compiler).
- **Example:**
   ```cpp
   void process_data() {
       auto temp_key = DRALYXOR_LOCAL("TemporaryProcessingKey123");
       // ... use temp_key with DRALYXOR_SECURE ...
   } // temp_key is destroyed here, its destructor calls Clear_Internal_Data().
   ```

#### `DRALYXOR_KEY(str_literal, key_literal)`

- **Purpose:** Similar to `DRALYXOR`, creates a static `Obfuscated_String` object, but uses a **user-provided key** (`key_literal`) to seed the obfuscation, offering the highest level of security.
- **Storage:** Static memory (usually in the program's data section).
- **Implementation:**
   ```cpp
   #define DRALYXOR_KEY(str_literal, key_literal) \
       []() -> auto& { \
           static auto obfuscated_static_string_with_key = Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal); \
           return obfuscated_static_string_with_key; \
       }()
   ```
- **Parameters:**
   - `str_literal`: The string literal to be obfuscated.
   - `key_literal`: The string literal to be used as a secret key.
- **Return:** A reference (`auto&`) to the static `Obfuscated_String` object.
- **Example:** `static auto& g_db_password = DRALYXOR_KEY("pa$$w0rd!", "MySecretAppKey-78d1-41e7-9a4d");`

#### `DRALYXOR_KEY_LOCAL(str_literal, key_literal)`

- **Purpose:** Similar to `DRALYXOR_LOCAL`, creates an `Obfuscated_String` object on the stack, using a **user-provided key**.
- **Storage:** Automatic (stack for local function variables).
- **Implementation:**
   ```cpp
   #define DRALYXOR_KEY_LOCAL(str_literal, key_literal) Dralyxor::Obfuscated_String<typename Dralyxor::Detail::Fallback::decay<decltype(*str_literal)>::type, (sizeof(str_literal) / sizeof(decltype(*str_literal))), __COUNTER__, Dralyxor::Detail::fnv1a_hash(key_literal)>(str_literal)
   ```
- **Parameters:**
   - `str_literal`: The string literal to be obfuscated.
   - `key_literal`: The string literal to be used as a key.
- **Return:** An `Obfuscated_String` object by value.
- **Example:** `auto temp_token = DRALYXOR_KEY_LOCAL("TempAuthToken", "SessionSpecificSecret-a1b2");`

### Secure Access Macro

#### `DRALYXOR_SECURE(obfuscated_var)`

- **Purpose:** Provides secure, temporary access to the decrypted content of an `Obfuscated_String` object. This is the **only recommended method** for reading the string.
- **Implementation:**
   ```cpp
   #define DRALYXOR_SECURE(obfuscated_var) Dralyxor::Secure_Accessor<typename Dralyxor::Detail::Fallback::decay<decltype(obfuscated_var)>::type>(obfuscated_var)
   ```

- **Parameters:**
   - `obfuscated_var`: A variable (an lvalue or an rvalue that can bind to a non-const lvalue reference) of type `Dralyxor::Obfuscated_String<...>`. The variable must be mutable because the `Secure_Accessor` constructor calls `Decrypt()` and `Encrypt()` on it.
- **Return:** A `Dralyxor::Secure_Accessor<decltype(obfuscated_var)>` object by value.
- **Usage:**
   ```cpp
   auto& my_static_secret = DRALYXOR("My Top Secret");
   // ...
   {
       auto accessor = DRALYXOR_SECURE(my_static_secret);
       const char* secret_ptr = accessor.Get(); // Or just: const char* secret_ptr = accessor; (implicit conversion)
       
       if (secret_ptr) {
           // Use secret_ptr here. It points to the temporarily decrypted string in the accessor's buffer.
           // Ex: send_data(secret_ptr);
       }
       else {
           // Decryption or integrity check failed. Handle the error.
           // The accessor may have failed to initialize (e.g., my_static_secret was corrupted).
       }
   } // accessor is destroyed. Its internal buffers (fragments and reconstructed string) are cleared.
    // my_static_secret.storage_ was already re-obfuscated by the Secure_Accessor constructor
    // right after copying the content to the accessor's fragments.
   ```

> [!WARNING]
> Always check if the pointer returned by `DRALYXOR_SECURE(...).Get()` (or by the implicit conversion) is not `nullptr` before using it. A `nullptr` return indicates a failure in decryption (e.g., debugger detection, corruption of canaries/checksums in the parent `Obfuscated_String` or in the `Secure_Accessor` itself). Using a `nullptr` pointer will result in undefined behavior (most likely a segmentation fault).

## Advanced Features and Best Practices

### Full Unicode Support (Wide Strings - `wchar_t`)

**Dralyxor** is character-type agnostic thanks to its use of templates (`CharT`). It natively handles `char` (for ASCII/UTF-8 strings) and `wchar_t` (for UTF-16 strings on Windows or UTF-32 on other systems, depending on platform and compiler). Simply use the `L` prefix for `wchar_t` literals:
```cpp
auto wide_message = DRALYXOR_LOCAL(L"Unicode Message: Hello World Ω ❤️");
{
    auto accessor = DRALYXOR_SECURE(wide_message);

    if (accessor.Get()) {
        // Example on Windows:
        // MessageBoxW(nullptr, accessor.Get(), L"Unicode Title", MB_OK);
        // Example with wcout:
        // #include <io.h> // For _setmode on Windows with MSVC
        // #include <fcntl.h> // For _O_U16TEXT on Windows with MSVC
        // _setmode(_fileno(stdout), _O_U16TEXT); // Set stdout to UTF-16
        // std::wcout << L"Wide Message: " << accessor.Get() << std::endl;
    }
}
```

For 1-byte characters (`sizeof(CharT) == 1`), the `Micro_Program_Cipher` transformation engine applies the micro-program byte-by-byte. For multi-byte characters (`sizeof(CharT) > 1`):
- `Micro_Program_Cipher::Transform_Compile_Time_Consistent` uses a simpler approach: the entire multi-byte character is XORed with a mask derived from `prng_key_for_ops_in_elem` (replicated to fill the size of `CharT`). For example, if `CharT` is `wchar_t` (2 bytes) and `prng_key_for_ops_in_elem` is `0xAB`, the character will be XORed with `0xABAB`.
This ensures all bytes of the `wchar_t` are affected by the obfuscation, even if not by the full micro-program. The micro-program's complexity still contributes indirectly through the derivation of the PRNG keys.

### Intelligent Adaptation to C++ Standards and Environments (Kernel Mode)

As mentioned, **Dralyxor** adapts:
- **C++ Standards:** Requires at least **C++14**. It detects and uses features from **C++17** and **C++20** (like `if constexpr`, `consteval`, `_v` suffixes for `type_traits`) when the compiler supports them, falling back to **C++14** alternatives otherwise. Macros like `_DRALYXOR_IF_CONSTEXPR` and `_DRALYXOR_CONSTEVAL` in `detection.hpp` manage this adaptation.
- **Kernel Mode:** When `_KERNEL_MODE` is defined (typical in WDK projects for Windows drivers), **Dralyxor** (via `env_traits.hpp`) avoids including standard STL headers like `<type_traits>` which may not be available or may behave differently. Instead, it uses its own `constexpr` implementations of basic tools like `Dralyxor::Detail::Fallback::decay` and `Dralyxor::Detail::Fallback::remove_reference`. This allows for the safe use of **Dralyxor** to protect strings in low-level system components.
   - Similarly, `secure_memory.hpp` uses `RtlSecureZeroMemory` in Kernel Mode. For other platforms, such as Linux, it falls back to the safe use of `memset` to ensure memory clearing, adapting to be compatible with different data types.
   - The User Mode anti-debug checks (like `IsDebuggerPresent`, `NtQueryInformationProcess`, `OutputDebugString`) are disabled (`#if !defined(_KERNEL_MODE)`) in Kernel Mode, as they do not apply or have different equivalents. The timing checks may still have some effect, but the main line of defense in Kernel Mode is the obfuscation itself.

### Performance Considerations and Overhead

- **Compile Time:** Obfuscation, including micro-program generation and application, occurs entirely at compile-time. For projects with a very large number of obfuscated strings, compile time may increase. This is a one-time cost per compilation.
- **Binary Size:** Each `Obfuscated_String` adds its `storage_` (string size), the `micro_program_` (fixed at `max_micro_instructions * sizeof(Micro_Instruction)`), plus a few bytes for canaries, checksum, and flags. There might be an increase in binary size compared to pure literal strings, especially for many small strings.
- **Runtime:**
   - **`Obfuscated_String` Creation (static or local objects):** Occurs at compile-time (for statics) or involves copying pre-computed data (for locals, optimizable by RVO). No "generation" cost at runtime.
   - **`Obfuscated_String::Decrypt()` / `Encrypt()`:**
      - Canary checks (extremely fast).
      - `Detail::Calculate_Runtime_Key_Modifier()`: Includes anti-debug checks. The timing check (`Perform_Timing_Check_Generic`) is the most costly here, executing a loop. Others are API calls or file reads (Linux).
      - Micro-program de-obfuscation (copy and XOR, fast).
      - String transformation: Loop over `N_data_elements_to_transform`, and within it, loop over `num_actual_instructions_in_program_`. For each instruction, a call to `Byte_Transform_Applier` which does some byte operations. Cost is O(string_length \* num_instructions).
      - Checksum calculation/verification (`Detail::Calculate_String_Content_Checksum`): O(string_length \* sizeof(CharT)).
   - **`Secure_Accessor` Creation:**
      - Calls `Obfuscated_String::Decrypt()`.
      - Copies string to fragments: O(string_length).
      - Calculates fragment checksum (`Calculate_Current_Fragments_Checksum`): O(string_length).
      - Calls `Obfuscated_String::Encrypt()`. This is the point of highest overhead concentration in a single access operation.
   - **`Secure_Accessor::Get()`:**
      - First call: Checks canaries, reconstructs string from fragments (O(string_length)), checks fragment checksum.
      - Subsequent calls (to the same `Secure_Accessor` object): Checks canaries (fast) and returns already computed pointer (O(1)).
- **Overall Overhead:** For most applications where sensitive strings are not accessed in very high-frequency loops, runtime overhead is generally acceptable, especially considering the security benefit. The `Secure_Accessor` design (created only when needed and strictly scoped by RAII) is key to managing this cost. Test in your specific environment if performance is critical.

### Integration into a Layered Security Strategy

> [!IMPORTANT]
> **Dralyxor is a powerful tool for obfuscating embedded strings and defending against memory analysis**, not a generic encryption solution for persistent data storage on disk or secure network transmission.
>
> It should be used as **one of many layers** in a comprehensive security strategy. No single tool is a silver bullet. Other measures to consider include:
> - **Minimizing Embedded Secrets:** Whenever possible, avoid embedding highly critical secrets. Use alternatives such as:
>    - Secure configurations provided at runtime (environment variables, configuration files with restricted permissions).
>    - Secret management services (vaults) like HashiCorp Vault, Azure Key Vault, AWS Secrets Manager.
> - Robust input validation on all interfaces.
> - Principle of least privilege for processes and users.
> - Secure network communication (TLS/SSL with certificate pinning, if applicable).
> - Secure hashing of user passwords (Argon2, scrypt, bcrypt).
> - Protecting the binary as a whole with other anti-reversing/anti-tampering techniques (packers, code virtualizers, code integrity checks), being aware of the trade-offs these may introduce (antivirus false positives, complexity).
> - Secure development best practices (Secure SDLC).

**Dralyxor** focuses on solving a specific, common problem very well: protecting embedded literal strings against static analysis and minimizing their memory exposure during execution, making life harder for those attempting to reverse engineer your software.

## License

This library is protected under the MIT License, which allows for:

- ✔️ Commercial and private use
- ✔️ Modification of the source code
- ✔️ Distribution of the code
- ✔️ Sublicensing

### Conditions:

- Retain the copyright notice
- Include a copy of the MIT license

For more details on the license: https://opensource.org/licenses/MIT

**Copyright (c) Calasans - All rights reserved**