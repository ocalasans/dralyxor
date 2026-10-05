# Dralyxor benchmark

This benchmark answers four concrete questions about `Dralyxor::Obfuscated::String` with
measured numbers instead of assumptions:

1. How much does `Decrypt()`+`Encrypt()` cost, and how does that scale with the literal's length?
2. Where does that cost actually go? `Decrypt()` runs a full anti-debug scan before touching the
   cipher, every single time by design. This breaks down what each individual check in that scan
   costs.
3. Does choosing the direct C++20 `consteval` construction over the `DRALYXOR_OBFUSCATED` macro
   change anything at *runtime*? It shouldn't: the difference between the two is a compile-time
   guarantee, not a different runtime code path. This measures it rather than assuming it.
4. What does `Accessor::Guard`'s extra copy-and-re-encrypt step cost over calling
   `Decrypt()`/`Encrypt()` directly?

## Methodology

`Harness::Measure` auto-calibrates an inner iteration count per scenario (enough repetitions to
clear ~100 microseconds of wall-clock time, so the loop overhead itself doesn't dominate), runs a
handful of untimed warmup rounds, then records 200 independent trials (50 for
`Hardware_Breakpoints::Check()` alone, see the platform note below for why) and reports
min/median/mean/max/stddev of that distribution. `Escape::Do()` forces the compiler to materialize
each result instead of optimizing the "unused" computation away.

This always builds at `-O2` regardless of the project's own build type (`CMAKE_BUILD_TYPE` is
intentionally not propagated here), since nobody tunes for a Debug build's performance. It is not
registered with CTest: it's a number-reporting tool for humans, not a pass/fail check.

Run it with:

```sh
cmake -S . -B build -DDRALYXOR_BUILD_BENCHMARK=ON
cmake --build build
./build/benchmark/dralyxor_benchmark
```

### A note on comparing platforms

Two of `Decrypt()`'s anti-debug checks are implemented differently per platform:
`Hardware_Breakpoints::Check()` reads the CPU's debug registers directly via `GetThreadContext`
on Windows, but has no equivalent direct API on Linux and instead has to fork a short-lived child
process to read them through `ptrace`, a fundamentally more expensive operation. Because of that,
**the relative cost breakdown below is platform-specific, not just the absolute numbers**: which
check ends up dominating the total can differ between Windows and Linux. If you care about one
platform in particular, measure on that platform; don't extrapolate the breakdown from the other
one.

## Results

Measured on Windows, GCC (MinGW-w64), `-O2`.

```
Dralyxor Benchmark

-- === Decrypt()+Encrypt() cost by literal length (full public API, real anti-debug scan included) === --

-- Baseline: reading byte 0 of a plain, non-obfuscated pointer (no work at all) --
plain char* (16 bytes)                         min       0.3 ns   median       0.3 ns   mean       0.3 ns   max         0.5 ns   stddev       0.0 ns   (n=200)
plain char* (1024 bytes)                       min       0.3 ns   median       0.3 ns   mean       0.3 ns   max         0.4 ns   stddev       0.0 ns   (n=200)

-- Dralyxor::Obfuscated::String: Decrypt()+Encrypt(), by Storage_Size --
Obfuscated::String (16 bytes)                  min   53100.0 ns   median   56800.0 ns   mean   60206.5 ns   max    248200.0 ns   stddev   18785.1 ns   (n=200)
Obfuscated::String (64 bytes)                  min   54950.0 ns   median   55400.0 ns   mean   55676.5 ns   max     59700.0 ns   stddev     825.2 ns   (n=200)
Obfuscated::String (256 bytes)                 min   59850.0 ns   median   60300.0 ns   mean   61190.0 ns   max     69350.0 ns   stddev    2108.4 ns   (n=200)
Obfuscated::String (1024 bytes)                min   94900.0 ns   median   96000.0 ns   mean   97767.0 ns   max    114500.0 ns   stddev    4000.8 ns   (n=200)

-- === Cost of each individual anti-debug check Decrypt() runs on every call === --
Presence::Check() (IsDebuggerPresent/PEB/NtQuery* or TracerPid)   min     535.9 ns   median     553.7 ns   mean     568.6 ns   max       941.0 ns   stddev      45.1 ns   (n=200)
Hardware_Breakpoints::Check()                                     min     843.8 ns   median     908.6 ns   mean     998.9 ns   max      1532.8 ns   stddev     158.7 ns   (n=50)
Timing::Check()                                                   min   51300.0 ns   median   51775.0 ns   mean   53171.8 ns   max     63550.0 ns   stddev    2570.4 ns   (n=200)

-- === Does construction method change runtime Decrypt() cost? === --
direct C++20 consteval construction            min   53900.0 ns   median   59050.0 ns   mean   59890.0 ns   max     87350.0 ns   stddev    4590.0 ns   (n=200)
DRALYXOR_OBFUSCATED macro                      min   53950.0 ns   median   55650.0 ns   mean   57441.5 ns   max     83950.0 ns   stddev    4117.9 ns   (n=200)
   (median ratio macro/direct = 0.942x)

-- === Accessor::Guard vs calling Decrypt()/Encrypt() directly === --
String::Decrypt()+Encrypt() directly           min   54300.0 ns   median   54650.0 ns   mean   55771.5 ns   max     68600.0 ns   stddev    2538.7 ns   (n=200)
Accessor::Guard (construct + Get())            min   55750.0 ns   median   55850.0 ns   mean   57667.5 ns   max     73650.0 ns   stddev    3049.9 ns   (n=200)
   (Guard costs 1.02x direct access)
```

(Reproducible with the command above. `n` is the trial count; `Hardware_Breakpoints::Check()` uses
fewer trials because it's comparatively heavier per call on some platforms; see the note above.)

## What these numbers say

**The cipher itself is a small fraction of the total.** Going from a 16-byte to a 1024-byte secret
moves the median from ~56.8µs to ~96µs. Most of that total, on either end, is fixed per-call
overhead that doesn't depend on the secret's length at all.

**On this measurement, `Timing::Check()` is what dominates the total** (~51.8µs of a
~55-96µs call), not `Hardware_Breakpoints::Check()` (~0.9µs here, cheap on Windows specifically,
since `GetThreadContext` doesn't need the fork a non-Windows platform would require for the same
check; see the platform note above). `Presence::Check()` is cheap everywhere (~0.55µs) since it's
just a handful of direct API/PEB reads. Summing the three checks (~0.55 + ~0.91 + ~51.8 ≈ 53.3µs)
roughly accounts for the full `Decrypt()+Encrypt()` cost at the smallest size, confirming the scan
is indeed almost the entire bill, not the cipher.

**Construction method doesn't meaningfully change runtime cost** (0.942x, i.e. within a few
percent either way, well inside this benchmark's own run-to-run noise, not a real directional
effect). `DRALYXOR_OBFUSCATED` exists for compile-time safety on pre-C++20 toolchains, not as a
runtime trade-off, and that holds up: picking it over direct construction on a C++20+ compiler
costs nothing measurable.

**`Accessor::Guard` is cheap relative to `Decrypt()` itself** (1.02x): it pays the owner's full
anti-debug scan once, same as a direct `Decrypt()` call, plus a second, independent
re-encryption of its own short-lived copy. The RAII convenience is close to free once you're
already paying for one decryption.