add_executable(dralyxor_benchmark
    main.cxx
    harness.cxx
    reporter.cxx
    scenarios/decrypt_cost_by_length.cxx
    scenarios/anti_debug_check_cost.cxx
    scenarios/consteval_vs_macro_parity.cxx
    scenarios/guard_vs_direct_access.cxx
)

target_link_libraries(dralyxor_benchmark PRIVATE Dralyxor::dralyxor)
target_compile_features(dralyxor_benchmark PRIVATE cxx_std_20)

if (MSVC)
    target_compile_options(dralyxor_benchmark PRIVATE /O2)
else ()
    target_compile_options(dralyxor_benchmark PRIVATE -O2)
endif ()