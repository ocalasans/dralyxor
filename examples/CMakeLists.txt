set(DRALYXOR_EXAMPLES_CXX17
    basic_usage
    seeded_and_call_site_diversity
    reencrypting_between_uses
    scoped_access_with_guard
    detecting_debuggers_and_tampering
    wide_and_multibyte_literals
)

foreach (example ${DRALYXOR_EXAMPLES_CXX17})
    add_executable(${example} ${example}.cxx)
    target_link_libraries(${example} PRIVATE Dralyxor::dralyxor)
    target_compile_features(${example} PRIVATE cxx_std_17)
endforeach ()

add_executable(minimum_supported_standard_cpp14 minimum_supported_standard_cpp14.cxx)
target_link_libraries(minimum_supported_standard_cpp14 PRIVATE Dralyxor::dralyxor)
target_compile_features(minimum_supported_standard_cpp14 PRIVATE cxx_std_14)

add_executable(direct_construction_in_cpp20 direct_construction_in_cpp20.cxx)
target_link_libraries(direct_construction_in_cpp20 PRIVATE Dralyxor::dralyxor)
target_compile_features(direct_construction_in_cpp20 PRIVATE cxx_std_20)

find_package(Threads REQUIRED)

add_executable(one_instance_per_thread one_instance_per_thread.cxx)
target_link_libraries(one_instance_per_thread PRIVATE Dralyxor::dralyxor Threads::Threads)
target_compile_features(one_instance_per_thread PRIVATE cxx_std_17)