set(DRALYXOR_TESTS
    construction
    encrypt_decrypt_roundtrip
    seeded_and_diversity
    guard_scoped_access
    detection_flags
    generic_character_types
    move_semantics
)

set(DRALYXOR_TEST_STANDARDS 14 17 20 23)

foreach (test ${DRALYXOR_TESTS})
    foreach (std ${DRALYXOR_TEST_STANDARDS})
        set(target_name test_${test}_cxx${std})

        add_executable(${target_name} ${test}.cxx)
        target_link_libraries(${target_name} PRIVATE Dralyxor::dralyxor)
        target_compile_features(${target_name} PRIVATE cxx_std_${std})

        add_test(NAME ${test}_cxx${std} COMMAND ${target_name})
    endforeach ()
endforeach ()