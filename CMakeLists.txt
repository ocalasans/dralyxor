cmake_minimum_required(VERSION 3.25)
project(Dralyxor VERSION 1.0.0 LANGUAGES CXX)

include(GNUInstallDirs)

option(DRALYXOR_BUILD_EXAMPLES "Build Dralyxor examples" ON)
option(DRALYXOR_BUILD_TESTS "Build Dralyxor tests" ON)
option(DRALYXOR_BUILD_BENCHMARK "Build Dralyxor benchmark" OFF)

add_library(dralyxor INTERFACE)
add_library(Dralyxor::dralyxor ALIAS dralyxor)

target_include_directories(dralyxor INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

enable_testing()

if (DRALYXOR_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif ()

if (DRALYXOR_BUILD_TESTS)
    add_subdirectory(tests)
endif ()

if (DRALYXOR_BUILD_BENCHMARK)
    add_subdirectory(benchmark)
endif ()

include(CMakePackageConfigHelpers)

install(TARGETS dralyxor
    EXPORT DralyxorTargets
)

install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/dralyxor
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.hxx"
)

install(EXPORT DralyxorTargets
    FILE DralyxorTargets.cmake
    NAMESPACE Dralyxor::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Dralyxor
)

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/DralyxorConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/DralyxorConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Dralyxor
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/DralyxorConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
    ARCH_INDEPENDENT
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/DralyxorConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/DralyxorConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Dralyxor
)