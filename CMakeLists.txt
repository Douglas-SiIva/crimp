cmake_minimum_required(VERSION 3.21)
project(crimp LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(capstone CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn)

add_library(crimp STATIC
    src/core/finding.c
    src/core/registry.c
    src/core/walk.c
    src/core/fileutil.c
    src/extract/identify.c
    src/extract/squashfs.c
    src/detectors/weak_credentials.c
    src/detectors/exposed_protocols.c
)
target_include_directories(crimp PUBLIC include PRIVATE src)

add_executable(crimp_cli src/cli/main.c)
target_link_libraries(crimp_cli PRIVATE crimp)
set_target_properties(crimp_cli PROPERTIES OUTPUT_NAME crimp)

enable_testing()
add_executable(test_weak_credentials tests/detectors/test_weak_credentials.c)
target_link_libraries(test_weak_credentials PRIVATE crimp)
add_test(NAME weak_credentials COMMAND test_weak_credentials)

add_executable(test_exposed_protocols tests/detectors/test_exposed_protocols.c)
target_link_libraries(test_exposed_protocols PRIVATE crimp)
add_test(NAME exposed_protocols COMMAND test_exposed_protocols)

add_executable(spike_capstone_test spike/capstone-test/test_disasm.c)
target_link_libraries(spike_capstone_test PRIVATE capstone::capstone)

add_executable(spike_unicorn_test spike/unicorn-test/test_emulate.c)
target_link_libraries(spike_unicorn_test PRIVATE PkgConfig::UNICORN)
