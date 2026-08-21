cmake_minimum_required(VERSION 3.21)
project(crimp LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(CRIMP_ENABLE_COVERAGE "Instrument builds with gcov for coverage reporting" OFF)
if(CRIMP_ENABLE_COVERAGE)
    add_compile_options(--coverage -O0)
    add_link_options(--coverage)
endif()

find_package(capstone CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn)
find_package(ZLIB REQUIRED)

add_library(crimp STATIC
    src/core/finding.c
    src/core/registry.c
    src/core/walk.c
    src/core/fileutil.c
    src/core/pattern_scan.c
    src/core/binstring.c
    src/core/inventory.c
    src/core/component_identify.c
    src/core/sbom.c
    src/core/scan.c
    src/extract/identify.c
    src/extract/squashfs.c
    src/detectors/weak_credentials.c
    src/detectors/exposed_protocols.c
    src/detectors/weak_crypto.c
)
target_include_directories(crimp PUBLIC include PRIVATE src)
target_link_libraries(crimp PRIVATE ZLIB::ZLIB)

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

add_executable(test_weak_crypto tests/detectors/test_weak_crypto.c)
target_link_libraries(test_weak_crypto PRIVATE crimp)
add_test(NAME weak_crypto COMMAND test_weak_crypto)

add_executable(test_component_identify tests/core/test_component_identify.c)
target_link_libraries(test_component_identify PRIVATE crimp)
add_test(NAME component_identify COMMAND test_component_identify)

add_executable(test_sbom tests/core/test_sbom.c)
target_link_libraries(test_sbom PRIVATE crimp)
add_test(NAME sbom COMMAND test_sbom)

add_executable(test_scan tests/core/test_scan.c)
target_link_libraries(test_scan PRIVATE crimp)
add_test(NAME scan COMMAND test_scan)

add_executable(test_identify tests/extract/test_identify.c)
target_link_libraries(test_identify PRIVATE crimp)
add_test(NAME identify COMMAND test_identify)

add_executable(test_squashfs_list tests/extract/test_squashfs_list.c)
target_include_directories(test_squashfs_list PRIVATE src/extract)
target_link_libraries(test_squashfs_list PRIVATE crimp)
target_compile_definitions(test_squashfs_list PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_uncompressed.img")
add_test(NAME squashfs_list COMMAND test_squashfs_list)

add_executable(test_squashfs_gzip tests/extract/test_squashfs_gzip.c)
target_include_directories(test_squashfs_gzip PRIVATE src/extract)
target_link_libraries(test_squashfs_gzip PRIVATE crimp)
target_compile_definitions(test_squashfs_gzip PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_gzip.img")
add_test(NAME squashfs_gzip COMMAND test_squashfs_gzip)

add_executable(test_squashfs_synthetic tests/extract/test_squashfs_synthetic.c)
target_include_directories(test_squashfs_synthetic PRIVATE src/extract)
target_link_libraries(test_squashfs_synthetic PRIVATE crimp)
add_test(NAME squashfs_synthetic COMMAND test_squashfs_synthetic)

add_executable(spike_capstone_test spike/capstone-test/test_disasm.c)
target_link_libraries(spike_capstone_test PRIVATE capstone::capstone)

add_executable(spike_unicorn_test spike/unicorn-test/test_emulate.c)
target_link_libraries(spike_unicorn_test PRIVATE PkgConfig::UNICORN)
