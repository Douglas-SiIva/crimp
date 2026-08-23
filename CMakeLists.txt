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
find_package(LibLZMA REQUIRED)
find_package(yaml CONFIG REQUIRED)

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
    src/core/yaml_rules.c
    src/extract/identify.c
    src/extract/fs_util.c
    src/extract/squashfs.c
    src/extract/cramfs.c
    src/extract/jffs2.c
    src/detectors/weak_credentials.c
    src/detectors/exposed_protocols.c
    src/detectors/weak_crypto.c
)
target_include_directories(crimp PUBLIC include PRIVATE src)
target_link_libraries(crimp PRIVATE ZLIB::ZLIB LibLZMA::LibLZMA yaml)

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

add_executable(test_yaml_rules tests/core/test_yaml_rules.c)
target_link_libraries(test_yaml_rules PRIVATE crimp)
add_test(NAME yaml_rules COMMAND test_yaml_rules)

add_executable(test_identify tests/extract/test_identify.c)
target_link_libraries(test_identify PRIVATE crimp)
add_test(NAME identify COMMAND test_identify)

add_executable(test_fs_extract tests/extract/test_fs_extract.c)
target_link_libraries(test_fs_extract PRIVATE crimp)
target_compile_definitions(test_fs_extract PRIVATE
    FIXTURE_WITH_BIGFILE="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_extract.img"
    FIXTURE_WITHOUT_BIGFILE="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_uncompressed.img")
add_test(NAME fs_extract COMMAND test_fs_extract)

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

add_executable(test_squashfs_extract tests/extract/test_squashfs_extract.c)
target_include_directories(test_squashfs_extract PRIVATE src/extract)
target_link_libraries(test_squashfs_extract PRIVATE crimp)
target_compile_definitions(test_squashfs_extract PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_extract.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/squashfs_extract_output")
add_test(NAME squashfs_extract COMMAND test_squashfs_extract)

add_executable(test_squashfs_xz tests/extract/test_squashfs_xz.c)
target_include_directories(test_squashfs_xz PRIVATE src/extract)
target_link_libraries(test_squashfs_xz PRIVATE crimp)
target_compile_definitions(test_squashfs_xz PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_xz.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/squashfs_xz_output")
add_test(NAME squashfs_xz COMMAND test_squashfs_xz)

add_executable(test_squashfs_mutation_sweep tests/extract/test_squashfs_mutation_sweep.c)
target_include_directories(test_squashfs_mutation_sweep PRIVATE src/extract)
target_link_libraries(test_squashfs_mutation_sweep PRIVATE crimp)
target_compile_definitions(test_squashfs_mutation_sweep PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_extract.img"
    WORK_FILE="${CMAKE_CURRENT_BINARY_DIR}/squashfs_mutation_work.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/squashfs_mutation_output")
add_test(NAME squashfs_mutation_sweep COMMAND test_squashfs_mutation_sweep)

add_executable(test_cramfs_extract tests/extract/test_cramfs_extract.c)
target_include_directories(test_cramfs_extract PRIVATE src/extract)
target_link_libraries(test_cramfs_extract PRIVATE crimp)
target_compile_definitions(test_cramfs_extract PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/cramfs_extract.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/cramfs_extract_output")
add_test(NAME cramfs_extract COMMAND test_cramfs_extract)

add_executable(test_cramfs_endian tests/extract/test_cramfs_endian.c)
target_include_directories(test_cramfs_endian PRIVATE src/extract)
target_link_libraries(test_cramfs_endian PRIVATE crimp)
add_test(NAME cramfs_endian COMMAND test_cramfs_endian)

add_executable(test_cramfs_synthetic tests/extract/test_cramfs_synthetic.c)
target_include_directories(test_cramfs_synthetic PRIVATE src/extract)
target_link_libraries(test_cramfs_synthetic PRIVATE crimp)
add_test(NAME cramfs_synthetic COMMAND test_cramfs_synthetic)

add_executable(test_jffs2_extract tests/extract/test_jffs2_extract.c)
target_include_directories(test_jffs2_extract PRIVATE src/extract)
target_link_libraries(test_jffs2_extract PRIVATE crimp)
target_compile_definitions(test_jffs2_extract PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/jffs2_extract.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/jffs2_extract_output")
add_test(NAME jffs2_extract COMMAND test_jffs2_extract)

add_executable(test_jffs2_endian tests/extract/test_jffs2_endian.c)
target_include_directories(test_jffs2_endian PRIVATE src/extract)
target_link_libraries(test_jffs2_endian PRIVATE crimp)
add_test(NAME jffs2_endian COMMAND test_jffs2_endian)

add_executable(test_jffs2_mutation_sweep tests/extract/test_jffs2_mutation_sweep.c)
target_include_directories(test_jffs2_mutation_sweep PRIVATE src/extract)
target_link_libraries(test_jffs2_mutation_sweep PRIVATE crimp)
target_compile_definitions(test_jffs2_mutation_sweep PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/jffs2_extract.img"
    WORK_FILE="${CMAKE_CURRENT_BINARY_DIR}/jffs2_mutation_work.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/jffs2_mutation_output")
add_test(NAME jffs2_mutation_sweep COMMAND test_jffs2_mutation_sweep)

add_executable(test_squashfs_mutation_sweep_xz tests/extract/test_squashfs_mutation_sweep.c)
target_include_directories(test_squashfs_mutation_sweep_xz PRIVATE src/extract)
target_link_libraries(test_squashfs_mutation_sweep_xz PRIVATE crimp)
target_compile_definitions(test_squashfs_mutation_sweep_xz PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/squashfs_xz.img"
    WORK_FILE="${CMAKE_CURRENT_BINARY_DIR}/squashfs_mutation_work_xz.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/squashfs_mutation_output_xz")
add_test(NAME squashfs_mutation_sweep_xz COMMAND test_squashfs_mutation_sweep_xz)

add_executable(test_cramfs_mutation_sweep tests/extract/test_cramfs_mutation_sweep.c)
target_include_directories(test_cramfs_mutation_sweep PRIVATE src/extract)
target_link_libraries(test_cramfs_mutation_sweep PRIVATE crimp)
target_compile_definitions(test_cramfs_mutation_sweep PRIVATE
    FIXTURE_PATH="${CMAKE_SOURCE_DIR}/tests/fixtures/cramfs_extract.img"
    WORK_FILE="${CMAKE_CURRENT_BINARY_DIR}/cramfs_mutation_work.img"
    OUTPUT_DIR="${CMAKE_CURRENT_BINARY_DIR}/cramfs_mutation_output")
add_test(NAME cramfs_mutation_sweep COMMAND test_cramfs_mutation_sweep)

add_executable(spike_capstone_test spike/capstone-test/test_disasm.c)
target_link_libraries(spike_capstone_test PRIVATE capstone::capstone)

add_executable(spike_unicorn_test spike/unicorn-test/test_emulate.c)
target_link_libraries(spike_unicorn_test PRIVATE PkgConfig::UNICORN)
