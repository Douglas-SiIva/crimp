cmake_minimum_required(VERSION 3.21)
project(crimp LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(capstone CONFIG REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(UNICORN REQUIRED IMPORTED_TARGET unicorn)

add_executable(spike_capstone_test spike/capstone-test/test_disasm.c)
target_link_libraries(spike_capstone_test PRIVATE capstone::capstone)

add_executable(spike_unicorn_test spike/unicorn-test/test_emulate.c)
target_link_libraries(spike_unicorn_test PRIVATE PkgConfig::UNICORN)
