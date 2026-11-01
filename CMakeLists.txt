cmake_minimum_required(VERSION 3.12)
project(PacketSniffer C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Werror -O3 -g -D_GNU_SOURCE -pipe)

include_directories(include src/headers src/globals)

set(CORE_SOURCES
    src/core/capture.c
    src/parser/parser.c
    src/parser/checksum.c
    src/filter/filter.c
    src/analytics/analytics.c
    src/printer/printer.c
    src/pcap/pcap.c
)

# Core Library
add_library(sniffer_core STATIC ${CORE_SOURCES})

# Main Sniffer Executable
add_executable(sniffer src/main/sniffer.c)
target_link_libraries(sniffer sniffer_core)

# Unit Tests Executable
add_executable(test_runner tests/test_runner.c)
target_link_libraries(test_runner sniffer_core)

# Benchmark Executable
add_executable(benchmark benchmarks/benchmark.c)
target_link_libraries(benchmark sniffer_core)

enable_testing()
add_test(NAME SnifferUnitTests COMMAND test_runner)
