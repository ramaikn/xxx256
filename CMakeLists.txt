cmake_minimum_required(VERSION 3.16)

project(xxx256 VERSION 3.0.0 LANGUAGES C)

include(CheckSymbolExists)
check_symbol_exists(explicit_bzero "string.h" XXX256_HAVE_EXPLICIT_BZERO)

add_library(xxx256 STATIC
    src/xxx256_api.c
    src/xxx256_core.c
    src/xxx256_envelope.c
    src/xxx256_permutation.c
    src/xxx256_random.c
)

target_include_directories(xxx256
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(xxx256 PUBLIC c_std_99)

if(XXX256_HAVE_EXPLICIT_BZERO)
    target_compile_definitions(xxx256 PRIVATE XXX256_HAVE_EXPLICIT_BZERO=1)
endif()

if(MSVC)
    target_compile_options(xxx256 PRIVATE /W4 /permissive-)
else()
    target_compile_options(xxx256 PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

if(WIN32)
    target_link_libraries(xxx256 PRIVATE bcrypt)
endif()

option(XXX256_BUILD_INDEPENDENT "Build the independent validation implementation" ON)

if(XXX256_BUILD_INDEPENDENT)
    add_library(xxx256_independent STATIC
        independent/xxx256_independent.c
    )
    target_include_directories(xxx256_independent
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/independent
    )
    target_compile_features(xxx256_independent PUBLIC c_std_99)
    if(MSVC)
        target_compile_options(xxx256_independent PRIVATE /W4 /permissive-)
    else()
        target_compile_options(xxx256_independent PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    endif()
endif()

option(XXX256_BUILD_TOOLS "Build reproducibility tools" ON)
if(XXX256_BUILD_TOOLS)
    add_executable(xxx256_generate_tables tools/generate_tables.c)
    target_compile_features(xxx256_generate_tables PRIVATE c_std_99)

    add_executable(xxx256_benchmark tools/benchmark.c)
    target_link_libraries(xxx256_benchmark PRIVATE xxx256)
endif()

option(XXX256_BUILD_EXAMPLES "Build usage examples" ON)
if(XXX256_BUILD_EXAMPLES)
    add_executable(xxx256_basic_example examples/basic.c)
    target_link_libraries(xxx256_basic_example PRIVATE xxx256)
endif()

include(CTest)
if(BUILD_TESTING AND XXX256_BUILD_INDEPENDENT)
    add_executable(xxx256_tests tests/test_xxx256.c)
    target_link_libraries(xxx256_tests PRIVATE xxx256 xxx256_independent)
    add_test(NAME xxx256_tests COMMAND xxx256_tests)
endif()
