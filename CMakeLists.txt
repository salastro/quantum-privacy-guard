cmake_minimum_required(VERSION 3.10)
project(quantum_privacy_guard C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Find liboqs ──────────────────────────────────────────────────────────────

# Try find_package first (CMake config mode), then fall back to pkg-config.
# Both paths yield an imported target that carries include dirs, link dirs and
# compile flags to everything linking qpg_lib.
find_package(liboqs 0.8.0 CONFIG QUIET)

if(liboqs_FOUND)
    message(STATUS "Found liboqs via CMake config: ${liboqs_VERSION}")
    set(OQS_TARGET OQS::oqs)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OQS REQUIRED IMPORTED_TARGET liboqs>=0.8.0)
    message(STATUS "Found liboqs via pkg-config: ${OQS_VERSION}")
    set(OQS_TARGET PkgConfig::OQS)
endif()

# ── Find OpenSSL ─────────────────────────────────────────────────────────────

find_package(OpenSSL REQUIRED)
message(STATUS "Found OpenSSL ${OPENSSL_VERSION}")

# ── Library (shared between the binary and tests) ────────────────────────────

set(QPG_LIB_SOURCES
    src/cli.c
    src/crypto_kem.c
    src/crypto_sig.c
    src/encryption.c
    src/file_io.c
    src/utils.c
)

add_library(qpg_lib STATIC ${QPG_LIB_SOURCES})

target_include_directories(qpg_lib
    PUBLIC  ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(qpg_lib
    PUBLIC  ${OQS_TARGET}
            OpenSSL::Crypto
)

# ── Main executable ──────────────────────────────────────────────────────────

add_executable(qpg src/main.c)
target_link_libraries(qpg PRIVATE qpg_lib)

# ── Installation ─────────────────────────────────────────────────────────────

install(TARGETS qpg RUNTIME DESTINATION bin)

# ── Compiler warnings ────────────────────────────────────────────────────────

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(qpg_lib PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(qpg     PRIVATE -Wall -Wextra -Wpedantic)
endif()

# ── Tests (opt-in with -DBUILD_TESTS=ON) ─────────────────────────────────────

option(BUILD_TESTS "Build the QPG test suite" OFF)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
