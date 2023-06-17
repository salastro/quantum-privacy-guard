cmake_minimum_required(VERSION 3.0)
project(quantum_privacy_guard C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Find liboqs
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBOQS REQUIRED liboqs)

# Set source files
set(SOURCE_FILES
    src/qpg.c
    src/qpg_crypto.c
    src/qpg_utils.c)

# Define the executable
add_executable(qpg ${SOURCE_FILES})

# Include directories
target_include_directories(qpg PRIVATE include ${LIBOQS_INCLUDE_DIRS})

# Link libraries
target_link_libraries(qpg ${LIBOQS_LIBRARIES})

# Set compiler options
target_compile_options(qpg PRIVATE ${LIBOQS_CFLAGS_OTHER})

# Set linker options
target_link_libraries(qpg PRIVATE ${LIBOQS_LDFLAGS_OTHER})

# Installation
install(TARGETS qpg
        RUNTIME DESTINATION bin)

# Unit tests (optional)
option(BUILD_TESTS "Build unit tests" OFF)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
