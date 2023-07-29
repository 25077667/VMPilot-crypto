cmake_minimum_required(VERSION 3.20)

project(VMPilot-crypto)

set(CMAKE_CXX_STANDARD 20)

# Setup default variables
# Set default values for compile options
set(CRYPTO_LIB "Botan" CACHE STRING "The backend crypto library")
set_property(CACHE CRYPTO_LIB PROPERTY STRINGS "Botan" "OpenSSL" "libsodium")

set(CMAKE_LINKER "ld" CACHE STRING "The linker")
set_property(CACHE CMAKE_LINKER PROPERTY STRINGS "ld" "mold" "lld" "gold")

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -O0 -g)
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    add_compile_options(/W4 /WX /Od /Zi)
endif ()

include(cmake/CPM.cmake)

# Add subdirectories
add_subdirectory(src)