set(INCLUDE_DIRS ${CMAKE_SOURCE_DIR})

if(NOT CRYPTO_LIB)
    message(FATAL_ERROR "CRYPTO_LIB is not defined")
endif()

function(add_blake3)
  CPMAddPackage(
    NAME BLAKE3-cmake
    GITHUB_REPOSITORY 25077667/BLAKE3-cmake
    GIT_TAG 1.4.0
  )
  set(BLAKE3_INCLUDE_DIR ${CMAKE_BINARY_DIR}/_deps/blake3-src/c/)
  set(BLAKE3_LIBRARY ${CMAKE_BINARY_DIR}/_deps/blake3-build/libblake3.a)

  set(INCLUDE_DIRS ${INCLUDE_DIRS} ${BLAKE3_INCLUDE_DIR} PARENT_SCOPE)
  set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} ${BLAKE3_LIBRARY} PARENT_SCOPE)
endfunction(add_blake3)

function(add_botan)
    # print compiler name and version
    message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
    set(SOURCE_FILES botan.cpp PARENT_SCOPE)
    # Add botan as a dependency
    CPMAddPackage(
        NAME botan-cmake
        GIT_TAG 3.0.0-rc3
        GITHUB_REPOSITORY "25077667/botan-cmake"
    )
    # Set botan include directory variable, link botan library
    set(BOTAN_INCLUDE_DIR ${CMAKE_BINARY_DIR}/_deps/botan-src/build/include/)
    set(BOTAN_LIBRARY ${CMAKE_BINARY_DIR}/_deps/botan-src/libbotan-3.a)

    # Append botan include directory to include directories
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${BOTAN_INCLUDE_DIR} PARENT_SCOPE)
    # Append botan library to libraries
    set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} ${BOTAN_LIBRARY} PARENT_SCOPE)
endfunction(add_botan)

function(add_openssl)
    find_package(OpenSSL STATIC REQUIRED)
    set(SOURCE_FILES openssl.cpp PARENT_SCOPE)
    set(INCLUDE_DIRS ${INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR} PARENT_SCOPE)
    set(THIRD_PARTY_LIBS ${THIRD_PARTY_LIBS} ${OPENSSL_LIBRARIES} PARENT_SCOPE)
endfunction(add_openssl)

function(add_sodium)
    message(STATUS "Welcome to pull request to add libsodium support")
    message(FATAL_ERROR "libsodium is not supported now")
endfunction(add_sodium)

if(CRYPTO_LIB STREQUAL "Botan")
    add_botan()
elseif(CRYPTO_LIB STREQUAL "OpenSSL")
    add_openssl()
elseif(CRYPTO_LIB STREQUAL "libsodium")
    add_sodium()
else()
    message(FATAL_ERROR "CRYPTO_LIB is not defined")
endif()

add_blake3()

include_directories(${INCLUDE_DIRS} ${THIRD_PARTY_LIBS})

# Add the library static linked to the source file
add_library(crypto STATIC ${SOURCE_FILES})
target_link_libraries(crypto ${THIRD_PARTY_LIBS})

# Copy crypto library to CMAKE_BINARY_DIR
add_custom_command(TARGET crypto POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:crypto> ${CMAKE_BINARY_DIR}
)
