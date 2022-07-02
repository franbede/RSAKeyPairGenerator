# Sets the minimum version of CMake required to build your native library.
# This ensures that a certain set of CMake features is available to
# your build.

cmake_minimum_required(VERSION 3.18.1)

# Specifies a library name, specifies whether the library is STATIC or
# SHARED, and provides relative paths to the source code. You can
# define multiple libraries by adding multiple add_library() commands,
# and CMake builds them for you. When you build your app, Gradle
# automatically packages shared libraries with your APK.

project("rsakeypairgenerator")

set(distribution_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../jni)

find_library( # Sets the name of the path variable.
        log-lib

        # Specifies the name of the NDK library that
        # you want CMake to locate.
        log )

#===v===v===v===v===v===v===openssl-include===v===v===v===v===v===v===
add_library(
        openssl
        SHARED
        IMPORTED
)

set_target_properties(
        openssl
        PROPERTIES IMPORTED_LOCATION
        ${distribution_DIR}/openssl/lib/${ANDROID_ABI}/libcrypto.so
)
#===^===^===^===^===^===^===openssl-include===^===^===^===^===^===^===
add_library( # Specifies the name of the library.
        rsakeypairgenerator
        # Sets the library as a shared library.
        SHARED
        # Provides a relative path to your source file(s).
        generate_key_pair.cpp )

target_include_directories(
        rsakeypairgenerator
        PRIVATE
        ${distribution_DIR}/openssl/include/${ANDROID_ABI})

target_link_libraries(
        rsakeypairgenerator
        openssl
        ${log-lib}
)