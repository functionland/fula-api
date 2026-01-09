# CMake configuration for fula_flutter native library
#
# This file handles loading the pre-built Rust library for Android.
# The library is built by the CI/CD pipeline and included in the package.

cmake_minimum_required(VERSION 3.18.1)
project(fula_flutter VERSION 0.1.0 LANGUAGES C)

# Find the pre-built library based on ABI
set(FULA_LIB_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src/main/jniLibs/${ANDROID_ABI}")

# Import the pre-built shared library
add_library(fula_flutter SHARED IMPORTED)
set_target_properties(fula_flutter PROPERTIES
    IMPORTED_LOCATION "${FULA_LIB_DIR}/libfula_flutter.so"
)

# If building from source (development mode), use Cargo
# This is typically only needed during development
option(BUILD_FROM_SOURCE "Build Rust library from source" OFF)

if(BUILD_FROM_SOURCE)
    # Path to the Rust crate
    set(RUST_CRATE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../crates/fula-flutter")

    # Determine the Rust target based on Android ABI
    if(ANDROID_ABI STREQUAL "arm64-v8a")
        set(RUST_TARGET "aarch64-linux-android")
    elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
        set(RUST_TARGET "armv7-linux-androideabi")
    elseif(ANDROID_ABI STREQUAL "x86_64")
        set(RUST_TARGET "x86_64-linux-android")
    elseif(ANDROID_ABI STREQUAL "x86")
        set(RUST_TARGET "i686-linux-android")
    endif()

    # Custom command to build Rust library
    add_custom_command(
        OUTPUT "${FULA_LIB_DIR}/libfula_flutter.so"
        COMMAND cargo build --release --target ${RUST_TARGET} -p fula-flutter
        COMMAND ${CMAKE_COMMAND} -E copy
            "${RUST_CRATE_DIR}/../../target/${RUST_TARGET}/release/libfula_flutter.so"
            "${FULA_LIB_DIR}/libfula_flutter.so"
        WORKING_DIRECTORY ${RUST_CRATE_DIR}
        COMMENT "Building Rust library for ${ANDROID_ABI}"
    )

    add_custom_target(build_rust_lib DEPENDS "${FULA_LIB_DIR}/libfula_flutter.so")
    add_dependencies(fula_flutter build_rust_lib)
endif()
