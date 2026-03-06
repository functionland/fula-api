cmake_minimum_required(VERSION 3.14)
project(fula_flutter VERSION 0.1.0 LANGUAGES C)

# Pre-built DLL path (downloaded from GitHub Releases or built locally)
set(FULA_DLL "${CMAKE_CURRENT_SOURCE_DIR}/fula_flutter.dll")

if(EXISTS "${FULA_DLL}")
  # Install the pre-built DLL to the Flutter app's build output
  install(FILES "${FULA_DLL}" DESTINATION "${CMAKE_INSTALL_PREFIX}")
else()
  # Option: build from source if DLL not found and BUILD_FROM_SOURCE is set
  option(BUILD_FROM_SOURCE "Build fula_flutter from Rust source" OFF)

  if(BUILD_FROM_SOURCE)
    # Find the workspace root (3 levels up from windows/)
    get_filename_component(WORKSPACE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)

    add_custom_command(
      OUTPUT "${WORKSPACE_ROOT}/target/release/fula_flutter.dll"
      COMMAND cargo build -p fula-flutter --release
      WORKING_DIRECTORY "${WORKSPACE_ROOT}"
      COMMENT "Building fula_flutter from Rust source..."
    )

    add_custom_target(build_fula_flutter ALL
      DEPENDS "${WORKSPACE_ROOT}/target/release/fula_flutter.dll"
    )

    install(
      FILES "${WORKSPACE_ROOT}/target/release/fula_flutter.dll"
      DESTINATION "${CMAKE_INSTALL_PREFIX}"
    )
  else()
    message(FATAL_ERROR
      "fula_flutter.dll not found at ${FULA_DLL}. "
      "Download it from GitHub Releases and place it in the windows/ directory, "
      "or set -DBUILD_FROM_SOURCE=ON to build from Rust source."
    )
  endif()
endif()
