cmake_minimum_required(VERSION 3.20)

project(crossmool-cpp VERSION 1.3.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Force MSVC to use UTF-8 source/execution charset so Chinese comments compile correctly
if(MSVC)
    add_compile_options(/utf-8)
endif()

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Option to use system GmSSL or build with bundled implementation
option(USE_SYSTEM_GMSSL "Use system-installed GmSSL library" ON)
option(BUILD_SAMPLES "Build sample programs" ON)

# Sibling GmSSL install path (relative to this project - used when GmSSL is not in system path)
set(GMSSL_SIBLING_DIR "${PROJECT_SOURCE_DIR}/../../c/crossmool/gmssl_install")

# GmSSL root resolution priority:
#   1. -DGMSSL_ROOT=<prefix> (vcpkg / CI / custom install, contains include/ and lib/)
#   2. default CMake search paths (CMAKE_PREFIX_PATH, e.g. vcpkg installed tree)
#   3. sibling gmssl_install directory (local development)
set(GMSSL_ROOT "" CACHE PATH "GmSSL installation prefix (contains include/ and lib/)")

# Resolve GmSSL paths (command-line variable takes priority)
if(NOT GMSSL_LIBRARIES)
    find_library(GMSSL_LIBRARIES NAMES gmssl
        HINTS
            "${GMSSL_ROOT}/lib"
            "${GMSSL_SIBLING_DIR}/lib"
    )
endif()
if(NOT GMSSL_INCLUDE_DIRS)
    find_path(GMSSL_INCLUDE_DIRS NAMES gmssl/sm2.h
        HINTS
            "${GMSSL_ROOT}/include"
            "${GMSSL_SIBLING_DIR}/include"
    )
endif()

if(USE_SYSTEM_GMSSL AND GMSSL_LIBRARIES AND GMSSL_INCLUDE_DIRS)
    set(GMSSL_FOUND TRUE)
    message(STATUS "GmSSL found: lib=${GMSSL_LIBRARIES}, include=${GMSSL_INCLUDE_DIRS}")
else()
    message(WARNING "GmSSL not found. Building with stub implementations. GMSSL_LIBRARIES=${GMSSL_LIBRARIES}, GMSSL_INCLUDE_DIRS=${GMSSL_INCLUDE_DIRS}")
    set(USE_SYSTEM_GMSSL OFF)
    set(GMSSL_FOUND FALSE)
endif()

# Define library target
add_library(crossmool
    utils/Base64Util.cpp
    utils/HexUtil.cpp
    utils/StringUtil.cpp
    src/SM2Util.cpp
    src/SM3Util.cpp
    src/SM4Util.cpp
)

target_include_directories(crossmool PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/utils>
    $<INSTALL_INTERFACE:include>
)

if(USE_SYSTEM_GMSSL AND GMSSL_FOUND)
    target_include_directories(crossmool PUBLIC ${GMSSL_INCLUDE_DIRS})
    target_link_libraries(crossmool PRIVATE ${GMSSL_LIBRARIES})
    target_compile_definitions(crossmool PRIVATE USE_GMSSL=1)
    message(STATUS "crossmool will be compiled with USE_GMSSL=1")
else()
    # Define stub implementations
    target_compile_definitions(crossmool PRIVATE USE_STUB_IMPLEMENTATION=1)
    message(STATUS "crossmool will be compiled with stub implementations")
endif()

# Create executables for testing
option(BUILD_TESTS "Build test executables" ON)
if(BUILD_TESTS)
    add_executable(crossmool_test tests/test_all.cpp)
    target_link_libraries(crossmool_test PRIVATE crossmool)
endif()

# User quick-start sample programs
if(BUILD_SAMPLES)
    add_subdirectory(samples)
endif()

# Install targets (standard GNU layout + CMake package export)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS crossmool
    EXPORT crossmool-cpp-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/crossmool-cpp-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-cpp-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crossmool-cpp
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-cpp-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-cpp-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-cpp-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crossmool-cpp
)
install(EXPORT crossmool-cpp-targets
    FILE crossmool-cpp-targets.cmake
    NAMESPACE crossmoolcpp::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crossmool-cpp
)

# Enable testing
if(BUILD_TESTS)
    enable_testing()
    add_test(NAME crossmool_test COMMAND crossmool_test)
endif()
