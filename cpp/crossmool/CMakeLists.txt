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

# Resolve GmSSL paths (command-line override takes priority)
if(NOT GMSSL_LIBRARIES)
    find_library(GMSSL_LIBRARIES NAMES gmssl
        PATHS
            "${GMSSL_SIBLING_DIR}/lib"
            "C:/Program Files/GmSSL/lib"
            "C:/Program Files (x86)/GmSSL/lib"
        NO_DEFAULT_PATH
    )
endif()
if(NOT GMSSL_INCLUDE_DIRS)
    find_path(GMSSL_INCLUDE_DIRS NAMES gmssl/sm2.h
        PATHS
            "${GMSSL_SIBLING_DIR}/include"
            "C:/Program Files/GmSSL/include"
            "C:/Program Files (x86)/GmSSL/include"
        NO_DEFAULT_PATH
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
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/utils
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
add_executable(crossmool_test tests/test_all.cpp)

target_link_libraries(crossmool_test PRIVATE crossmool)

# 用户快速上手示例程序
if(BUILD_SAMPLES)
    add_subdirectory(samples)
endif()

# Install targets
install(TARGETS crossmool
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin)

install(DIRECTORY include/
    DESTINATION include/crossmool)

# Enable testing
enable_testing()
add_test(NAME crossmool_test COMMAND crossmool_test)
