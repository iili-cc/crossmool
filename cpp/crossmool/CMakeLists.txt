cmake_minimum_required(VERSION 3.20)

project(crossmool-cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib)

# Option to use system GmSSL or build with bundled implementation
option(USE_SYSTEM_GMSSL "Use system-installed GmSSL library" ON)

if(USE_SYSTEM_GMSSL)
    # Find GmSSL library
    find_package(PkgConfig QUIET)

    # Try to find GmSSL with pkg-config first
    if(PkgConfig_FOUND)
        pkg_check_modules(GMSSL QUIET gmssl)
    endif()

    if(GMSSL_FOUND)
        message(STATUS "Found GmSSL via pkg-config: ${GMSSL_VERSION}")
    else()
        # Alternative: try find_library and find_path
        find_library(GMSSL_LIBRARIES NAMES gmssl libgmssl PATHS ENV LD_LIBRARY_PATH)
        find_path(GMSSL_INCLUDE_DIRS NAMES gmssl.h PATHS ENV CPATH PATH_SUFFIXES include)

        # On Windows, also check common installation paths
        if(WIN32)
            find_library(GMSSL_LIBRARIES NAMES gmssl libgmssl
                PATHS
                    "C:/Program Files/GmSSL/lib"
                    "C:/Program Files (x86)/GmSSL/lib"
                    "$ENV{PROGRAMFILES}/GmSSL/lib"
                    "$ENV{PROGRAMFILES(X86)}/GmSSL/lib"
                    "${PROJECT_SOURCE_DIR}/../GmSSL/build"
                    "${PROJECT_SOURCE_DIR}/../../GmSSL/build"
            )
            find_path(GMSSL_INCLUDE_DIRS NAMES gmssl.h
                PATHS
                    "C:/Program Files/GmSSL/include"
                    "C:/Program Files (x86)/GmSSL/include"
                    "$ENV{PROGRAMFILES}/GmSSL/include"
                    "$ENV{PROGRAMFILES(X86)}/GmSSL/include"
                    "${PROJECT_SOURCE_DIR}/../GmSSL/include"
                    "${PROJECT_SOURCE_DIR}/../../GmSSL/include"
                    "${PROJECT_SOURCE_DIR}/../GmSSL/build"
                    "${PROJECT_SOURCE_DIR}/../../GmSSL/build"
                PATH_SUFFIXES include
            )
        endif()

        if(GMSSL_LIBRARIES AND GMSSL_INCLUDE_DIRS)
            set(GMSSL_FOUND TRUE)
            message(STATUS "Found GmSSL: ${GMSSL_LIBRARIES}")
        else()
            message(WARNING "GmSSL not found. Building with stub implementations.")
            set(USE_SYSTEM_GMSSL OFF)
        endif()
    endif()
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

if(USE_SYSTEM_GMSSL)
    target_include_directories(crossmool PUBLIC ${GMSSL_INCLUDE_DIRS})
    target_link_libraries(crossmool PRIVATE ${GMSSL_LIBRARIES})
    target_compile_definitions(crossmool PRIVATE USE_GMSSL=1)
else()
    # Define stub implementations
    target_compile_definitions(crossmool PRIVATE USE_STUB_IMPLEMENTATION=1)
endif()

# Create executables for testing
add_executable(crossmool_test tests/main.cpp)
add_executable(interoperability_test tests/interoperability_test.cpp)
add_executable(edge_case_tests tests/edge_case_tests.cpp)

target_link_libraries(crossmool_test PRIVATE crossmool)
target_link_libraries(interoperability_test PRIVATE crossmool)
target_link_libraries(edge_case_tests PRIVATE crossmool)

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
add_test(NAME interoperability_test COMMAND interoperability_test)
add_test(NAME edge_case_tests COMMAND edge_case_tests)