cmake_minimum_required(VERSION 3.15)
project(test_java_c_interop_sm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 查找 GmSSL
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(GMSSL QUIET gmssl)
endif()

if(NOT GMSSL_FOUND)
    # 尝试直接查找 GmSSL 库
    find_library(GMSSL_LIB NAMES gmssl libgmssl
        PATHS 
            /usr/local/lib
            /usr/lib
            "C:/Program Files/GmSSL/lib"
            "H:/Programs/GmSSL/lib"
    )
    find_path(GMSSL_INCLUDE_DIR NAMES gmssl/sm2.h gmssl/sm3.h gmssl/sm4.h
        PATHS
            /usr/local/include
            /usr/include
            "C:/Program Files/GmSSL/include"
            "H:/Programs/GmSSL/include"
    )
    
    if(GMSSL_LIB AND GMSSL_INCLUDE_DIR)
        set(GMSSL_FOUND TRUE)
        set(GMSSL_LIBRARIES ${GMSSL_LIB})
        set(GMSSL_INCLUDE_DIRS ${GMSSL_INCLUDE_DIR})
    endif()
endif()

if(NOT GMSSL_FOUND)
    message(FATAL_ERROR "GmSSL not found. Please install GmSSL first.")
endif()

message(STATUS "GmSSL found:")
message(STATUS "  Libraries: ${GMSSL_LIBRARIES}")
message(STATUS "  Include dirs: ${GMSSL_INCLUDE_DIRS}")

# 查找 crossmool C 库源文件
set(CROSSMOOL_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../c/crossmool/src")
set(CROSSMOOL_INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../c/crossmool/include")

if(NOT EXISTS "${CROSSMOOL_SRC_DIR}")
    message(FATAL_ERROR "crossmool C source directory not found: ${CROSSMOOL_SRC_DIR}")
endif()

message(STATUS "crossmool C source: ${CROSSMOOL_SRC_DIR}")
message(STATUS "crossmool C include: ${CROSSMOOL_INC_DIR}")

# 收集 crossmool 源文件
set(CROSSMOOL_SOURCES
    ${CROSSMOOL_SRC_DIR}/sm2.c
    ${CROSSMOOL_SRC_DIR}/sm3.c
    ${CROSSMOOL_SRC_DIR}/sm4.c
    ${CROSSMOOL_SRC_DIR}/util_hex.c
    ${CROSSMOOL_SRC_DIR}/util_base64.c
    ${CROSSMOOL_SRC_DIR}/util_string.c
    ${CROSSMOOL_SRC_DIR}/error.c
)

# 创建测试可执行文件
add_executable(test_java_c_interop_sm
    test_java_c_interop_sm.c
    ${CROSSMOOL_SOURCES}
)

target_include_directories(test_java_c_interop_sm PRIVATE
    ${GMSSL_INCLUDE_DIRS}
    ${CROSSMOOL_INC_DIR}
)

target_link_libraries(test_java_c_interop_sm
    ${GMSSL_LIBRARIES}
)

# Windows 特定设置
if(WIN32)
    target_compile_definitions(test_java_c_interop_sm PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# 安装目标
install(TARGETS test_java_c_interop_sm
    RUNTIME DESTINATION bin
)