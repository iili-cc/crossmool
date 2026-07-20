cmake_minimum_required(VERSION 3.20)
project(crossmool-c VERSION 1.0.0 LANGUAGES C)
# 设置 C 语言标准为 C17
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
# MSVC 全局 /utf-8 选项（必须放在 add_executable/add_library 之前）
# 同时强制使用 /MD（Release CRT），与 gmssl.dll 保持一致，
# 避免 Debug(/MDd) vs Release(/MD) CRT 混用导致 fprintf(stderr) 崩溃
if(MSVC)
    add_compile_options(/utf-8 /MD)
    # 覆盖 CMake 默认在 Debug 模式下注入的 /MDd
    foreach(flag_var
        CMAKE_C_FLAGS_DEBUG CMAKE_CXX_FLAGS_DEBUG
        CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_CXX_FLAGS_RELWITHDEBINFO)
        if(${flag_var} MATCHES "/MDd")
            string(REGEX REPLACE "/MDd" "/MD" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
endif()
# 配置选项
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test executables" ON)
option(BUILD_SAMPLES "Build sample programs" ON)
# 查找 GmSSL 包 - 手动配置
# 由于 GmSSL 没有提供 CMake 配置文件，我们手动指定路径
# 默认使用项目目录下的 gmssl_install 文件夹
set(GMSSL_INSTALL_DIR "${CMAKE_SOURCE_DIR}/gmssl_install")
set(GMSSL_INCLUDE_DIR "${GMSSL_INSTALL_DIR}/include")
# 根据编译器类型选择导入库文件格式
if(MSVC)
    # MSVC: 使用 .lib + .dll
    set(GMSSL_LIBRARY "${GMSSL_INSTALL_DIR}/lib/gmssl.lib")
    set(GMSSL_DLL     "${GMSSL_INSTALL_DIR}/bin/gmssl.dll")
else()
    # MinGW/GCC: 使用 .dll.a + .dll
    set(GMSSL_LIBRARY "${GMSSL_INSTALL_DIR}/lib/libgmssl.dll.a")
    set(GMSSL_DLL     "${GMSSL_INSTALL_DIR}/bin/libgmssl.dll")
endif()
message(STATUS "GMSSL_INSTALL_DIR: ${GMSSL_INSTALL_DIR}")
message(STATUS "GMSSL_INCLUDE_DIR: ${GMSSL_INCLUDE_DIR}")
message(STATUS "GMSSL_LIBRARY: ${GMSSL_LIBRARY}")
# 验证 GmSSL 文件是否存在
if(NOT EXISTS "${GMSSL_INCLUDE_DIR}/gmssl/sm2.h")
    message(FATAL_ERROR "GmSSL headers not found at ${GMSSL_INCLUDE_DIR}")
endif()
if(NOT EXISTS "${GMSSL_LIBRARY}")
    message(FATAL_ERROR "GmSSL library not found at ${GMSSL_LIBRARY}")
endif()
# 创建 GmSSL 导入目标
add_library(gmssl::gmssl SHARED IMPORTED)
set_target_properties(gmssl::gmssl PROPERTIES
    IMPORTED_LOCATION "${GMSSL_DLL}"
    IMPORTED_IMPLIB "${GMSSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${GMSSL_INCLUDE_DIR}"
)
message(STATUS "Found GmSSL at ${GMSSL_INSTALL_DIR}")
# 定义库目标
add_library(crossmool
    src/error.c
    src/util_hex.c
    src/util_base64.c
    src/util_string.c
    src/sm2.c
    src/sm3.c
    src/sm4.c
)
# 设置库的别名
add_library(crossmool::crossmool ALIAS crossmool)
# MSVC 下自动导出所有公共符号（等效于 MinGW 的默认行为）
set_target_properties(crossmool PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
# 包含目录
target_include_directories(crossmool
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${GMSSL_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:include>
)
# 链接 GmSSL 库
target_link_libraries(crossmool
    PUBLIC
        gmssl::gmssl
)
# MinGW 需要额外的链接选项来正确链接 DLL
if(MINGW)
    target_link_options(crossmool PRIVATE -Wl,-rpath,"${GMSSL_INSTALL_DIR}/bin")
endif()
# 设置编译定义
target_compile_definitions(crossmool
    PUBLIC
        DEBUG=0
    PRIVATE
        CROSSMOOL_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
        CROSSMOOL_VERSION_MINOR=${PROJECT_VERSION_MINOR}
        CROSSMOOL_VERSION_PATCH=${PROJECT_VERSION_PATCH}
)
# 跨平台编译选项
if(MSVC)
    # MSVC 特定选项（/utf-8 已在全局配置）
    target_compile_options(crossmool PRIVATE /W4)
else()
    # GCC/Clang 特定选项
    target_compile_options(crossmool PRIVATE -Wall -Wextra -Wpedantic)
endif()
# 安装配置
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
# 安装头文件
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
# 安装库
install(TARGETS crossmool
    EXPORT crossmool-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
# 生成并安装 CMake 配置文件
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/crossmool-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crossmool
)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crossmool
)
install(EXPORT crossmool-targets
    FILE crossmool-targets.cmake
    NAMESPACE crossmool::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/crossmool
)
# 生成 pkg-config 文件
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/crossmool.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/crossmool.pc
    @ONLY
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/crossmool.pc
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig
)
# 测试
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
# 用户快速上手示例程序
if(BUILD_SAMPLES)
    add_subdirectory(samples)
endif()
message(STATUS "crossmool-c ${PROJECT_VERSION} configured successfully")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  Tests: ${BUILD_TESTS}")
message(STATUS "  Samples: ${BUILD_SAMPLES}")