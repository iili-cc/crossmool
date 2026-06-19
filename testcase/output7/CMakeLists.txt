cmake_minimum_required(VERSION 3.20)
project(multi_self_test LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options(/utf-8 /MD /EHsc)
    add_definitions(-DUSE_GMSSL)
endif()

# GmSSL paths
set(GMSSL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/gmssl_install")
set(GMSSL_INC "${GMSSL_DIR}/include")
set(GMSSL_LIB "${GMSSL_DIR}/lib/gmssl.lib")
set(GMSSL_DLL "${GMSSL_DIR}/bin/gmssl.dll")

# ============================================
# C self-test target
# ============================================
set(CROSSMOOL_C_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/error.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/util_hex.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/util_base64.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/util_string.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/sm2.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/sm3.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/src/sm4.c"
)
add_executable(c_self_test c_self_test.c ${CROSSMOOL_C_SRC})
target_include_directories(c_self_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/include"
    "${GMSSL_INC}"
)
target_link_libraries(c_self_test PRIVATE "${GMSSL_LIB}")
add_custom_command(TARGET c_self_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${GMSSL_DLL}" "$<TARGET_FILE_DIR:c_self_test>"
)

# ============================================
# C++ self-test target
# ============================================
set(CROSSMOOL_CPP_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/src/SM2Util.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/src/SM3Util.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/src/SM4Util.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/utils/Base64Util.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/utils/HexUtil.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/utils/StringUtil.cpp"
)
add_executable(cpp_self_test cpp_self_test.cpp ${CROSSMOOL_C_SRC} ${CROSSMOOL_CPP_SRC})
target_include_directories(cpp_self_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../../c/crossmool/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../cpp/crossmool/utils"
    "${GMSSL_INC}"
)
target_link_libraries(cpp_self_test PRIVATE "${GMSSL_LIB}")
add_custom_command(TARGET cpp_self_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${GMSSL_DLL}" "$<TARGET_FILE_DIR:cpp_self_test>"
)
