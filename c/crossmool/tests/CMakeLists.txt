cmake_minimum_required(VERSION 3.20)

# DLL 路径（使用生成器表达式）
set(DLL_DIR "${CMAKE_BINARY_DIR}/$<CONFIG>")
set(GMSSL_DLL "${CMAKE_SOURCE_DIR}/gmssl_install/bin/gmssl.dll")

# 辅助函数：创建复制 DLL 的自定义命令
function(add_dll_copy target_name)
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${DLL_DIR}/crossmool.dll"
            "$<TARGET_FILE_DIR:${target_name}>"
        COMMENT "Copy crossmool.dll for ${target_name}"
    )
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${GMSSL_DLL}"
            "$<TARGET_FILE_DIR:${target_name}>"
        COMMENT "Copy gmssl.dll for ${target_name}"
    )
endfunction()

# 单元测试
add_executable(sm2_test test_sm2_v2.c)
target_link_libraries(sm2_test PRIVATE crossmool::crossmool)
add_test(NAME SM2Test COMMAND sm2_test)
add_dll_copy(sm2_test)
add_executable(sm3_test test_sm3.c)
target_link_libraries(sm3_test PRIVATE crossmool::crossmool)
add_test(NAME SM3Test COMMAND sm3_test)
add_dll_copy(sm3_test)

add_executable(sm4_test test_sm4.c)
target_link_libraries(sm4_test PRIVATE crossmool::crossmool)
add_test(NAME SM4Test COMMAND sm4_test)
add_dll_copy(sm4_test)

add_executable(util_test test_util.c)
target_link_libraries(util_test PRIVATE crossmool::crossmool)
add_test(NAME UtilTest COMMAND util_test)
add_dll_copy(util_test)

# 互通性测试
add_executable(interop_test test_interop.c)
target_link_libraries(interop_test PRIVATE crossmool::crossmool)
add_test(NAME InteropTest COMMAND interop_test)
add_dll_copy(interop_test)

# 跨语言互通性测试（使用 Java 端固定密钥）
add_executable(crosslang_test test_crosslang.c)
target_link_libraries(crosslang_test PRIVATE crossmool::crossmool)
add_test(NAME CrossLangTest COMMAND crosslang_test)
add_dll_copy(crosslang_test)

# ASN.1 解码诊断
add_executable(asn1_debug test_asn1_debug.c)
target_link_libraries(asn1_debug PRIVATE crossmool::crossmool)
add_dll_copy(asn1_debug)

message(STATUS "Tests configured")