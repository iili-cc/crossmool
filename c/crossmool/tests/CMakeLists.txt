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

# 核心综合测试（覆盖 SM2/SM3/SM4/Util 全部 API）
add_executable(test_all test_all.c)
target_link_libraries(test_all PRIVATE crossmool::crossmool)
add_dll_copy(test_all)
add_test(NAME TestAll COMMAND test_all)

message(STATUS "Tests configured: test_all (SM2+SM3+SM4+Util comprehensive)")