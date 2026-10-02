cmake_minimum_required(VERSION 3.20)

# Copy runtime DLLs next to test executables (generator-agnostic:
# $<TARGET_FILE:...> works for both multi-config (VS) and single-config (Ninja) generators)
function(add_dll_copy target_name)
    add_custom_command(TARGET ${target_name} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:crossmool>"
            "$<TARGET_FILE_DIR:${target_name}>"
        COMMENT "Copy crossmool.dll for ${target_name}"
    )
    if(EXISTS "${GMSSL_ROOT}/bin/gmssl.dll")
        add_custom_command(TARGET ${target_name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${GMSSL_ROOT}/bin/gmssl.dll"
                "$<TARGET_FILE_DIR:${target_name}>"
            COMMENT "Copy gmssl.dll for ${target_name}"
        )
    endif()
endfunction()

# Core comprehensive test (covers all SM2/SM3/SM4/Util APIs)
add_executable(test_all test_all.c)
target_link_libraries(test_all PRIVATE crossmool::crossmool)
add_dll_copy(test_all)
add_test(NAME TestAll COMMAND test_all)

message(STATUS "Tests configured: test_all (SM2+SM3+SM4+Util comprehensive)")
