cmake_minimum_required(VERSION 3.20)

# 用户快速上手示例程序（Sample）
add_executable(sm2_sample sm2_sample.c)
target_link_libraries(sm2_sample PRIVATE crossmool::crossmool)
add_executable(sm3_sample sm3_sample.c)
target_link_libraries(sm3_sample PRIVATE crossmool::crossmool)
add_executable(sm4_sample sm4_sample.c)
target_link_libraries(sm4_sample PRIVATE crossmool::crossmool)
add_executable(interop_sample interop_sample.c)
target_link_libraries(interop_sample PRIVATE crossmool::crossmool)
message(STATUS "Samples configured")
