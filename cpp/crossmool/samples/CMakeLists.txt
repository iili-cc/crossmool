cmake_minimum_required(VERSION 3.20)

# 用户快速上手示例程序（Sample）
add_executable(sm2_sample SM2Sample.cpp)
target_link_libraries(sm2_sample PRIVATE crossmool)

add_executable(sm3_sample SM3Sample.cpp)
target_link_libraries(sm3_sample PRIVATE crossmool)

add_executable(sm4_sample SM4Sample.cpp)
target_link_libraries(sm4_sample PRIVATE crossmool)

message(STATUS "Samples configured")
