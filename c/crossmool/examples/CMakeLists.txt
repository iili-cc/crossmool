cmake_minimum_required(VERSION 3.20)

# 示例程序
add_executable(example_sm2 example_sm2.c)
target_link_libraries(example_sm2 PRIVATE crossmool::crossmool)
add_executable(example_sm3 example_sm3.c)
target_link_libraries(example_sm3 PRIVATE crossmool::crossmool)
add_executable(example_sm4 example_sm4.c)
target_link_libraries(example_sm4 PRIVATE crossmool::crossmool)
add_executable(example_interop example_interop.c)
target_link_libraries(example_interop PRIVATE crossmool::crossmool)
message(STATUS "Examples configured")