cmake_minimum_required(VERSION 3.9)
project(5_aws)

set(CMAKE_C_STANDARD 11)

add_subdirectory(util)
add_subdirectory(checker-lin)

add_executable(aws aws.c $<TARGET_OBJECTS:sock_util.o>)
target_compile_definitions(aws PUBLIC -DDEBUG -DLOG_LEVEL=LOG_DEBUG)
target_include_directories(aws PRIVATE util util/lin)