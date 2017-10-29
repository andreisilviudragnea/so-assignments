cmake_minimum_required(VERSION 3.8.2)
project(5_aws)

set(CMAKE_C_STANDARD 11)

add_subdirectory(util)
add_subdirectory(checker-lin)

add_executable(aws aws.c $<TARGET_OBJECTS:sock_util.o> $<TARGET_OBJECTS:http_parser.o> util/aws.h)
#target_compile_options(aws PRIVATE -g)
target_compile_definitions(aws PRIVATE -DDEBUG -DLOG_LEVEL=LOG_DEBUG)
target_include_directories(aws PRIVATE util util/lin util/http-parser)