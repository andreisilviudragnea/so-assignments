cmake_minimum_required(VERSION 3.10)

project(scheduler)

add_compile_options(/nologo /W3 /EHsc)

add_subdirectory(checker-win)

include_directories(util)
add_library(so_sheduler SHARED so_sheduler.c util/so_scheduler.h)

add_executable(run_test $<TARGET_OBJECTS:objects>)
target_link_libraries(run_test so_sheduler)
