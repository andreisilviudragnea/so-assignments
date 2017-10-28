add_subdirectory(samples)

add_library(sock_util.o OBJECT sock_util.c sock_util.h ../debug.h ../util.h)
target_include_directories(sock_util.o PRIVATE ..)