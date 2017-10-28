add_definitions(-DDEBUG -DLOG_LEVEL=LOG_DEBUG)
include_directories(.. ../..)
add_compile_options(-Wall -Wextra -g)

add_library(epoll_echo_server.o OBJECT epoll_echo_server.c ../sock_util.h ../../debug.h ../../util.h ../w_epoll.h)
add_executable(epoll_echo_server $<TARGET_OBJECTS:epoll_echo_server.o> $<TARGET_OBJECTS:sock_util.o>)

add_library(http_reply_once.o OBJECT http_reply_once.c ../sock_util.h ../../debug.h ../../util.h)
add_executable(http_reply_once $<TARGET_OBJECTS:http_reply_once.o> $<TARGET_OBJECTS:sock_util.o> $<TARGET_OBJECTS:http_parser.o>)