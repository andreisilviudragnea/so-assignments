add_compile_options(-O3 -Wall -Wextra -g)
include_directories(..)
add_executable(test_get_request_path test_get_request_path.c $<TARGET_OBJECTS:http_parser.o>)