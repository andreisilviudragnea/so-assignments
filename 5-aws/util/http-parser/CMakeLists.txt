add_subdirectory(samples)

add_definitions(-DHTTP_PARSER_STRICT=0)
include_directories(.)
add_compile_options(-O3)
add_library(http_parser.o OBJECT http_parser.c http_parser.h)