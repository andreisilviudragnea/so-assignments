add_compile_options(-Wall)
add_library(sockop_preload SHARED sockop_preload.c)
target_link_libraries(sockop_preload -nostdlib -lc -ldl)