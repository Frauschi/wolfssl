cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(els_sfr_trace)

target_sources(app PRIVATE src/main.c src/els_trace.c)

# Interpose on every ELS register access inside the vendor library. All of them
# go through six macros in one header, so redefining those is enough and no NXP
# file is edited.
target_compile_options(McuxElsPkc PRIVATE
    -include ${CMAKE_CURRENT_SOURCE_DIR}/src/els_sfr_trace.h)
target_include_directories(McuxElsPkc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
