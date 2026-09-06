cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfssl_els_pkc)
target_sources(app PRIVATE src/main.c)
# the offload counters this sample asserts on are opt-in
zephyr_compile_definitions(WOLFSSL_ELS_PKC_COUNTERS)
target_link_libraries(app PRIVATE wolfSSL)
