project(awgip)

add_executable(awgip src/server.c)
target_link_libraries(awgip crypto ssl)