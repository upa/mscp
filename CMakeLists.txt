cmake_minimum_required(VERSION 3.13)

project(sscp C)

set(CMAKE_C_FLAGS "-Wall -g")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

add_executable(sscp src/main.c src/platform.c src/ssh.c src/file.c src/pprint.c)
target_include_directories(sscp PUBLIC ./src /usr/local/include)
target_link_directories(sscp PUBLIC /usr/local/lib)
target_link_libraries(sscp ssh pthread m)
