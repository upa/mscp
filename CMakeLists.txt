cmake_minimum_required(VERSION 3.13)

project(mscp C)

set(CMAKE_C_FLAGS "-Wall -g")

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -DDEBUG")

add_executable(mscp src/main.c src/platform.c src/ssh.c src/file.c src/pprint.c)
target_include_directories(mscp PUBLIC ./src /usr/local/include)
target_link_directories(mscp PUBLIC /usr/local/lib)
target_link_libraries(mscp ssh pthread m)
