cmake_minimum_required(VERSION 3.22)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

project(myTest)

find_library(LIBURING NAMES liburing)

add_executable(test test.cpp)

target_link_libraries(test ${LIBURING})