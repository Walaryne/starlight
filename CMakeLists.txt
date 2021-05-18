cmake_minimum_required(VERSION 3.15)
project(starlight)

set(CMAKE_CXX_STANDARD 17)

add_library(starlight SHARED library.cpp library.h offsets.h)
target_link_libraries(starlight dl pthread)