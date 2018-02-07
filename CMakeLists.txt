cmake_minimum_required(VERSION 3.1)
project(sigmaker C CXX)

include("ida-cmake/cmake/IDA.cmake")

list(APPEND HEADERS
    "${CMAKE_CURRENT_LIST_DIR}/src/Includes.h"
    "${CMAKE_CURRENT_LIST_DIR}/src/Misc.h")

list(APPEND SOURCES
    "${CMAKE_CURRENT_LIST_DIR}/src/Converter.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/src/Generate.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/src/Main.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/src/Misc.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/src/Platform.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/src/Search.cpp")

# Add IDA plugin target
include_directories("src")
add_ida_plugin(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC "-std=c++11")