cmake_minimum_required(VERSION 3.1)
project(sigmaker C CXX)

set(IDA_ENABLE_QT_SUPPORT ON CACHE BOOL "")
include("ida-cmake/cmake/IDA.cmake")

list(APPEND HEADERS
    "src/Core.hpp"
    "src/PluginConfig.hpp"
    "src/Settings.hpp"
    "src/Utils.hpp"
)

list(APPEND SOURCES
    "src/Core.cpp"
    "src/Settings.cpp"
    "src/sigmaker.cpp"
)

# Add IDA plugin target
#include_directories("src")
add_ida_qt_plugin(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC "/wd4267")
