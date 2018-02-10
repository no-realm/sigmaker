cmake_minimum_required(VERSION 3.1)
project(sigmaker C CXX)

set(IDA_ENABLE_QT_SUPPORT ON CACHE BOOL "")
include("ida-cmake/cmake/IDA.cmake")

list(APPEND HEADERS
    "src/Converter.hpp"
    "src/Core.hpp"
    "src/Generator.hpp"
    "src/PluginConfig.hpp"
    "src/Searcher.hpp"
    "src/Settings.hpp"
    "src/Signature.hpp"
    "src/Utils.hpp"
)

list(APPEND SOURCES
    "src/Converter.cpp"
    "src/Core.cpp"
    "src/Generator.cpp"
    "src/Searcher.cpp"
    "src/Settings.cpp"
    "src/sigmaker.cpp"
    "src/Utils.cpp"
)

# Add IDA plugin target
#include_directories("src")
add_ida_qt_plugin(${CMAKE_PROJECT_NAME} ${HEADERS} ${SOURCES})
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC "/wd4267")
target_compile_options(${CMAKE_PROJECT_NAME} PUBLIC "/wd4244")
