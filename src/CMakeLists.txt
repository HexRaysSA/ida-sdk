cmake_minimum_required(VERSION 3.27)
project(idasdk)
set(CMAKE_CXX_STANDARD 17)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

add_subdirectory(ldr)
add_subdirectory(module)
add_subdirectory(plugins)
add_subdirectory(idalib/examples)
add_subdirectory(dbg)
