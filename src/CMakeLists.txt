cmake_minimum_required(VERSION 3.27)
project(idasdk)
set(CMAKE_CXX_STANDARD 17)

# Auto-detect if building from within the SDK itself (integrated build)
# Check if we have include/ida.hpp or include/pro.h in current directory
if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/ida.hpp" OR
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/pro.h")
        # We're building from within the SDK directory structure
        set(ENV{IDASDK} "${CMAKE_CURRENT_SOURCE_DIR}")
        message(STATUS "Auto-detected integrated SDK build: $ENV{IDASDK}")
    endif()
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/ida.hpp" OR
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/pro.h")
    # IDASDK is set, but we're building from within SDK - prefer local SDK
    get_filename_component(_DETECTED_IDASDK "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
    get_filename_component(_CURRENT_IDASDK "$ENV{IDASDK}" ABSOLUTE)
    if(NOT "${_CURRENT_IDASDK}" STREQUAL "${_DETECTED_IDASDK}")
        message(STATUS "Overriding IDASDK (${_CURRENT_IDASDK}) with local SDK: ${_DETECTED_IDASDK}")
        set(ENV{IDASDK} "${_DETECTED_IDASDK}")
    endif()
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)

add_subdirectory(ldr)
add_subdirectory(module)
add_subdirectory(plugins)
add_subdirectory(idalib/examples)
add_subdirectory(dbg)
