cmake_minimum_required(VERSION 3.25)

# On Windows with Ninja, auto-detect MSVC if not already in environment.
# Cross-compile toolchain files include find_msvc themselves (after setting
# CMAKE_SYSTEM_PROCESSOR), so this top-level invocation only fires for the
# native (no-toolchain) case.
if(NOT CMAKE_TOOLCHAIN_FILE)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/find_msvc.cmake)
endif()

# Before project(): shipped SDK libs are Release-only.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif()

project(idasdk)
set(CMAKE_CXX_STANDARD 17)

set(IDA_WARNINGS "default" CACHE STRING "Compiler warning level: none, default, all")
set_property(CACHE IDA_WARNINGS PROPERTY STRINGS "none" "default" "all")
if(NOT IDA_WARNINGS MATCHES "^(none|default|all)$")
    message(FATAL_ERROR "IDA_WARNINGS must be one of: none, default, all (got '${IDA_WARNINGS}')")
endif()

# Auto-detect if building from within the SDK itself (integrated build)
if(NOT DEFINED ENV{IDASDK} OR "$ENV{IDASDK}" STREQUAL "")
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/ida.hpp" OR
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/pro.h")
        set(ENV{IDASDK} "${CMAKE_CURRENT_SOURCE_DIR}")
        message(STATUS "Auto-detected integrated SDK build: $ENV{IDASDK}")
    endif()
elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/ida.hpp" OR
       EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/pro.h")
    get_filename_component(_DETECTED_IDASDK "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
    get_filename_component(_CURRENT_IDASDK "$ENV{IDASDK}" ABSOLUTE)
    if(NOT "${_CURRENT_IDASDK}" STREQUAL "${_DETECTED_IDASDK}")
        message(STATUS "Overriding IDASDK (${_CURRENT_IDASDK}) with local SDK: ${_DETECTED_IDASDK}")
        set(ENV{IDASDK} "${_DETECTED_IDASDK}")
    endif()
endif()

# Covers ldr/module/plugins/idalib + dbg stubs/user-plugins in this layer.
option(IDA_BUILD_IDA    "Build SDK extensions and stubs/user-plugins" ON)
option(IDA_BUILD_DBGSRV "Build debug servers"                         OFF)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/idasdk_init.cmake)
find_package(idasdk REQUIRED)
set(IDA_IDC_DIR "${IDABIN}/idc")

# Plugins/loaders/procmods/idalib need libida (not shipped in EA32 / dbgserver flavors).
if(IDA_BUILD_IDA AND IDA_EA64 AND EXISTS "${IDA_LIB_PATH}")
    add_subdirectory(ldr)
    add_subdirectory(module)
    add_subdirectory(plugins)
    add_subdirectory(idalib/examples)
endif()
add_subdirectory(dbg)
