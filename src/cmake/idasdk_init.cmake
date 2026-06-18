# idasdk_init.cmake -- include before project(): resolves IDASDK, makes
# find_package(idasdk) reachable, pre-selects MSVC on Windows.

# 1. Resolve SDK root: $ENV{IDASDK} wins, else derive from this file's location.
set(_idasdk_raw "$ENV{IDASDK}")
if(_idasdk_raw STREQUAL "")
    cmake_path(GET CMAKE_CURRENT_LIST_DIR PARENT_PATH _idasdk_raw)
endif()

# Supported shapes: <root>/include/pro.h (zip) or <root>/src/include/pro.h (git).
set(_idasdk_resolved "")
foreach(_probe IN ITEMS "" "src")
    set(_candidate "${_idasdk_raw}")
    if(NOT _probe STREQUAL "")
        set(_candidate "${_idasdk_raw}/${_probe}")
    endif()
    if(EXISTS "${_candidate}/include/pro.h")
        set(_idasdk_resolved "${_candidate}")
        break()
    endif()
endforeach()

if(_idasdk_resolved STREQUAL "")
    message(FATAL_ERROR
        "Could not locate include/pro.h under '${_idasdk_raw}' "
        "(checked '<root>' and '<root>/src').")
endif()

if(NOT _idasdk_resolved STREQUAL _idasdk_raw)
    message(STATUS "IDA SDK detected at: ${_idasdk_resolved}")
endif()
set(ENV{IDASDK} "${_idasdk_resolved}")
unset(_idasdk_raw)
unset(_idasdk_resolved)
unset(_probe)
unset(_candidate)

# 2. Make idasdkConfig.cmake reachable to find_package.
# Direct idasdk_DIR is set as well so a cross-compile toolchain file's
# CMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY doesn't hide it.
list(PREPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_LIST_DIR}")
list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")
set(idasdk_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE PATH
    "Directory containing idasdkConfig.cmake")

# cmake_path() and block() are needed across the helper layer.
if(CMAKE_VERSION VERSION_LESS 3.25)
    message(FATAL_ERROR
        "This SDK requires CMake 3.25 or newer (you have ${CMAKE_VERSION}).")
endif()

# 3. Windows: preselect MSVC so the subsequent project() finds cl.exe.
# Cross-compile toolchain files include find_msvc themselves; skip here.
if(CMAKE_HOST_WIN32 AND NOT CMAKE_TOOLCHAIN_FILE
        AND EXISTS "${CMAKE_CURRENT_LIST_DIR}/find_msvc.cmake")
    include("${CMAKE_CURRENT_LIST_DIR}/find_msvc.cmake")
endif()
