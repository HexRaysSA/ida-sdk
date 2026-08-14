# Standalone entry points include this before project(): CMAKE_BUILD_TYPE is
# materialized by project() (Debug on MSVC), too late to default afterwards.
if(NOT CMAKE_TOOLCHAIN_FILE)
    include("${CMAKE_CURRENT_LIST_DIR}/find_msvc.cmake")
endif()
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type")
endif()
