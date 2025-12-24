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

# Function to copy a file to the ${IDABIN}/cfg folder if the source is newer
function(copy_cfg TARGET SRC_FILE)
    if(EXISTS ${SRC_FILE})
        # Define the destination directory (same for all files)
        set(DEST_DIR ${IDABIN}/cfg)

        # Ensure the destination directory exists
        file(MAKE_DIRECTORY ${DEST_DIR})
        get_filename_component(FILENAME ${SRC_FILE} NAME)

        # Copy the source file to the destination if it's newer, tied to the given target
        add_custom_command(
            TARGET ${TARGET} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${SRC_FILE}
                ${DEST_DIR}/${FILENAME}
            COMMENT "Copying ${SRC_FILE} to ${DEST_DIR} if newer"
        )
    endif()
endfunction()


include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/bootstrap.cmake)
find_package(idasdk REQUIRED)
set(IDA_IDC_DIR "${IDABIN}/idc")

add_subdirectory(ldr)
add_subdirectory(module)
add_subdirectory(plugins)
add_subdirectory(idalib/examples)
add_subdirectory(dbg)
