# ===========================================================================
# sdk/src/plugins/idapython/CMakeLists.txt  (public / standalone entrypoint)
# ===========================================================================
# Builds IDAPython against a RELEASED IDA SDK, reusing the shared build body
# cmake/idapython_body.cmake. Fills the seam via cmake/idapython_shims.cmake
# (find_package(idasdk), Python3, SWIG, shipped parsed-notifications zip).
#
# Build (run from this directory; the SDK is auto-detected from the tree):
#   cmake -B build && cmake --build build
# With an explicitly specified SDK:
#   cmake -B build -DIDASDK=/path/to/idasdk && cmake --build build
#
# Or add_subdirectory()'d from an SDK plugins orchestrator that has already
# called project()/find_package(idasdk).
# ===========================================================================

cmake_minimum_required(VERSION 3.25)

# Dual-mode: only declare a project when built standalone (top-level).
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # Auto-detect MSVC on Windows (self-guards) so vcvarsall isn't required.
    include("${CMAKE_CURRENT_LIST_DIR}/../../cmake/find_msvc.cmake" OPTIONAL)
    project(idapython CXX)
endif()

set(IDAPYTHON_SRC "${CMAKE_CURRENT_SOURCE_DIR}")

# Staging root. Nested one level under "mirror/" so that the SWIG-generated
# `#include "../../../pywraps.hpp"` (3 dirs up from gen/wrappers/) resolves to
# ${CMAKE_CURRENT_BINARY_DIR} -- inside the build tree, never the source tree.
set(GEN "${CMAKE_CURRENT_BINARY_DIR}/mirror/gen")
set(ST_SWIG "${GEN}/swig")
set(ST_PYW "${GEN}/pywraps")
set(ST_WRAP "${GEN}/wrappers")
set(ST_PARSED_HEADERS_NOXML "${GEN}/staging/parsed_notifications")
set(ST_PARSED_HEADERS "${ST_PARSED_HEADERS_NOXML}/xml")

# Output layout: bin/python/{lib-dynload,...} + bin/plugins/idapython3.
set(_runtime_dir "${CMAKE_BINARY_DIR}/bin")
set(DEPLOY_PYDIR "${_runtime_dir}/python")
set(DEPLOY_LIBDIR "${DEPLOY_PYDIR}/lib-dynload")

file(MAKE_DIRECTORY "${ST_SWIG}" "${ST_PYW}" "${ST_WRAP}"
     "${ST_PARSED_HEADERS}" "${GEN}/staging")

# Mirror pywraps/extapi next to where the generated wrappers' relative include
# lands (see GEN comment above). Symlink on Unix, copy on Windows.
get_filename_component(_symlink_dir "${ST_WRAP}/../../.." ABSOLUTE)
file(MAKE_DIRECTORY "${_symlink_dir}")
foreach(_symfile pywraps.hpp pywraps.cpp extapi.hpp extapi.cpp)
    if(WIN32)
        file(COPY "${IDAPYTHON_SRC}/${_symfile}" DESTINATION "${_symlink_dir}")
    elseif(NOT EXISTS "${_symlink_dir}/${_symfile}")
        file(CREATE_LINK "${IDAPYTHON_SRC}/${_symfile}"
             "${_symlink_dir}/${_symfile}" SYMBOLIC)
    endif()
endforeach()
if(WIN32)
    file(COPY "${IDAPYTHON_SRC}/py-include" DESTINATION "${_symlink_dir}")
elseif(NOT EXISTS "${_symlink_dir}/py-include")
    file(CREATE_LINK "${IDAPYTHON_SRC}/py-include"
         "${_symlink_dir}/py-include" SYMBOLIC)
endif()

# Fill the seam from the released SDK, then build the shared body.
include("${CMAKE_CURRENT_LIST_DIR}/cmake/idapython_shims.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmake/idapython_body.cmake")

# Master target: plugin + wrapper modules + python; by default also merges the
# build output into the SDK's bin/ (keeps existing files there).
option(IDAPYTHON_DEPLOY_TO_SDK "Copy the build output into <sdk>/bin/" ON)
set(_deploy "")
if(IDAPYTHON_DEPLOY_TO_SDK)
    set(_deploy COMMAND "${CMAKE_COMMAND}" -E copy_directory
                "${_runtime_dir}" "${IDASDK}/bin")
endif()
add_custom_target(idapython ALL
    ${_deploy}
    DEPENDS idapython3 ${ALL_WRAPPER_TARGETS} idapython_pyfiles)
