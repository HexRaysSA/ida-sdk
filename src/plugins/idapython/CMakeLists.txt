# =================================================================
# IDAPython - Python scripting support for IDA
# =================================================================
# CMake-only build. Requires: SWIG (>= 4.2), Python3 (>= 3.8)
# If SWIG is not found, IDAPython is skipped gracefully.
#
# Standalone build (from this directory):
#   cmake -B build && cmake --build build --config Release
#
# From SDK root (builds everything including IDAPython):
#   cd ../../ && cmake -B build && cmake --build build --config Release
#
# Build just IDAPython target (from either):
#   cmake --build build --config Release --target idapython_all
# =================================================================

# Standalone bootstrap — when this is the top-level CMakeLists.txt,
# set up the SDK environment. When included as a subdirectory, this
# block is skipped and the parent project has already configured everything.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    cmake_minimum_required(VERSION 3.27)
    project(idapython LANGUAGES C CXX)

    # We live at src/plugins/idapython — SDK root is ../../
    set(ENV{IDASDK} "${CMAKE_CURRENT_SOURCE_DIR}/../..")
    include(${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/bootstrap.cmake)
    find_package(idasdk REQUIRED)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/IDAPythonSupport.cmake)

# ---------------------------------------------------------------
# Graceful skip if SWIG is not available
# ---------------------------------------------------------------
# Try to find SWIG first — if not found, skip rather than error
if(DEFINED ENV{SWIG})
    set(_swig_hint "$ENV{SWIG}")
    get_filename_component(_swig_dir "${_swig_hint}" DIRECTORY)
    find_program(_SWIG_CHECK swig HINTS "${_swig_dir}" NO_DEFAULT_PATH)
    if(NOT _SWIG_CHECK AND EXISTS "${_swig_hint}")
        set(_SWIG_CHECK "${_swig_hint}")
    endif()
else()
    find_program(_SWIG_CHECK swig)
endif()

if(NOT _SWIG_CHECK)
    message(STATUS "IDAPython: Skipping (SWIG not found). Install SWIG 4.2+ to build IDAPython.")
    return()
endif()
unset(_SWIG_CHECK CACHE)

# Now do the full prerequisite check (will FATAL_ERROR if Python3 missing)
idapython_check_prerequisites()

# ---------------------------------------------------------------
# Setup directories and staging areas
# ---------------------------------------------------------------
idapython_setup_directories()

# ---------------------------------------------------------------
# Phase 1: Extract pre-built doxygen XML
# ---------------------------------------------------------------
idapython_extract_parsed_headers()
# IDAPYTHON_PARSED_HEADERS_MARKER is now set

# ---------------------------------------------------------------
# Phase 2: Stage pywraps (copy to build dir)
# ---------------------------------------------------------------
idapython_stage_pywraps()
# IDAPYTHON_STAGED_PYWRAPS is now set

# ---------------------------------------------------------------
# Phase 3: Generate hooks (6 hook types)
# ---------------------------------------------------------------
idapython_generate_hooks("${IDAPYTHON_PARSED_HEADERS_MARKER}")
# IDAPYTHON_HOOK_FILES is now set

# ---------------------------------------------------------------
# Phase 4: Generate SWIG header
# ---------------------------------------------------------------
idapython_generate_swig_header()
# IDAPYTHON_SWIG_HEADER is now set

# ---------------------------------------------------------------
# Phase 5: Build main idapython3 plugin
# ---------------------------------------------------------------
idapython_add_main_plugin()
# IDAPYTHON_IMPLIB is now set

# ---------------------------------------------------------------
# Phase 6: Define all 49 modules
# ---------------------------------------------------------------
set(IDAPYTHON_MODULES
    hexrays allins auto bitrange bytes dbg diskio dirtree entry expr
    fixup fpro frame funcs gdl graph ida idaapi idc idd idp ieee
    kernwin libfuncs lines loader lumina moves nalt name netnode offset
    pro problems range registry regfinder search segment segregs srclang
    strlist tryblks typeinf ua xref mergemod merge undo
)

# Interface dependencies (some .i files need to %import others)
set(IFACE_DEPS_bytes     range)
set(IFACE_DEPS_dbg       idd)
set(IFACE_DEPS_frame     range)
set(IFACE_DEPS_funcs     range)
set(IFACE_DEPS_gdl       range)
set(IFACE_DEPS_graph     gdl)
set(IFACE_DEPS_hexrays   pro typeinf xref gdl)
set(IFACE_DEPS_idd       range)
set(IFACE_DEPS_idp       bitrange)
set(IFACE_DEPS_segment   range)
set(IFACE_DEPS_segregs   range)
set(IFACE_DEPS_typeinf   idp)
set(IFACE_DEPS_tryblks   range)

# Lifecycle-aware modules
set(LIFECYCLE_MODULES bytes hexrays idaapi kernwin typeinf)

# ---------------------------------------------------------------
# Phase 7: Build all SWIG modules
# ---------------------------------------------------------------
set(_all_deployed_py "")
set(_all_module_targets "")

foreach(_mod IN LISTS IDAPYTHON_MODULES)
    # Check for interface deps
    set(_deps "")
    if(DEFINED IFACE_DEPS_${_mod})
        set(_deps "${IFACE_DEPS_${_mod}}")
    endif()

    # Check lifecycle-aware
    set(_lifecycle "")
    if("${_mod}" IN_LIST LIFECYCLE_MODULES)
        set(_lifecycle "LIFECYCLE_AWARE")
    endif()

    idapython_add_swig_module(
        MODULE_NAME "${_mod}"
        INTERFACE_DEPS ${_deps}
        ${_lifecycle}
        ALL_PYWRAPS ${IDAPYTHON_STAGED_PYWRAPS}
        ALL_HOOKS ${IDAPYTHON_HOOK_FILES}
        SWIG_HEADER "${IDAPYTHON_SWIG_HEADER}"
        PARSED_MARKER "${IDAPYTHON_PARSED_HEADERS_MARKER}"
        IMPLIB "${IDAPYTHON_IMPLIB}"
    )

    list(APPEND _all_deployed_py "${_IDAPYTHON_PY_${_mod}}")
    list(APPEND _all_module_targets "_ida_${_mod}")
endforeach()

# ---------------------------------------------------------------
# Phase 8: Generate init.py and idaapi.py via genidaapi.py
# ---------------------------------------------------------------
set(_genidaapi "${IDAPYTHON_SOURCE_DIR}/tools/genidaapi.py")
string(REPLACE ";" "," _modules_csv "${IDAPYTHON_MODULES}")

# init.py
set(_deploy_init "${IDAPYTHON_DEPLOY_PYDIR}/init.py")
add_custom_command(
    OUTPUT "${_deploy_init}"
    COMMAND ${Python3_EXECUTABLE} "${_genidaapi}"
        -i "${IDAPYTHON_SOURCE_DIR}/python/init.py"
        -o "${_deploy_init}"
        -m "${_modules_csv}"
    DEPENDS
        "${IDAPYTHON_SOURCE_DIR}/python/init.py"
        "${_genidaapi}"
        ${_all_deployed_py}
    COMMENT "IDAPython: Generating init.py"
)

# idaapi.py
set(_deploy_idaapi "${IDAPYTHON_DEPLOY_PYDIR}/idaapi.py")
add_custom_command(
    OUTPUT "${_deploy_idaapi}"
    COMMAND ${Python3_EXECUTABLE} "${_genidaapi}"
        -i "${IDAPYTHON_SOURCE_DIR}/python/idaapi.py"
        -o "${_deploy_idaapi}"
        -m "${_modules_csv}"
    DEPENDS
        "${IDAPYTHON_SOURCE_DIR}/python/idaapi.py"
        "${_genidaapi}"
        ${_all_deployed_py}
    COMMENT "IDAPython: Generating idaapi.py"
)

# ---------------------------------------------------------------
# Phase 9: Deploy static Python files
# ---------------------------------------------------------------
set(_static_py_files
    idc.py
    idautils.py
    idadex.py
    lumina_model.py
)

set(_deployed_static "")
foreach(_pyfile IN LISTS _static_py_files)
    set(_src "${IDAPYTHON_SOURCE_DIR}/python/${_pyfile}")
    set(_dst "${IDAPYTHON_DEPLOY_PYDIR}/${_pyfile}")
    add_custom_command(
        OUTPUT "${_dst}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst}"
        DEPENDS "${_src}"
        COMMENT "IDAPython: Deploying ${_pyfile}"
    )
    list(APPEND _deployed_static "${_dst}")
endforeach()

# Deploy idapython.cfg to IDA cfg dir
set(_cfg_src "${IDAPYTHON_SOURCE_DIR}/idapython.cfg")
set(_cfg_dst "${IDABIN}/cfg/idapython.cfg")
file(MAKE_DIRECTORY "${IDABIN}/cfg")
add_custom_command(
    OUTPUT "${_cfg_dst}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_cfg_src}" "${_cfg_dst}"
    DEPENDS "${_cfg_src}"
    COMMENT "IDAPython: Deploying idapython.cfg"
)

# ---------------------------------------------------------------
# Phase 10: Aggregate target
# ---------------------------------------------------------------
add_custom_target(idapython_all
    DEPENDS
        idapython3
        ${_all_module_targets}
        ${_all_deployed_py}
        "${_deploy_init}"
        "${_deploy_idaapi}"
        ${_deployed_static}
        "${_cfg_dst}"
    COMMENT "IDAPython: All targets built"
)

# Summary
list(LENGTH IDAPYTHON_MODULES _num_modules)
message(STATUS "IDAPython: Configured ${_num_modules} SWIG modules + main plugin")
