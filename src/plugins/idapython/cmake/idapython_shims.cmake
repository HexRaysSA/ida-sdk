# ===========================================================================
# plugins/idapython/cmake/idapython_shims.cmake
# ===========================================================================
# Standalone seam provider for idapython_body.cmake: builds against a RELEASED
# IDA SDK via find_package(idasdk). The includer sets the staging/output dir
# vars (IDAPYTHON_SRC GEN ST_SWIG ST_PYW ST_WRAP
# ST_PARSED_HEADERS_NOXML ST_PARSED_HEADERS _runtime_dir DEPLOY_PYDIR
# DEPLOY_LIBDIR), includes this, then includes idapython_body.cmake.
# ===========================================================================

# --- 1. Released SDK ------------------------------------------------------
# Default: the SDK this tree ships in (3 up); override with -DIDASDK / IDASDK env.
if(NOT IDASDK)
    if(DEFINED ENV{IDASDK} AND NOT "$ENV{IDASDK}" STREQUAL "")
        set(IDASDK "$ENV{IDASDK}")
    else()
        get_filename_component(IDASDK "${CMAKE_CURRENT_LIST_DIR}/../../.." ABSOLUTE)
    endif()
endif()
cmake_path(ABSOLUTE_PATH IDASDK NORMALIZE)

# An includer may point IDASDK_CMAKE at a different config location.
if(NOT DEFINED IDASDK_CMAKE)
    set(IDASDK_CMAKE "${IDASDK}/cmake")
endif()
if(NOT EXISTS "${IDASDK_CMAKE}/idasdkConfig.cmake")
    message(FATAL_ERROR
        "No IDA SDK at '${IDASDK}' (missing ${IDASDK_CMAKE}/idasdkConfig.cmake); "
        "pass -DIDASDK=<sdk> or set the IDASDK env var.")
endif()
# NO_CMAKE_FIND_ROOT_PATH: host-side config; else CMAKE_SYSROOT re-roots PATHS.
find_package(idasdk REQUIRED PATHS "${IDASDK_CMAKE}"
    NO_DEFAULT_PATH NO_CMAKE_FIND_ROOT_PATH)

# --- 2. Python / SWIG (find only if the includer hasn't set them) ------
if(NOT Python3_INCLUDE_DIRS)
    include("${CMAKE_CURRENT_LIST_DIR}/idapython_python.cmake")
    ida_find_python()
endif()

# SWIG (build-from-source / find + ccache-swig) lives in its own module.
include("${CMAKE_CURRENT_LIST_DIR}/idapython_swig.cmake")

# --- 4. Seam variables ----------------------------------------------------
# _lib_dir / IDA_STUB_LIB are include-safe: an includer's own values win.
set(ST_SDK_DIR "${IDASDK}/include")
set(_lib_ext "${IDA_STATIC_EXT}")
set(_obj_ext "${IDA_OBJ_EXT}")
if(NOT DEFINED _lib_dir)
    set(_lib_dir "${IDA_LIB_DIR}")
endif()
if(NOT DEFINED IDA_STUB_LIB)
    set(IDA_STUB_LIB "${IDA_LIB_PATH}")
endif()

# Includer-providable; defaults apply when unset.
if(NOT DEFINED ST_SDK_EXTRA)
    set(ST_SDK_EXTRA "")
endif()
if(NOT DEFINED IDAVER_MAJOR)
    set(IDAVER_MAJOR "${IDA_SDK_MAJOR}")
    set(IDAVER_MINOR "${IDA_SDK_MINOR}")
    set(IDAVER_PATCH 0)
endif()
foreach(_flag IDA_FREE IDA_HOME IDA_TESTABLE_BUILD IDA_TELEMETRY)
    if(NOT DEFINED ${_flag})
        set(${_flag} OFF)
    endif()
endforeach()
if(NOT DEFINED IDA_APPLE_SILICON)
    if(IDA_MAC AND IDA_ARM)
        set(IDA_APPLE_SILICON ON)
    else()
        set(IDA_APPLE_SILICON OFF)
    endif()
endif()
if(NOT IDASDK_FILES)
    file(GLOB_RECURSE IDASDK_FILES "${ST_SDK_DIR}/*.h" "${ST_SDK_DIR}/*.hpp")
endif()

# Released SDK ships only static-runtime import libs -> force /MT (before targets).
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>" CACHE STRING "" FORCE)
endif()

# --- 5. Compiler-flags carrier (body links this target) -------------------
# ida_addon_base (from idasdk) carries PIC + platform flags, never IDA symbols.
if(NOT TARGET ida_compiler_flags)
    add_library(ida_compiler_flags INTERFACE)
    target_link_libraries(ida_compiler_flags INTERFACE ida_addon_base)
endif()

# --- 6. Minimal helpers the body calls (guarded: an includer's win) ------
if(NOT COMMAND _ida_comment)
    function(_ida_comment outvar text)
        set(${outvar} "${text}" PARENT_SCOPE)
    endfunction()
endif()
if(NOT COMMAND ida_module_warnings)
    function(ida_module_warnings target profile)
        if(MSVC)
            target_compile_options(${target} PRIVATE /w)
        else()
            target_compile_options(${target} PRIVATE -w)
        endif()
    endfunction()
endif()
if(NOT COMMAND set_rtti_enabled)
    function(set_rtti_enabled target enabled)
        if(enabled)
            if(MSVC)
                target_compile_options(${target} PRIVATE /GR)
            else()
                target_compile_options(${target}
                    PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-frtti>)
            endif()
        endif()
    endfunction()
endif()
if(NOT COMMAND _ida_apply_pie_link_options)
    function(_ida_apply_pie_link_options target)
    endfunction()
endif()

# --- 7. Seam targets ------------------------------------------------------
# SDK headers already exist in a released SDK: staging is a no-op.
if(NOT TARGET idapython_staging_sdk)
    add_custom_target(idapython_staging_sdk)
endif()

# Parsed hook notifications: a forced IDA_DOXYGEN_BIN regenerates them, else the
# shipped bundle is used, else doxygen is searched for.
set(PARSED_HEADERS_MARKER "${ST_PARSED_HEADERS}/headers_generated.marker")
set(_notif_zip "${IDAPYTHON_SRC}/out_of_tree/parsed_notifications.zip")
if(NOT IDA_DOXYGEN_BIN AND NOT EXISTS "${_notif_zip}")
    find_program(IDA_DOXYGEN_BIN NAMES doxygen)
endif()
if(IDA_DOXYGEN_BIN AND EXISTS "${IDA_DOXYGEN_BIN}")
    set(_gh "${IDAPYTHON_SRC}/tools/genhooks")
    set(_doxycfg "${ST_PARSED_HEADERS_NOXML}/doxy_gen_notifs.cfg")
    set(_doxy_inc "${ST_SDK_DIR}")
    if(ST_SDK_EXTRA)
        set(_doxy_inc "${ST_SDK_DIR},${ST_SDK_EXTRA}")
    endif()
    file(GLOB _extra_hdrs "${ST_SDK_EXTRA}/*.h" "${ST_SDK_EXTRA}/*.hpp")
    add_custom_command(OUTPUT "${_doxycfg}"
        COMMAND "${IDA_PYTHON}" "${_gh}/gendoxycfg.py"
            -i "${_gh}/doxy_gen_notifs.cfg.in" -o "${_doxycfg}"
            --includes "${_doxy_inc}"
        DEPENDS "${_gh}/gendoxycfg.py" "${_gh}/doxy_gen_notifs.cfg.in"
        COMMENT "gendoxycfg: doxy_gen_notifs.cfg"
        VERBATIM)
    add_custom_command(OUTPUT "${PARSED_HEADERS_MARKER}"
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${ST_PARSED_HEADERS}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${ST_PARSED_HEADERS_NOXML}"
        COMMAND "${IDA_DOXYGEN_BIN}" "${_doxycfg}"
        COMMAND ${CMAKE_COMMAND} -E touch "${PARSED_HEADERS_MARKER}"
        WORKING_DIRECTORY "${GEN}"
        DEPENDS "${_doxycfg}" ${IDASDK_FILES} ${_extra_hdrs}
        COMMENT "doxygen: generating parsed headers"
        VERBATIM)
else()
    if(NOT EXISTS "${_notif_zip}")
        message(FATAL_ERROR
            "Missing ${_notif_zip} and no doxygen found; install doxygen or pass "
            "-DIDA_DOXYGEN_BIN=<path>.")
    endif()
    add_custom_command(OUTPUT "${PARSED_HEADERS_MARKER}"
        COMMAND ${CMAKE_COMMAND} -E rm -rf "${ST_PARSED_HEADERS}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${ST_PARSED_HEADERS_NOXML}"
        COMMAND ${CMAKE_COMMAND} -E tar xf "${_notif_zip}"
        COMMAND ${CMAKE_COMMAND} -E touch "${PARSED_HEADERS_MARKER}"
        WORKING_DIRECTORY "${ST_PARSED_HEADERS_NOXML}"
        DEPENDS "${_notif_zip}"
        COMMENT "unzip: parsed_notifications"
        VERBATIM)
endif()
add_custom_target(idapython_parsed_headers DEPENDS "${PARSED_HEADERS_MARKER}")
