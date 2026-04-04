# =================================================================
# IDAPython Support for IDA SDK CMake Build
# =================================================================
# Provides SWIG-based IDAPython build pipeline.
#
# Features:
#   - Automatic SWIG + Python3 detection
#   - 10-step per-module pipeline (deploy → swig → patch×4 → compile → link → pypasses → deploy)
#   - Pre-built doxygen XML (avoids doxygen version issues)
#   - Cross-platform: Windows (MSVC), Linux (GCC/Clang), macOS (Clang)
#
# Usage:
#   include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/IDAPythonSupport.cmake)
#   idapython_check_prerequisites()
#   idapython_add_main_plugin()
#   idapython_add_swig_module(MODULE_NAME ...)
# =================================================================

# Guard against multiple inclusion
if(DEFINED _IDAPYTHON_SUPPORT_INCLUDED)
    return()
endif()
set(_IDAPYTHON_SUPPORT_INCLUDED TRUE)

# =================================================================
# idapython_check_prerequisites()
# Find SWIG and Python3, validate versions.
# Sets: SWIG_EXECUTABLE, SWIG_LIB_DIR, Python3 variables
# =================================================================
function(idapython_check_prerequisites)
    # Find SWIG — respect $ENV{SWIG} if set
    if(DEFINED ENV{SWIG})
        set(_swig_hint "$ENV{SWIG}")
        get_filename_component(_swig_dir "${_swig_hint}" DIRECTORY)
        find_program(SWIG_EXECUTABLE swig HINTS "${_swig_dir}" NO_DEFAULT_PATH)
        if(NOT SWIG_EXECUTABLE)
            # Try the env var as the direct path
            if(EXISTS "${_swig_hint}")
                set(SWIG_EXECUTABLE "${_swig_hint}" CACHE FILEPATH "SWIG executable" FORCE)
            endif()
        endif()
    endif()
    if(NOT SWIG_EXECUTABLE)
        find_program(SWIG_EXECUTABLE swig)
    endif()

    if(NOT SWIG_EXECUTABLE)
        message(FATAL_ERROR
            "IDAPython: SWIG not found!\n"
            "  Install SWIG 4.2+ and ensure it's in PATH, or set SWIG env variable.\n"
            "  Windows: winget install SWIG.SWIG\n"
            "  Linux:   apt install swig\n"
            "  macOS:   brew install swig")
    endif()

    # Get SWIG version
    execute_process(
        COMMAND "${SWIG_EXECUTABLE}" -version
        OUTPUT_VARIABLE _swig_version_output
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    string(REGEX MATCH "SWIG Version ([0-9]+\\.[0-9]+\\.[0-9]+)" _match "${_swig_version_output}")
    set(_swig_version "${CMAKE_MATCH_1}")
    if(_swig_version VERSION_LESS "4.2")
        message(FATAL_ERROR "IDAPython: SWIG ${_swig_version} found, but >= 4.2 is required")
    endif()

    # Get SWIG lib dir
    execute_process(
        COMMAND "${SWIG_EXECUTABLE}" -swiglib
        OUTPUT_VARIABLE _swig_lib
        ERROR_QUIET
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    set(SWIG_LIB_DIR "${_swig_lib}" CACHE PATH "SWIG library directory" FORCE)

    # Find Python3 — we need Interpreter (for running tools) and Development (for headers)
    find_package(Python3 REQUIRED COMPONENTS Interpreter Development)
    if(Python3_VERSION VERSION_LESS "3.8")
        message(FATAL_ERROR "IDAPython: Python ${Python3_VERSION} found, but >= 3.8 is required")
    endif()

    # Export to parent scope
    set(SWIG_EXECUTABLE "${SWIG_EXECUTABLE}" PARENT_SCOPE)
    set(SWIG_LIB_DIR "${SWIG_LIB_DIR}" PARENT_SCOPE)
    set(SWIG_VERSION "${_swig_version}" PARENT_SCOPE)
    set(Python3_INCLUDE_DIRS "${Python3_INCLUDE_DIRS}" PARENT_SCOPE)
    set(Python3_LIBRARIES "${Python3_LIBRARIES}" PARENT_SCOPE)
    set(Python3_LIBRARY_DIRS "${Python3_LIBRARY_DIRS}" PARENT_SCOPE)
    set(Python3_EXECUTABLE "${Python3_EXECUTABLE}" PARENT_SCOPE)
    set(Python3_VERSION "${Python3_VERSION}" PARENT_SCOPE)

    message(STATUS "IDAPython: SWIG ${_swig_version} at ${SWIG_EXECUTABLE}")
    message(STATUS "IDAPython: Python ${Python3_VERSION} at ${Python3_EXECUTABLE}")
    message(STATUS "IDAPython: Python include: ${Python3_INCLUDE_DIRS}")
endfunction()

# =================================================================
# idapython_setup_directories()
# Create staging directory variables used by the build pipeline.
# =================================================================
macro(idapython_setup_directories)
    set(IDAPYTHON_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    set(IDAPYTHON_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}")

    set(IDAPYTHON_ST_SWIG    "${IDAPYTHON_BINARY_DIR}/swig")
    set(IDAPYTHON_ST_WRAP    "${IDAPYTHON_BINARY_DIR}/wrappers")
    set(IDAPYTHON_ST_PYW     "${IDAPYTHON_BINARY_DIR}/pywraps")
    set(IDAPYTHON_PARSED_XML "${IDAPYTHON_BINARY_DIR}/parsed_notifications/xml")

    set(IDAPYTHON_DEPLOY_PYDIR  "${IDABIN}/python")
    set(IDAPYTHON_DEPLOY_LIBDIR "${IDABIN}/python/lib-dynload")

    # Create directories at configure time
    file(MAKE_DIRECTORY "${IDAPYTHON_ST_SWIG}")
    file(MAKE_DIRECTORY "${IDAPYTHON_ST_WRAP}")
    file(MAKE_DIRECTORY "${IDAPYTHON_ST_PYW}")
    file(MAKE_DIRECTORY "${IDAPYTHON_DEPLOY_PYDIR}")
    file(MAKE_DIRECTORY "${IDAPYTHON_DEPLOY_LIBDIR}")
    file(MAKE_DIRECTORY "${IDAPYTHON_BINARY_DIR}/parsed_notifications")

    # pywraps.hpp include path is injected via genswigheader.py --pywraps-dir
    # (no file copies needed)
endmacro()

# =================================================================
# idapython_extract_parsed_headers()
# Extract pre-built doxygen XML from out_of_tree/parsed_notifications.zip
# =================================================================
function(idapython_extract_parsed_headers)
    set(_zip "${IDAPYTHON_SOURCE_DIR}/out_of_tree/parsed_notifications.zip")
    set(_extract_dir "${IDAPYTHON_BINARY_DIR}/parsed_notifications")
    set(_marker "${IDAPYTHON_PARSED_XML}/headers_generated.marker")

    # The zip contains parsed_notifications/xml/...
    # Extract one level above so nested dir lands correctly
    add_custom_command(
        OUTPUT "${_marker}"
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${_extract_dir}/xml"
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${_extract_dir}/parsed_notifications"
        COMMAND ${CMAKE_COMMAND} -E tar xf "${_zip}"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${_extract_dir}/parsed_notifications/xml"
            "${_extract_dir}/xml"
        COMMAND ${CMAKE_COMMAND} -E remove_directory "${_extract_dir}/parsed_notifications"
        COMMAND ${CMAKE_COMMAND} -E touch "${_marker}"
        WORKING_DIRECTORY "${_extract_dir}"
        DEPENDS "${_zip}"
        COMMENT "IDAPython: Extracting pre-built doxygen XML..."
    )
    # Wrap in a custom target so MSBuild runs extraction exactly once
    # (without this, parallel MSBuild nodes race on the same zip extraction)
    add_custom_target(idapython_extract_headers DEPENDS "${_marker}")

    # Make the marker available
    set(IDAPYTHON_PARSED_HEADERS_MARKER "${_marker}" PARENT_SCOPE)
endfunction()

# =================================================================
# idapython_stage_pywraps()
# Copy pywraps/*.hpp and *.py to build staging directory.
# Returns list of staged files via IDAPYTHON_STAGED_PYWRAPS.
# =================================================================
function(idapython_stage_pywraps)
    file(GLOB _hpp_sources "${IDAPYTHON_SOURCE_DIR}/pywraps/*.hpp")
    file(GLOB _py_sources "${IDAPYTHON_SOURCE_DIR}/pywraps/*.py")

    # These files are generated by genhooks.py, not plain-copied
    set(_hook_generated_files
        py_idp.hpp
        py_idp_idbhooks.hpp
        py_dbg.hpp
        py_kernwin.hpp
        py_kernwin_viewhooks.hpp
        py_hexrays_hooks.hpp
    )

    set(_staged_files "")
    foreach(_src IN LISTS _hpp_sources _py_sources)
        get_filename_component(_fname "${_src}" NAME)

        # Skip files that will be generated by genhooks
        if("${_fname}" IN_LIST _hook_generated_files)
            continue()
        endif()

        set(_dst "${IDAPYTHON_ST_PYW}/${_fname}")
        add_custom_command(
            OUTPUT "${_dst}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst}"
            DEPENDS "${_src}"
            COMMENT "IDAPython: Staging pywraps/${_fname}"
        )
        list(APPEND _staged_files "${_dst}")
    endforeach()

    set(IDAPYTHON_STAGED_PYWRAPS "${_staged_files}" PARENT_SCOPE)
endfunction()

# =================================================================
# idapython_generate_hooks()
# Run genhooks.py for each hook type.
# Returns list of generated files via IDAPYTHON_HOOK_FILES.
# =================================================================
function(idapython_generate_hooks PARSED_MARKER)
    set(_genhooks "${IDAPYTHON_SOURCE_DIR}/tools/genhooks/genhooks.py")
    set(_sdk_include "${IDASDK}/include")

    # Hook definitions: output_base|input_pywrap|hooks_class|qualifier|marker_name
    set(_hooks
        "py_idp|pywraps/py_idp.hpp|IDP_Hooks|processor_t::|hookgenIDP"
        "py_idp_idbhooks|pywraps/py_idp_idbhooks.hpp|IDB_Hooks|idb_event::|hookgenIDB"
        "py_dbg|pywraps/py_dbg.hpp|DBG_Hooks|dbg_notification_t::|hookgenDBG"
        "py_kernwin|pywraps/py_kernwin.hpp|UI_Hooks|ui_notification_t::|hookgenUI"
        "py_kernwin_viewhooks|pywraps/py_kernwin_viewhooks.hpp|View_Hooks|view_notification_t::|hookgenVIEW"
        "py_hexrays_hooks|pywraps/py_hexrays_hooks.hpp|Hexrays_Hooks|hexrays_event_t::|hookgenHEXRAYS"
    )

    set(_hook_outputs "")
    foreach(_hook IN LISTS _hooks)
        string(REPLACE "|" ";" _parts "${_hook}")
        list(GET _parts 0 _base)
        list(GET _parts 1 _input_rel)
        list(GET _parts 2 _class)
        list(GET _parts 3 _qualifier)
        list(GET _parts 4 _marker)

        set(_input "${IDAPYTHON_SOURCE_DIR}/${_input_rel}")
        set(_output "${IDAPYTHON_ST_PYW}/${_base}.hpp")

        add_custom_command(
            OUTPUT "${_output}"
            COMMAND ${Python3_EXECUTABLE} "${_genhooks}"
                -i "${_input}"
                -o "${_output}"
                -c "${_class}"
                -x "${IDAPYTHON_PARSED_XML}"
                -m "${_marker}"
                -q "${_qualifier}"
            DEPENDS "${_input}" "${_genhooks}" "${PARSED_MARKER}"
            COMMENT "IDAPython: Generating hooks for ${_class}..."
        )
        list(APPEND _hook_outputs "${_output}")
    endforeach()

    set(IDAPYTHON_HOOK_FILES "${_hook_outputs}" PARENT_SCOPE)
endfunction()

# =================================================================
# idapython_generate_swig_header()
# Run genswigheader.py to create header.i
# =================================================================
function(idapython_generate_swig_header)
    set(_template "${IDAPYTHON_SOURCE_DIR}/tools/deploy/header.i.in")
    set(_script "${IDAPYTHON_SOURCE_DIR}/tools/genswigheader.py")
    set(_output "${IDAPYTHON_ST_SWIG}/header.i")
    set(_sdk "${IDASDK}/include")

    add_custom_command(
        OUTPUT "${_output}"
        COMMAND ${Python3_EXECUTABLE} "${_script}"
            -i "${_template}"
            -o "${_output}"
            -s "${_sdk}"
            --pywraps-dir "${IDAPYTHON_SOURCE_DIR}"
        DEPENDS "${_template}" "${_script}"
        COMMENT "IDAPython: Generating SWIG header..."
    )
    set(IDAPYTHON_SWIG_HEADER "${_output}" PARENT_SCOPE)
endfunction()

# =================================================================
# idapython_add_main_plugin()
# Build the main idapython3.dll/.so plugin.
# =================================================================
function(idapython_add_main_plugin)
    # idapython.cpp #includes pywraps.cpp and extapi.cpp — single translation unit
    set(_sources
        "${IDAPYTHON_SOURCE_DIR}/idapython.cpp"
    )

    add_library(idapython3 SHARED ${_sources})

    target_include_directories(idapython3 PRIVATE
        "${IDASDK}/include"
        "${IDAPYTHON_SOURCE_DIR}"
        "${Python3_INCLUDE_DIRS}"
    )

    # Compute IDAVER_MAJOR/MINOR/PATCH from IDA_SDK_VERSION
    file(STRINGS "${IDASDK}/include/pro.h" _ver_line REGEX "^#define IDA_SDK_VERSION")
    string(REGEX REPLACE ".*IDA_SDK_VERSION[ \t]+([0-9]+)" "\\1" _ver_num "${_ver_line}")
    math(EXPR _ver_major "${_ver_num} / 100")
    math(EXPR _ver_minor "(${_ver_num} % 100) / 10")
    math(EXPR _ver_patch "${_ver_num} % 10")

    target_compile_definitions(idapython3 PRIVATE
        __IDP__
        __EA64__=1
        __EXPR_SRC
        PY3=1
        Py_LIMITED_API=0x03090000
        INDIRECT_PYTHON_API
        MISSED_BC695
        USE_STANDARD_FILE_FUNCTIONS
        IDAVER_MAJOR=${_ver_major}
        IDAVER_MINOR=${_ver_minor}
        IDAVER_PATCH=${_ver_patch}
        ${IDAPROPLAT}
        $<$<PLATFORM_ID:Windows>:WIN32>
        $<$<PLATFORM_ID:Windows>:_WINDOWS>
    )

    target_link_libraries(idapython3 PRIVATE
        ida_addon_base
        "${IDA_LIB_PATH}"
    )

    # Platform-specific settings
    if(MSVC)
        # Use /MD runtime to match SDK libraries
        set_target_properties(idapython3 PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
        target_compile_options(idapython3 PRIVATE /bigobj /Zc:strictStrings-)
        target_link_options(idapython3 PRIVATE
            /SUBSYSTEM:WINDOWS
            /DEF:${IDAPYTHON_SOURCE_DIR}/idapython_implib.def
            /IMPLIB:${IDAPYTHON_BINARY_DIR}/idapython.lib
        )
    elseif(APPLE)
        target_link_options(idapython3 PRIVATE -Wl,-undefined,dynamic_lookup)
        set_target_properties(idapython3 PROPERTIES
            INSTALL_NAME_DIR "@rpath/plugins"
        )
    else()
        # Linux: allow undefined symbols (resolved at runtime by Python)
        target_link_options(idapython3 PRIVATE -Wl,--allow-shlib-undefined)
    endif()

    # Unix: no "lib" prefix
    if(NOT WIN32)
        set_target_properties(idapython3 PROPERTIES PREFIX "")
    endif()

    # Output to plugins directory
    set_target_properties(idapython3 PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "$<1:${IDA_PLUGIN_DIR}>"
        LIBRARY_OUTPUT_DIRECTORY "$<1:${IDA_PLUGIN_DIR}>"
    )

    ida_disable_warnings(idapython3)

    # Export the import library path for SWIG modules to link against
    if(WIN32)
        set(IDAPYTHON_IMPLIB "${IDAPYTHON_BINARY_DIR}/idapython.lib" PARENT_SCOPE)
    else()
        set(IDAPYTHON_IMPLIB "$<TARGET_FILE:idapython3>" PARENT_SCOPE)
    endif()
endfunction()

# =================================================================
# idapython_add_swig_module()
# Build one _ida_<MODULE>.pyd/.so SWIG extension module.
#
# Arguments:
#   MODULE_NAME          - e.g. "bytes", "kernwin"
#   INTERFACE_DEPS       - list of .i dependencies (e.g. "range")
#   LIFECYCLE_AWARE      - flag for deploy.py --lifecycle-aware
#   ALL_PYWRAPS          - list of all staged pywrap files
#   ALL_HOOKS            - list of hook output files
#   SWIG_HEADER          - path to generated header.i
#   PARSED_MARKER        - path to parsed headers marker
#   IMPLIB               - import library for main plugin
# =================================================================
function(idapython_add_swig_module)
    cmake_parse_arguments(ARG
        "LIFECYCLE_AWARE"
        "MODULE_NAME;SWIG_HEADER;PARSED_MARKER;IMPLIB"
        "INTERFACE_DEPS;ALL_PYWRAPS;ALL_HOOKS"
        ${ARGN}
    )

    set(_mod "${ARG_MODULE_NAME}")
    set(_tools "${IDAPYTHON_SOURCE_DIR}/tools")
    set(_swig_dir "${IDAPYTHON_SOURCE_DIR}/swig")
    set(_sdk "${IDASDK}/include")

    # Output paths
    set(_st_swig_i    "${IDAPYTHON_ST_SWIG}/${_mod}.i")
    set(_wrap_cpp_in1 "${IDAPYTHON_ST_WRAP}/${_mod}.cpp.in1")
    set(_wrap_cpp_in2 "${IDAPYTHON_ST_WRAP}/${_mod}.cpp.in2")
    set(_wrap_cpp     "${IDAPYTHON_ST_WRAP}/${_mod}.cpp")
    set(_wrap_h       "${IDAPYTHON_ST_WRAP}/${_mod}.h")
    set(_wrap_py      "${IDAPYTHON_ST_WRAP}/ida_${_mod}.py")
    set(_wrap_py_final "${IDAPYTHON_ST_WRAP}/ida_${_mod}.py.final")

    # Stamp files for in-place patches
    set(_stamp_h      "${IDAPYTHON_ST_WRAP}/${_mod}.h.patched")
    set(_stamp_py     "${IDAPYTHON_ST_WRAP}/ida_${_mod}.py.patched")
    set(_stamp_dir_cc "${IDAPYTHON_ST_WRAP}/${_mod}.h.directors_patched")

    # Build interface dep flags for SWIG
    set(_iface_dep_files "")
    set(_iface_dep_defines "")
    foreach(_dep IN LISTS ARG_INTERFACE_DEPS)
        list(APPEND _iface_dep_files "${IDAPYTHON_ST_SWIG}/${_dep}.i")
        string(TOUPPER "${_dep}" _DEP_UPPER)
        list(APPEND _iface_dep_defines "-DHAS_DEP_ON_INTERFACE_${_DEP_UPPER}")
    endforeach()

    # Lifecycle flag
    set(_lifecycle_flag "")
    if(ARG_LIFECYCLE_AWARE)
        set(_lifecycle_flag "--lifecycle-aware")
    endif()

    # Interface deps as comma-separated for deploy.py
    set(_iface_deps_csv "")
    if(ARG_INTERFACE_DEPS)
        string(REPLACE ";" "," _iface_deps_csv "${ARG_INTERFACE_DEPS}")
    endif()

    # ---------------------------------------------------------------
    # Step 1: deploy.py — stage .i file with pywraps injected
    # ---------------------------------------------------------------
    # Find pywraps that this module depends on
    file(GLOB _mod_pywraps_hpp "${IDAPYTHON_SOURCE_DIR}/pywraps/py_${_mod}*.hpp")
    file(GLOB _mod_pywraps_py  "${IDAPYTHON_SOURCE_DIR}/pywraps/py_${_mod}*.py")
    set(_mod_staged_pywraps "")
    foreach(_pw IN LISTS _mod_pywraps_hpp _mod_pywraps_py)
        get_filename_component(_pwname "${_pw}" NAME)
        list(APPEND _mod_staged_pywraps "${IDAPYTHON_ST_PYW}/${_pwname}")
    endforeach()

    add_custom_command(
        OUTPUT "${_st_swig_i}"
        COMMAND ${Python3_EXECUTABLE} "${_tools}/deploy.py"
            --pywraps "${IDAPYTHON_ST_PYW}"
            --template "swig/${_mod}.i"
            --output "${_st_swig_i}"
            --module "${_mod}"
            ${_lifecycle_flag}
            "--interface-dependencies=${_iface_deps_csv}"
            "--xml-doc-directory=${IDAPYTHON_PARSED_XML}"
        WORKING_DIRECTORY "${IDAPYTHON_SOURCE_DIR}"
        DEPENDS
            "${_swig_dir}/${_mod}.i"
            "${ARG_SWIG_HEADER}"
            "${ARG_PARSED_MARKER}"
            "${_tools}/deploy.py"
            ${_mod_staged_pywraps}
            ${_iface_dep_files}
            ${ARG_ALL_HOOKS}
        COMMENT "IDAPython [${_mod}]: deploy.py"
    )

    # ---------------------------------------------------------------
    # Step 2: SWIG — generate .cpp.in1, .h, ida_MOD.py
    # ---------------------------------------------------------------
    # Platform-specific SWIG flags
    set(_swig_platform_flags "")
    if(WIN32)
        list(APPEND _swig_platform_flags -D__NT__ -DWIN32 -D_USRDLL)
        list(APPEND _swig_platform_flags "-I${Python3_INCLUDE_DIRS}")
    elseif(APPLE)
        list(APPEND _swig_platform_flags -D__MAC__)
    else()
        list(APPEND _swig_platform_flags -D__LINUX__)
    endif()

    add_custom_command(
        OUTPUT "${_wrap_cpp_in1}" "${_wrap_h}" "${_wrap_py}"
        COMMAND "${SWIG_EXECUTABLE}" -python -DPY3=1 -threads -c++ -shadow
            -D__GNUC__ -DSWIG_PYTHON_LEGACY_BOOL=1
            ${_swig_platform_flags}
            -D__EA64__=1 -DMISSED_BC695
            -DSWIG_TYPE_TABLE=idaapi
            -I"${_tools}/typemaps-supplement"
            ${_iface_dep_defines}
            -I"${IDAPYTHON_ST_SWIG}"
            -I"${_sdk}"
            -DIDAPYTHON_MODULE_${_mod}=1
            -outdir "${IDAPYTHON_ST_WRAP}"
            -o "${_wrap_cpp_in1}"
            -oh "${_wrap_h}"
            "${_st_swig_i}"
        DEPENDS "${_st_swig_i}"
        COMMENT "IDAPython [${_mod}]: swig"
    )

    # ---------------------------------------------------------------
    # Step 3: patch_constants.py — .cpp.in1 → .cpp.in2
    # ---------------------------------------------------------------
    add_custom_command(
        OUTPUT "${_wrap_cpp_in2}"
        COMMAND ${Python3_EXECUTABLE} "${_tools}/patch_constants.py"
            -i "${_wrap_cpp_in1}"
            -o "${_wrap_cpp_in2}"
        DEPENDS "${_wrap_cpp_in1}" "${_tools}/patch_constants.py"
        COMMENT "IDAPython [${_mod}]: patch_constants"
    )

    # ---------------------------------------------------------------
    # Step 4: patch_codegen.py — .cpp.in2 → .cpp
    # ---------------------------------------------------------------
    set(_patches_file "${_tools}/patch_codegen/${_mod}.py")
    set(_batch_patches_file "${_tools}/patch_codegen/${_mod}_batch.py")

    add_custom_command(
        OUTPUT "${_wrap_cpp}"
        COMMAND ${Python3_EXECUTABLE} "${_tools}/patch_codegen.py"
            --input "${_wrap_cpp_in2}"
            --output "${_wrap_cpp}"
            --module "${_mod}"
            --xml-doc-directory "${IDAPYTHON_PARSED_XML}"
            --patches "${_patches_file}"
            --batch-patches "${_batch_patches_file}"
        DEPENDS
            "${_wrap_cpp_in2}"
            "${_tools}/patch_codegen.py"
            "${ARG_PARSED_MARKER}"
        COMMENT "IDAPython [${_mod}]: patch_codegen"
    )

    # ---------------------------------------------------------------
    # Step 5: patch_h_codegen.py — patch .h in place (stamp file)
    # ---------------------------------------------------------------
    set(_h_patches_file "${_tools}/patch_codegen/${_mod}_h.py")

    add_custom_command(
        OUTPUT "${_stamp_h}"
        COMMAND ${Python3_EXECUTABLE} "${_tools}/patch_h_codegen.py"
            --file "${_wrap_h}"
            --module "${_mod}"
            --patches "${_h_patches_file}"
        COMMAND ${CMAKE_COMMAND} -E touch "${_stamp_h}"
        DEPENDS "${_wrap_h}" "${_tools}/patch_h_codegen.py"
        COMMENT "IDAPython [${_mod}]: patch_h_codegen"
    )

    # ---------------------------------------------------------------
    # Step 6: patch_python_codegen.py — patch ida_MOD.py in place (stamp)
    # ---------------------------------------------------------------
    set(_py_patches_file "${_tools}/patch_codegen/ida_${_mod}.py")

    add_custom_command(
        OUTPUT "${_stamp_py}"
        COMMAND ${Python3_EXECUTABLE} "${_tools}/patch_python_codegen.py"
            --file "${_wrap_py}"
            --module "${_mod}"
            --patches "${_py_patches_file}"
        COMMAND ${CMAKE_COMMAND} -E touch "${_stamp_py}"
        DEPENDS "${_wrap_py}" "${_tools}/patch_python_codegen.py"
        COMMENT "IDAPython [${_mod}]: patch_python_codegen"
    )

    # ---------------------------------------------------------------
    # Step 7: patch_directors_cc.py — Windows only, patch .h in place
    # ---------------------------------------------------------------
    if(WIN32)
        add_custom_command(
            OUTPUT "${_stamp_dir_cc}"
            COMMAND ${Python3_EXECUTABLE} "${_tools}/patch_directors_cc.py"
                --file "${_wrap_h}"
            COMMAND ${CMAKE_COMMAND} -E touch "${_stamp_dir_cc}"
            DEPENDS "${_stamp_h}" "${_tools}/patch_directors_cc.py"
            COMMENT "IDAPython [${_mod}]: patch_directors_cc (Windows)"
        )
        set(_compile_h_dep "${_stamp_dir_cc}")
    else()
        set(_compile_h_dep "${_stamp_h}")
    endif()

    # ---------------------------------------------------------------
    # Step 8: Compile + link → _ida_MOD.pyd/.so
    # ---------------------------------------------------------------
    set(_target_name "_ida_${_mod}")

    add_library(${_target_name} SHARED "${_wrap_cpp}")

    # The .cpp depends on the .h being fully patched
    set_source_files_properties("${_wrap_cpp}" PROPERTIES
        OBJECT_DEPENDS "${_compile_h_dep};${_stamp_py}"
    )

    target_include_directories(${_target_name} PRIVATE
        "${IDASDK}/include"
        "${IDAPYTHON_SOURCE_DIR}"
        "${IDAPYTHON_ST_SWIG}"
        "${IDAPYTHON_ST_WRAP}"
        "${IDAPYTHON_BINARY_DIR}"
        "${Python3_INCLUDE_DIRS}"
    )

    target_compile_definitions(${_target_name} PRIVATE
        __IDP__
        __EA64__=1
        PY3=1
        Py_LIMITED_API=0x03090000
        SWIG_TYPE_TABLE=idaapi
        PLUGIN_SUBMODULE
        SWIG_DIRECTOR_NORTTI
        MISSED_BC695
        USE_STANDARD_FILE_FUNCTIONS
        ${IDAPROPLAT}
        $<$<PLATFORM_ID:Windows>:WIN32>
        $<$<PLATFORM_ID:Windows>:_WINDOWS>
    )

    # Link libraries
    set(_link_libs "${IDA_LIB_PATH}")

    # int128 library (exists in 9.3.1+)
    set(_int128_path "${IDA_LIB_DIR}/int128${IDA_STATIC_EXT}")
    if(EXISTS "${_int128_path}")
        list(APPEND _link_libs "${_int128_path}")
    endif()

    if(WIN32)
        # python3.lib = stable ABI import lib (Py_LIMITED_API)
        # idapython.lib must come AFTER python3.lib to avoid DLL detection issues
        # (see Python's dynload_win.c:GetPythonImport)
        get_filename_component(_python_lib_dir "${Python3_LIBRARIES}" DIRECTORY)
        list(APPEND _link_libs user32.lib "${_python_lib_dir}/python3.lib")
        list(APPEND _link_libs "${ARG_IMPLIB}")
    else()
        # Link directly against the idapython3 target — using -l won't find it
        # because the library has no "lib" prefix (idapython3.so, not libidapython3.so)
        list(APPEND _link_libs idapython3)
    endif()

    target_link_libraries(${_target_name} PRIVATE
        ida_addon_base
        ${_link_libs}
    )

    # Compiler/linker settings
    if(MSVC)
        set_target_properties(${_target_name} PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
        target_compile_options(${_target_name} PRIVATE
            /bigobj /Zc:strictStrings-
            /wd4100 /wd4125 /wd4296 /wd4647 /wd4700 /wd4706 /wd4800 /wd4996 /wd5205
        )
        target_link_options(${_target_name} PRIVATE /SUBSYSTEM:WINDOWS)
        # .pyd extension
        set_target_properties(${_target_name} PROPERTIES SUFFIX ".pyd")
    else()
        target_compile_options(${_target_name} PRIVATE
            -Wno-shadow -Wno-unused-parameter -Wno-attributes
            -Wno-delete-non-virtual-dtor -Wno-deprecated-declarations
            -Wno-format-nonliteral -Wno-write-strings
        )
        if(APPLE)
            target_compile_options(${_target_name} PRIVATE -Wno-deprecated-register)
            target_link_options(${_target_name} PRIVATE
                -Wl,-rpath,@loader_path/../../..
                -Wl,-undefined,dynamic_lookup
            )
        else()
            target_link_options(${_target_name} PRIVATE
                "-Wl,-rpath,$ORIGIN/../../.."
            )
        endif()
        set_target_properties(${_target_name} PROPERTIES SUFFIX ".so")
    endif()

    # RTTI enabled (SWIG directors need it)
    if(MSVC)
        target_compile_options(${_target_name} PRIVATE /GR)
    else()
        target_compile_options(${_target_name} PRIVATE -frtti)
    endif()

    # Unix: no "lib" prefix
    if(NOT WIN32)
        set_target_properties(${_target_name} PROPERTIES PREFIX "")
    endif()

    # Output to lib-dynload
    set_target_properties(${_target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "$<1:${IDAPYTHON_DEPLOY_LIBDIR}>"
        LIBRARY_OUTPUT_DIRECTORY "$<1:${IDAPYTHON_DEPLOY_LIBDIR}>"
    )

    ida_disable_warnings(${_target_name})

    # Make module depend on main plugin and extracted headers
    add_dependencies(${_target_name} idapython3 idapython_extract_headers)

    # ---------------------------------------------------------------
    # Step 9: pypasses.py — AST transformation on ida_MOD.py
    # ---------------------------------------------------------------
    set(_apidoc "${IDAPYTHON_SOURCE_DIR}/apidoc/ida_${_mod}.py")
    set(_passes "inject_doxygen,return_type_from_cpp_wrapper,pydoc_overrides,proto_overrides,argsify_for_dispatching_cpp,fix_known_types")

    add_custom_command(
        OUTPUT "${_wrap_py_final}"
        COMMAND ${Python3_EXECUTABLE} "${_tools}/pypasses.py"
            --input "${_wrap_py}"
            --idapython-module-name "ida_${_mod}"
            --doxygen-xml "${IDAPYTHON_PARSED_XML}"
            --cpp-wrapper "${_wrap_cpp}"
            --passes "${_passes}"
            --pydoc-overrides "${_apidoc}"
            --output "${_wrap_py_final}"
        WORKING_DIRECTORY "${IDAPYTHON_SOURCE_DIR}/tools"
        DEPENDS
            "${_stamp_py}"
            "${_wrap_cpp}"
            "${ARG_PARSED_MARKER}"
            "${_tools}/pypasses.py"
        COMMENT "IDAPython [${_mod}]: pypasses"
    )

    # ---------------------------------------------------------------
    # Step 10: Deploy ida_MOD.py to python directory
    # ---------------------------------------------------------------
    set(_deployed_py "${IDAPYTHON_DEPLOY_PYDIR}/ida_${_mod}.py")

    add_custom_command(
        OUTPUT "${_deployed_py}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_wrap_py_final}" "${_deployed_py}"
        DEPENDS "${_wrap_py_final}"
        COMMENT "IDAPython [${_mod}]: deploy ida_${_mod}.py"
    )

    # Export outputs to parent scope
    set("_IDAPYTHON_PY_${_mod}" "${_deployed_py}" PARENT_SCOPE)
    set("_IDAPYTHON_PY_FINAL_${_mod}" "${_wrap_py_final}" PARENT_SCOPE)
endfunction()
