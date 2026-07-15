# ===========================================================================
# plugins/idapython/cmake/idapython_body.cmake
# ===========================================================================
# Shared IDAPython build body: SWIG codegen pipeline, wrapper modules
# (_ida_*), the idapython3 plugin, and python/ deployment. A thin entrypoint
# fills the seam below, then include()s this file. The body reaches nothing
# outside the seam (no CMAKE_SOURCE_DIR, no external helpers or targets).
#
# Seam the includer must provide BEFORE include():
#   vars: IDAPYTHON_SRC GEN ST_SWIG ST_PYW ST_WRAP ST_PARSED_HEADERS
#         ST_SDK_DIR ST_SDK_EXTRA [_extra_sdk_outputs] [INTERNAL_ONLY_MODULES]
#         IDASDK_FILES DEPLOY_PYDIR DEPLOY_LIBDIR
#         _runtime_dir _lib_dir IDA_PYTHON IDA_SWIG IDA_SWIG_LIB
#         Python3_INCLUDE_DIRS Python3_LIBRARY_DIRS IDA_PYTHON_VERNAME
#         IDA_STUB_LIB IDA_DLLEXT IDAVER_MAJOR/MINOR/PATCH
#         platform: IDA_NT IDA_LINUX IDA_MAC IDA_UNIX IDA_ARM IDA_APPLE_SILICON
#         flags: IDA_FREE IDA_HOME IDA_TESTABLE_BUILD IDA_TELEMETRY [IDA_WARNINGS]
#   targets: idapython_parsed_headers, idapython_staging_sdk,
#            ${PARSED_HEADERS_MARKER}; optional: pro_includes base_includes
#            ida_stub sdk-package
#   functions: _ida_comment ida_module_warnings set_rtti_enabled
#              ida_compiler_flags (link target)
#
# Exports back to the includer (same scope via include()):
#   MODULE_NAMES MODULE_NAMES_CSV ALL_WRAPPER_TARGETS ALL_WRAPPER_PY_FINALS
#   ALL_WRAPPER_PYS ALL_WRAPPER_CPPS
# ===========================================================================

# Python extension suffix
if(IDA_NT)
    set(PYDLL_EXT ".pyd")
else()
    set(PYDLL_EXT ".so")
endif()

# Static lib/obj extensions
if(IDA_NT)
    set(_lib_ext ".lib")
    set(_obj_ext ".obj")
else()
    set(_lib_ext ".a")
    set(_obj_ext ".o")
endif()

# Module names list (order matters for api_contents)
set(MODULE_NAMES
    hexrays
    allins auto bitrange bytes dbg diskio dirtree entry expr fixup fpro frame
    funcs gdl graph ida idaapi idc idd idp ieee kernwin libfuncs lines loader
    lumina
)
if(IDA_TESTABLE_BUILD AND INTERNAL_ONLY_MODULES)
    list(APPEND MODULE_NAMES ${INTERNAL_ONLY_MODULES})
endif()
list(APPEND MODULE_NAMES
    moves nalt name netnode offset pro problems range registry regfinder
    search segment segregs srclang strlist tryblks typeinf ua xref
    mergemod merge undo
)

# Hexrays: not for Free
if(IDA_FREE)
    list(REMOVE_ITEM MODULE_NAMES hexrays)
endif()

# SWIG interface dependencies (cross-module)
set(SWIG_IFACE_bytes range)
set(SWIG_IFACE_dbg idd)
set(SWIG_IFACE_frame range)
set(SWIG_IFACE_funcs range)
set(SWIG_IFACE_gdl range)
set(SWIG_IFACE_graph gdl)
set(SWIG_IFACE_hexrays pro typeinf xref gdl)
set(SWIG_IFACE_idd range)
set(SWIG_IFACE_idp bitrange)
set(SWIG_IFACE_lines range)
set(SWIG_IFACE_segment range)
set(SWIG_IFACE_segregs range)
set(SWIG_IFACE_typeinf idp)
set(SWIG_IFACE_tryblks range)

# Lifecycle-aware modules
set(MODULE_LIFECYCLE_ARG_bytes "--lifecycle-aware")
set(MODULE_LIFECYCLE_ARG_hexrays "--lifecycle-aware")
set(MODULE_LIFECYCLE_ARG_idaapi "--lifecycle-aware")
set(MODULE_LIFECYCLE_ARG_kernwin "--lifecycle-aware")
set(MODULE_LIFECYCLE_ARG_typeinf "--lifecycle-aware")

# SWIG platform flags
if(IDA_NT)
    set(SWIG_PLATFORM_FLAGS -D__NT__ -DWIN32 -D_USRDLL "-I${Python3_INCLUDE_DIRS}")
elseif(IDA_MAC)
    set(SWIG_PLATFORM_FLAGS -D__MAC__)
elseif(IDA_LINUX)
    set(SWIG_PLATFORM_FLAGS -D__LINUX__)
endif()

# Full SWIG flags
set(SWIGFLAGS
    ${SWIG_PLATFORM_FLAGS}
    # Absolute -I so SWIG's -MMD depfile resolves under the build dir.
    "-I${IDAPYTHON_SRC}/tools/typemaps-supplement"
    "-I${IDA_SWIG_LIB}/python"
    "-I${IDA_SWIG_LIB}"
    -DSWIG_TYPE_TABLE=idaapi
    -DMISSED_BC695
)
if(IDA_TESTABLE_BUILD)
    list(APPEND SWIGFLAGS -DTESTABLE_BUILD)
endif()

# ST_INCLUDES: SWIG include paths for SDK headers
# Will be appended to after ST_SDK_EXTRA is defined in Section 2
set(SWIG_ST_INCLUDES "")

# WITH_HEXRAYS for SWIG
if(NOT IDA_HOME AND NOT IDA_FREE)
    set(SWIG_HEXRAYS_FLAG -DWITH_HEXRAYS)
else()
    set(SWIG_HEXRAYS_FLAG "")
endif()
# Build SWIG_ST_INCLUDES: -I flags for SDK headers used by SWIG
# Make equivalent: ST_INCLUDES = -I$(ST_SDK) [-I$(ST_SDK_EXTRA)]
set(SWIG_ST_INCLUDES "-I${ST_SDK_DIR}")
if(IDA_TESTABLE_BUILD AND ST_SDK_EXTRA)
    list(APPEND SWIG_ST_INCLUDES "-I${ST_SDK_EXTRA}")
endif()
# 3c. Hook generation (6 files with injected hooks)
set(GENHOOKS "${IDAPYTHON_SRC}/tools/genhooks")

# Transitive Python imports - ninja doesn't scan them.
set(_PY_WRITEUTIL "${IDAPYTHON_SRC}/tools/_writeutil.py")
set(_PY_DOXYGEN_UTILS "${IDAPYTHON_SRC}/tools/doxygen_utils.py")
set(_PY_GENHOOKS_DEPS
    "${IDAPYTHON_SRC}/tools/hooks_utils.py"
    "${_PY_DOXYGEN_UTILS}"
    "${GENHOOKS}/recipe_index.py"
    "${GENHOOKS}/recipe_dbghooks.py"
    "${GENHOOKS}/recipe_hexrays.py"
    "${GENHOOKS}/recipe_idbhooks.py"
    "${GENHOOKS}/recipe_idphooks.py"
    "${GENHOOKS}/recipe_uihooks.py"
    "${GENHOOKS}/recipe_viewhooks.py"
)

set(HOOK_OUTPUTS "")

# Helper macro to generate hook commands
macro(idapython_add_hook _target_file _class_name _marker _qualifier)
    set(_src "${IDAPYTHON_SRC}/pywraps/${_target_file}")
    set(_dst "${ST_PYW}/${_target_file}")
    add_custom_command(OUTPUT "${_dst}"
        COMMAND "${IDA_PYTHON}" "${GENHOOKS}/genhooks.py"
            -i "${_src}" -o "${_dst}"
            -c "${_class_name}"
            -x "${ST_PARSED_HEADERS}"
            -m "${_marker}"
            -q "${_qualifier}"
        DEPENDS "${_src}" idapython_parsed_headers
                "${PARSED_HEADERS_MARKER}"
                "${GENHOOKS}/genhooks.py"
                ${_PY_GENHOOKS_DEPS}
                "${_PY_WRITEUTIL}"
        COMMENT "genhooks: ${_target_file} (${_class_name})"
        VERBATIM
    )
    list(APPEND HOOK_OUTPUTS "${_dst}")
endmacro()

idapython_add_hook(py_idp.hpp              IDP_Hooks      hookgenIDP      "processor_t::")
idapython_add_hook(py_idp_idbhooks.hpp     IDB_Hooks      hookgenIDB      "idb_event::")
idapython_add_hook(py_dbg.hpp              DBG_Hooks      hookgenDBG      "dbg_notification_t::")
idapython_add_hook(py_kernwin.hpp          UI_Hooks       hookgenUI       "ui_notification_t::")
idapython_add_hook(py_kernwin_viewhooks.hpp View_Hooks    hookgenVIEW     "view_notification_t::")
idapython_add_hook(py_hexrays_hooks.hpp    Hexrays_Hooks  hookgenHEXRAYS  "hexrays_event_t::")

# 3d. Simple pywraps copy (all other files from pywraps/)
file(GLOB _pywraps_hpp "${IDAPYTHON_SRC}/pywraps/*.hpp")
file(GLOB _pywraps_py "${IDAPYTHON_SRC}/pywraps/*.py")
set(_all_pywraps ${_pywraps_hpp} ${_pywraps_py})

# Files that need hook injection (already handled above)
set(HOOK_FILES
    py_idp.hpp py_idp_idbhooks.hpp py_dbg.hpp
    py_kernwin.hpp py_kernwin_viewhooks.hpp py_hexrays_hooks.hpp
)

set(SIMPLE_PYWRAP_OUTPUTS "")
foreach(_src ${_all_pywraps})
    get_filename_component(_fname "${_src}" NAME)
    # Skip files handled by hook generation
    list(FIND HOOK_FILES "${_fname}" _hook_idx)
    if(_hook_idx EQUAL -1)
        set(_dst "${ST_PYW}/${_fname}")
        _ida_comment(_comment "copy pywrap: ${_fname}")
        add_custom_command(OUTPUT "${_dst}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst}"
            DEPENDS "${_src}"
            COMMENT "${_comment}"
        )
        list(APPEND SIMPLE_PYWRAP_OUTPUTS "${_dst}")
    endif()
endforeach()

add_custom_target(idapython_pywraps DEPENDS ${HOOK_OUTPUTS} ${SIMPLE_PYWRAP_OUTPUTS})
add_dependencies(idapython_pywraps idapython_parsed_headers)
# ============================================================================
# Section 4: SWIG Header Generation
# ============================================================================

# Build comma-separated module list
string(REPLACE ";" "," MODULE_NAMES_CSV "${MODULE_NAMES}")

add_custom_command(OUTPUT "${ST_SWIG}/header.i"
    COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/genswigheader.py"
        -i "${IDAPYTHON_SRC}/tools/deploy/header.i.in"
        -o "${ST_SWIG}/header.i"
        -s "${ST_SDK_DIR}"
    DEPENDS idapython_staging_sdk
            ${IDASDK_FILES}
            "${IDAPYTHON_SRC}/tools/deploy/header.i.in"
            "${IDAPYTHON_SRC}/tools/genswigheader.py"
            "${_PY_WRITEUTIL}"
    COMMENT "genswigheader: header.i"
    VERBATIM
)
add_custom_target(idapython_swig_header DEPENDS "${ST_SWIG}/header.i")
# ============================================================================
# Section 5: SWIG Pipeline (per-module)
# ============================================================================

# Collect all wrapper module targets
set(ALL_WRAPPER_TARGETS "")
set(ALL_WRAPPER_PY_FINALS "")
set(ALL_WRAPPER_PYS "")
set(ALL_WRAPPER_CPPS "")

set(_swig_quiet_flag "")
if(IDA_WARNINGS STREQUAL "none")
    set(_swig_quiet_flag "-w315,361,503,509")
endif()

foreach(_mod ${MODULE_NAMES})

    # --- 5a. Deploy .i (tools/deploy.py) ---

    # Build interface dependency arguments
    set(_iface_deps "${SWIG_IFACE_${_mod}}")
    if(_iface_deps)
        string(REPLACE ";" "," _iface_deps_csv "${_iface_deps}")
        set(_iface_deps_arg "--interface-dependencies=${_iface_deps_csv}")
        set(_iface_dep_files "")
        foreach(_dep ${_iface_deps})
            list(APPEND _iface_dep_files "${ST_SWIG}/${_dep}.i")
        endforeach()
    else()
        set(_iface_deps_arg "--interface-dependencies=")
        set(_iface_dep_files "")
    endif()

    # Lifecycle argument
    set(_lifecycle_arg "${MODULE_LIFECYCLE_ARG_${_mod}}")

    # Per-module file-level deps on staged pywraps. DEPENDS on the
    # idapython_pywraps target alone is order-only in Ninja, so edits to
    # e.g. py_hexrays.py wouldn't re-trigger deploy.py.
    set(_mod_pywrap_deps "")
    foreach(_pw_src ${_all_pywraps})
        get_filename_component(_pw_name "${_pw_src}" NAME)
        if("${_pw_name}" MATCHES "^py_${_mod}(_.*)?\\.(py|hpp)$")
            list(APPEND _mod_pywrap_deps "${ST_PYW}/${_pw_name}")
        endif()
    endforeach()

    add_custom_command(OUTPUT "${ST_SWIG}/${_mod}.i"
        COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/deploy.py"
            --pywraps "${ST_PYW}"
            --template "${IDAPYTHON_SRC}/swig/${_mod}.i"
            --output "${ST_SWIG}/${_mod}.i"
            --module "${_mod}"
            ${_lifecycle_arg}
            ${_iface_deps_arg}
            --xml-doc-directory "${ST_PARSED_HEADERS}"
        DEPENDS idapython_pywraps
                idapython_swig_header
                idapython_parsed_headers
                "${PARSED_HEADERS_MARKER}"
                "${IDAPYTHON_SRC}/swig/${_mod}.i"
                "${IDAPYTHON_SRC}/tools/deploy.py"
                "${_PY_WRITEUTIL}"
                ${_iface_dep_files}
                ${_mod_pywrap_deps}
        COMMENT "deploy: ${_mod}.i"
        VERBATIM
    )

    # --- 5b. SWIG codegen ---
    # Per-module deps via SWIG's -MMD depfile.
    add_custom_command(
        OUTPUT "${ST_WRAP}/${_mod}.cpp.in1"
               "${ST_WRAP}/${_mod}.h"
               "${ST_WRAP}/ida_${_mod}.py"
        COMMAND "${IDA_SWIG}" ${SWIG_HEXRAYS_FLAG}
            -python -DPY3=1 -threads -c++ -shadow
            -D__GNUC__ -DSWIG_PYTHON_LEGACY_BOOL=1
            ${SWIGFLAGS}
            ${_swig_quiet_flag}
            -D__EA64__
            "-I${ST_SWIG}"
            -outdir "${ST_WRAP}"
            -o "${ST_WRAP}/${_mod}.cpp.in1"
            -oh "${ST_WRAP}/${_mod}.h"
            -MMD -MF "${ST_WRAP}/${_mod}.d"
            ${SWIG_ST_INCLUDES}
            -DIDAPYTHON_MODULE_${_mod}=1
            "${ST_SWIG}/${_mod}.i"
        DEPENDS "${ST_SWIG}/${_mod}.i"
                "${ST_SWIG}/header.i"
                idapython_staging_sdk
                ${_extra_sdk_outputs}
        DEPFILE "${ST_WRAP}/${_mod}.d"
        WORKING_DIRECTORY "${IDAPYTHON_SRC}"
        COMMENT "swig: ${_mod}"
        VERBATIM
    )

    # --- 5c. Patch constants ---
    add_custom_command(OUTPUT "${ST_WRAP}/${_mod}.cpp.in2"
        COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/patch_constants.py"
            -i "${ST_WRAP}/${_mod}.cpp.in1"
            -o "${ST_WRAP}/${_mod}.cpp.in2"
        DEPENDS "${ST_WRAP}/${_mod}.cpp.in1"
                "${IDAPYTHON_SRC}/tools/patch_constants.py"
                "${_PY_WRITEUTIL}"
        COMMENT "patch_constants: ${_mod}"
        VERBATIM
    )

    # --- 5d. Patch codegen ---
    set(_mod_patch "${IDAPYTHON_SRC}/tools/patch_codegen/${_mod}.py")
    set(_mod_patch_batch "${IDAPYTHON_SRC}/tools/patch_codegen/${_mod}_batch.py")
    set(_mod_patch_deps "")
    if(EXISTS "${_mod_patch}")
        list(APPEND _mod_patch_deps "${_mod_patch}")
    endif()
    if(EXISTS "${_mod_patch_batch}")
        list(APPEND _mod_patch_deps "${_mod_patch_batch}")
    endif()
    add_custom_command(OUTPUT "${ST_WRAP}/${_mod}.cpp"
        COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/patch_codegen.py"
            --input "${ST_WRAP}/${_mod}.cpp.in2"
            --output "${ST_WRAP}/${_mod}.cpp"
            --module "${_mod}"
            --xml-doc-directory "${ST_PARSED_HEADERS}"
            --patches "${_mod_patch}"
            --batch-patches "${_mod_patch_batch}"
        DEPENDS "${ST_WRAP}/${_mod}.cpp.in2"
                idapython_parsed_headers
                "${PARSED_HEADERS_MARKER}"
                "${IDAPYTHON_SRC}/tools/patch_codegen.py"
                "${_PY_DOXYGEN_UTILS}"
                "${_PY_WRITEUTIL}"
                ${_mod_patch_deps}
        COMMENT "patch_codegen: ${_mod}.cpp"
        VERBATIM
    )

    # --- 5e. Patch header ---
    set(_mod_patch_h "${IDAPYTHON_SRC}/tools/patch_codegen/${_mod}_h.py")
    set(_mod_patch_h_deps "")
    if(EXISTS "${_mod_patch_h}")
        list(APPEND _mod_patch_h_deps "${_mod_patch_h}")
    endif()
    add_custom_command(OUTPUT "${ST_WRAP}/${_mod}.h.patched"
        COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/patch_h_codegen.py"
            --file "${ST_WRAP}/${_mod}.h"
            --module "${_mod}"
            --patches "${_mod_patch_h}"
        COMMAND ${CMAKE_COMMAND} -E touch "${ST_WRAP}/${_mod}.h.patched"
        DEPENDS "${ST_WRAP}/${_mod}.h"
                "${IDAPYTHON_SRC}/tools/patch_h_codegen.py"
                "${_PY_WRITEUTIL}"
                ${_mod_patch_h_deps}
        COMMENT "patch_h_codegen: ${_mod}.h"
        VERBATIM
    )

    # --- 5f. Patch Python ---
    set(_mod_patch_py "${IDAPYTHON_SRC}/tools/patch_codegen/ida_${_mod}.py")
    set(_mod_patch_py_deps "")
    if(EXISTS "${_mod_patch_py}")
        list(APPEND _mod_patch_py_deps "${_mod_patch_py}")
    endif()
    add_custom_command(OUTPUT "${ST_WRAP}/ida_${_mod}.py.patched"
        COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/patch_python_codegen.py"
            --file "${ST_WRAP}/ida_${_mod}.py"
            --module "${_mod}"
            --patches "${_mod_patch_py}"
        COMMAND ${CMAKE_COMMAND} -E touch "${ST_WRAP}/ida_${_mod}.py.patched"
        DEPENDS "${ST_WRAP}/ida_${_mod}.py"
                "${IDAPYTHON_SRC}/tools/patch_python_codegen.py"
                ${_mod_patch_py_deps}
        COMMENT "patch_python_codegen: ida_${_mod}.py"
        VERBATIM
    )

    # --- 5g. Python passes (pypasses.py) ---
    set(_pydoc_override "${IDAPYTHON_SRC}/apidoc/ida_${_mod}.py")
    if(NOT EXISTS "${_pydoc_override}")
        set(_pydoc_override "")
    endif()
    add_custom_command(OUTPUT "${ST_WRAP}/ida_${_mod}.py.final"
        COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/pypasses.py"
            --input "${ST_WRAP}/ida_${_mod}.py"
            --idapython-module-name "ida_${_mod}"
            --doxygen-xml "${ST_PARSED_HEADERS}"
            --cpp-wrapper "${ST_WRAP}/${_mod}.cpp"
            --passes "inject_doxygen,return_type_from_cpp_wrapper,pydoc_overrides,proto_overrides,argsify_for_dispatching_cpp,fix_known_types"
            --pydoc-overrides "${IDAPYTHON_SRC}/apidoc/ida_${_mod}.py"
            --output "${ST_WRAP}/ida_${_mod}.py.final"
            --debug > "${ST_WRAP}/ida_${_mod}.pydoc_injection"
        DEPENDS "${ST_WRAP}/${_mod}.cpp"
                "${ST_WRAP}/ida_${_mod}.py.patched"
                idapython_parsed_headers
                "${PARSED_HEADERS_MARKER}"
                ${_pydoc_override}
                "${IDAPYTHON_SRC}/tools/pypasses.py"
        COMMENT "pypasses: ida_${_mod}.py"
        VERBATIM
    )

    list(APPEND ALL_WRAPPER_PY_FINALS "${ST_WRAP}/ida_${_mod}.py.final")
    list(APPEND ALL_WRAPPER_PYS "${ST_WRAP}/ida_${_mod}.py")
    list(APPEND ALL_WRAPPER_CPPS "${ST_WRAP}/${_mod}.cpp")

    # ========================================================================
    # Section 5h: Compile wrapper module (_ida_X.so/.pyd)
    # ========================================================================

    set(_mod_target "_ida_${_mod}")
    add_library(${_mod_target} SHARED "${ST_WRAP}/${_mod}.cpp")

    # Ensure generated header is patched before compilation.
    # Adding .h as a GENERATED source creates a file-level dependency that
    # VS/MSBuild respects (target-level add_dependencies alone is not enough).
    add_custom_target(idapython_swig_${_mod}_headers
        DEPENDS "${ST_WRAP}/${_mod}.h.patched"
    )
    target_sources(${_mod_target} PRIVATE "${ST_WRAP}/${_mod}.h")
    set_source_files_properties("${ST_WRAP}/${_mod}.h" PROPERTIES
        GENERATED TRUE HEADER_FILE_ONLY TRUE)
    add_dependencies(${_mod_target} idapython_swig_${_mod}_headers)
    add_dependencies(${_mod_target} idapython_staging_sdk)

    set_target_properties(${_mod_target} PROPERTIES
        PREFIX ""
        OUTPUT_NAME "_ida_${_mod}"
        SUFFIX "${PYDLL_EXT}"
        LIBRARY_OUTPUT_DIRECTORY "${DEPLOY_LIBDIR}"
        RUNTIME_OUTPUT_DIRECTORY "${DEPLOY_LIBDIR}"
    )

    target_include_directories(${_mod_target} PRIVATE
        "${IDAPYTHON_SRC}"
        "${ST_SWIG}"
        "${ST_SDK_DIR}"
        "${Python3_INCLUDE_DIRS}"
        "${GEN}"
    )
    if(IDA_TESTABLE_BUILD AND ST_SDK_EXTRA)
        target_include_directories(${_mod_target} PRIVATE "${ST_SDK_EXTRA}")
    endif()

    target_compile_definitions(${_mod_target} PRIVATE
        $<$<BOOL:${IDA_MAC}>:__MAC__>
        $<$<BOOL:${IDA_LINUX}>:__LINUX__>
        $<$<BOOL:${IDA_NT}>:__NT__>
        $<$<BOOL:${IDA_ARM}>:__ARM__>
        $<$<BOOL:${IDA_APPLE_SILICON}>:__APPLE_SILICON__>
        $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
        $<$<CONFIG:Debug>:_DEBUG>
        __EA64__
        $<$<BOOL:${IDA_TESTABLE_BUILD}>:TESTABLE_BUILD>
        $<$<BOOL:${IDA_TELEMETRY}>:TELEMETRY>
        PY3=1
        "Py_LIMITED_API=0x03090000"
        MISSED_BC695
        SWIG_TYPE_TABLE=idaapi
        USE_STANDARD_FILE_FUNCTIONS
        PLUGIN_SUBMODULE
        SWIG_DIRECTOR_NORTTI
        "IDAVER_MAJOR=${IDAVER_MAJOR}"
        "IDAVER_MINOR=${IDAVER_MINOR}"
        "IDAVER_PATCH=${IDAVER_PATCH}"
        __EXPR_SRC
    )
    if(NOT IDA_HOME AND NOT IDA_FREE)
        target_compile_definitions(${_mod_target} PRIVATE WITH_HEXRAYS)
    endif()

    # Enable RTTI (needed for SWIG directors)
    # Disable NO_OBSOLETE_FUNCS: makefile line 654 clears it for idapython
    # SWIG generates wrappers for deprecated functions, so they must be visible
    # SWIG wrappers need deprecated functions visible — NO_OBSOLETE_FUNCS is
    # applied per-target by helpers, so these modules (created directly) don't get it.
    if(IDA_MAC OR IDA_LINUX)
        target_compile_options(${_mod_target} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-frtti>
        )
    elseif(IDA_NT)
        set_rtti_enabled(${_mod_target} ON)
        target_compile_options(${_mod_target} PRIVATE
            /bigobj /Zc:strictStrings-
        )
        target_compile_definitions(${_mod_target} PRIVATE
            $<$<CONFIG:Debug>:SWIG_PYTHON_INTERPRETER_NO_DEBUG>)
    endif()
    # SWIG-generated code is noisy (shadows, non-literal formats, unused params,
    # ...). Suppress at source level so it wins over ida_compiler_flags.
    ida_module_warnings(${_mod_target} idapython)

    # Linking
    target_link_libraries(${_mod_target} PRIVATE
        "${IDA_STUB_LIB}"
        "${_lib_dir}/int128${_lib_ext}"
    )
    if(IDA_MAC)
        target_link_libraries(${_mod_target} PRIVATE idapython3)
        target_link_options(${_mod_target} PRIVATE
            -Wl,-undefined,dynamic_lookup
            "-Wl,-rpath,@loader_path/../../.."
        )
        set_target_properties(${_mod_target} PROPERTIES SKIP_BUILD_RPATH TRUE)
    elseif(IDA_LINUX)
        target_link_libraries(${_mod_target} PRIVATE idapython3)
        target_link_options(${_mod_target} PRIVATE
            "-Wl,-soname,_ida_${_mod}${PYDLL_EXT}"
        )
        set_target_properties(${_mod_target} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN/../../.."
        )
    elseif(IDA_NT)
        add_dependencies(${_mod_target} idapython3)
        target_link_directories(${_mod_target} PRIVATE "${Python3_LIBRARY_DIRS}")
        target_link_libraries(${_mod_target} PRIVATE
            user32.lib
            python3.lib
            "${GEN}/idapython.lib"
        )
    endif()

    target_link_libraries(${_mod_target} PRIVATE ida_compiler_flags)

    list(APPEND ALL_WRAPPER_TARGETS ${_mod_target})

endforeach()
# ============================================================================
# Section 6: Plugin principal idapython3
# ============================================================================

# pywraps.cpp and extapi.cpp are #included by idapython.cpp, not compiled separately
add_library(idapython3 SHARED
    "${IDAPYTHON_SRC}/idapython.cpp"
)

# idapython3 depends on SDK being available
add_dependencies(idapython3 idapython_staging_sdk)
if(TARGET sdk-package)
    add_dependencies(idapython3 sdk-package)
endif()

# Auxiliary targets (e.g. API checks) are wired by the includer, not here.

set_target_properties(idapython3 PROPERTIES
    PREFIX ""
    OUTPUT_NAME "idapython3"
    SUFFIX "${IDA_DLLEXT}"
    LIBRARY_OUTPUT_DIRECTORY "${_runtime_dir}/plugins"
    RUNTIME_OUTPUT_DIRECTORY "${_runtime_dir}/plugins"
)

target_include_directories(idapython3 PRIVATE
    "${IDAPYTHON_SRC}"
    "${ST_SDK_DIR}"
    "${Python3_INCLUDE_DIRS}"
    "${GEN}"
)

target_compile_definitions(idapython3 PRIVATE
    $<$<BOOL:${IDA_MAC}>:__MAC__>
    $<$<BOOL:${IDA_LINUX}>:__LINUX__>
    $<$<BOOL:${IDA_NT}>:__NT__>
    $<$<BOOL:${IDA_ARM}>:__ARM__>
    $<$<BOOL:${IDA_APPLE_SILICON}>:__APPLE_SILICON__>
    $<$<NOT:$<CONFIG:Debug>>:NDEBUG>
    $<$<CONFIG:Debug>:_DEBUG>
    __EA64__
    $<$<BOOL:${IDA_TESTABLE_BUILD}>:TESTABLE_BUILD>
    $<$<BOOL:${IDA_TELEMETRY}>:TELEMETRY>
    INDIRECT_PYTHON_API
    PY3=1
    "Py_LIMITED_API=0x03090000"
    MISSED_BC695
    SWIG_TYPE_TABLE=idaapi
    USE_STANDARD_FILE_FUNCTIONS
    "IDAVER_MAJOR=${IDAVER_MAJOR}"
    "IDAVER_MINOR=${IDAVER_MINOR}"
    "IDAVER_PATCH=${IDAVER_PATCH}"
    __EXPR_SRC
)

# Suppress warnings for pywraps.cpp (SWIG-related code), source-level.
ida_module_warnings(idapython3 idapython)

# Platform-specific linking
target_link_libraries(idapython3 PRIVATE "${IDA_STUB_LIB}")
if(IDA_MAC)
    target_link_options(idapython3 PRIVATE
        "-Wl,-weak-l${IDA_PYTHON_VERNAME}"
        -flat_namespace
    )
    if(Python3_LIBRARY_DIRS)
        target_link_directories(idapython3 PRIVATE "${Python3_LIBRARY_DIRS}")
    endif()
    set_target_properties(idapython3 PROPERTIES
        INSTALL_NAME_DIR "@rpath/plugins"
        BUILD_WITH_INSTALL_NAME_DIR ON
        SKIP_BUILD_RPATH TRUE
    )
elseif(IDA_LINUX)
    target_link_options(idapython3 PRIVATE
        "-Wl,--version-script=${IDAPYTHON_SRC}/idapython.script"
        "-Wl,-soname,idapython3${IDA_DLLEXT}"
    )
    set_target_properties(idapython3 PROPERTIES
        BUILD_WITH_INSTALL_RPATH TRUE
        INSTALL_RPATH "$ORIGIN/.."
    )
elseif(IDA_NT)
    set_target_properties(idapython3 PROPERTIES
        LINK_FLAGS "/DLL /DEF:${IDAPYTHON_SRC}/idapython_implib.def"
        ARCHIVE_OUTPUT_DIRECTORY "${GEN}"
        ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${GEN}"
        ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${GEN}"
        ARCHIVE_OUTPUT_DIRECTORY_RELWITHDEBINFO "${GEN}"
        ARCHIVE_OUTPUT_NAME "idapython"
    )
endif()

target_link_libraries(idapython3 PRIVATE ida_compiler_flags)
if(TARGET ida_stub)
    add_dependencies(idapython3 ida_stub)
endif()
if(TARGET pro_includes)
    add_dependencies(idapython3 pro_includes)
endif()
if(TARGET base_includes)
    add_dependencies(idapython3 base_includes)
endif()

# Copy config file
_ida_comment(_comment "Copying idapython.cfg to cfg/")
add_custom_command(TARGET idapython3 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${_runtime_dir}/cfg"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${IDAPYTHON_SRC}/idapython.cfg"
        "${_runtime_dir}/cfg/idapython.cfg"
    COMMENT "${_comment}"
)
# ============================================================================
# Section 9: Python files deployment
# ============================================================================

# 9a. Simple Python file copies
set(_pyfile_outputs "")

macro(idapython_deploy_pyfile _src_rel _dst_name)
    set(_src "${IDAPYTHON_SRC}/${_src_rel}")
    set(_dst "${DEPLOY_PYDIR}/${_dst_name}")
    add_custom_command(OUTPUT "${_dst}"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPLOY_PYDIR}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst}"
        DEPENDS "${_src}"
        COMMENT "deploy: ${_src_rel}"
    )
    list(APPEND _pyfile_outputs "${_dst}")
endmacro()

idapython_deploy_pyfile(python/idc.py           idc.py)
idapython_deploy_pyfile(python/idautils.py      idautils.py)
idapython_deploy_pyfile(python/idadex.py        idadex.py)
idapython_deploy_pyfile(python/lumina_model.py  lumina_model.py)

# 9b. Generated Python files (init.py and idaapi.py via genidaapi.py)
add_custom_command(OUTPUT "${DEPLOY_PYDIR}/init.py"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPLOY_PYDIR}"
    COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/genidaapi.py"
        -i "${IDAPYTHON_SRC}/python/init.py"
        -o "${DEPLOY_PYDIR}/init.py"
        -m "${MODULE_NAMES_CSV}"
    DEPENDS "${IDAPYTHON_SRC}/python/init.py"
            "${IDAPYTHON_SRC}/tools/genidaapi.py"
            ${ALL_WRAPPER_PY_FINALS}
    COMMENT "genidaapi: init.py"
    VERBATIM
)
list(APPEND _pyfile_outputs "${DEPLOY_PYDIR}/init.py")

add_custom_command(OUTPUT "${DEPLOY_PYDIR}/idaapi.py"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPLOY_PYDIR}"
    COMMAND "${IDA_PYTHON}" "${IDAPYTHON_SRC}/tools/genidaapi.py"
        -i "${IDAPYTHON_SRC}/python/idaapi.py"
        -o "${DEPLOY_PYDIR}/idaapi.py"
        -m "${MODULE_NAMES_CSV}"
    DEPENDS "${IDAPYTHON_SRC}/python/idaapi.py"
            "${IDAPYTHON_SRC}/tools/genidaapi.py"
            ${ALL_WRAPPER_PY_FINALS}
    COMMENT "genidaapi: idaapi.py"
    VERBATIM
)
list(APPEND _pyfile_outputs "${DEPLOY_PYDIR}/idaapi.py")

# 9c. Deploy generated ida_*.py modules
foreach(_mod ${MODULE_NAMES})
    add_custom_command(OUTPUT "${DEPLOY_PYDIR}/ida_${_mod}.py"
        COMMAND ${CMAKE_COMMAND} -E make_directory "${DEPLOY_PYDIR}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${ST_WRAP}/ida_${_mod}.py.final"
            "${DEPLOY_PYDIR}/ida_${_mod}.py"
        DEPENDS "${ST_WRAP}/ida_${_mod}.py.final"
        COMMENT "deploy: ida_${_mod}.py"
    )
    list(APPEND _pyfile_outputs "${DEPLOY_PYDIR}/ida_${_mod}.py")
endforeach()

# 9d. Deploy examples
if(EXISTS "${IDAPYTHON_SRC}/examples")
    # Deploy .py files + index.md + README.md (Make deploys all three)
    file(GLOB_RECURSE _example_files RELATIVE "${IDAPYTHON_SRC}/examples" "${IDAPYTHON_SRC}/examples/*.py")
    list(APPEND _example_files index.md README.md)
    foreach(_example ${_example_files})
        set(_src "${IDAPYTHON_SRC}/examples/${_example}")
        set(_dst "${DEPLOY_PYDIR}/examples/${_example}")
        get_filename_component(_dst_dir "${_dst}" DIRECTORY)
        add_custom_command(OUTPUT "${_dst}"
            COMMAND ${CMAKE_COMMAND} -E make_directory "${_dst_dir}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst}"
            DEPENDS "${_src}"
            COMMENT "deploy: examples/${_example}"
        )
        list(APPEND _pyfile_outputs "${_dst}")
    endforeach()
endif()

add_custom_target(idapython_pyfiles ALL DEPENDS ${_pyfile_outputs})
