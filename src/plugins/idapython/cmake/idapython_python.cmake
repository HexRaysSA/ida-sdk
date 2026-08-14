# ===========================================================================
# plugins/idapython/cmake/idapython_python.cmake
# ===========================================================================
# Resolves the Python that IDAPython builds against. Included by both the
# standalone build (idapython_shims.cmake) and by IDA's own build, so it must
# stay self-contained: no IDAPython variables, and nothing beyond the platform
# flags (IDA_NT, IDA_ARCH) that both sides define.
#
#   ida_find_python()
#     Honours cache vars IDA_PYTHON / IDA_PYTHON_VERSION_MINOR, otherwise
#     auto-detects the lowest-minor Python in the supported range. Populates
#     Python3_EXECUTABLE / Python3_VERSION / Python3_INCLUDE_DIRS /
#     Python3_LIBRARY_DIRS, plus aliases IDA_PYTHON, IDA_PYTHON_VERNAME.
#     Handles Windows (stable-ABI python3.lib generation, so no Python
#     "Development" install is needed) and cross-compile include overrides.
#
# Overrides (cache vars):
#   IDA_PYTHON                - executable path or name
#   IDA_PYTHON_VERSION_MINOR  - exact minor version (e.g. 12)
#   IDA_PYTHON_VERSION_SUFFIX - suffix appended to IDA_PYTHON_VERNAME
#   IDA_PYTHON_COMPONENTS     - FindPython3 component set for the native case
#                               (default: Interpreter Development)
# ===========================================================================

# Captured at include time: the stable-ABI .def sits next to this file, and
# CMAKE_CURRENT_LIST_DIR inside a function refers to the defining file.
set(_IDAPYTHON_PY_DIR "${CMAKE_CURRENT_LIST_DIR}")

set(_IDA_PYTHON_SUPPORTED_MINORS 9 10 11 12 13 14)

# -----------------------------------------------------------------------------
# Clear the cache variables FindPython3 reuses internally. `unset(... CACHE)`
# on Python3_EXECUTABLE alone isn't enough - FindPython3 remembers previous
# results in `_Python3_*` INTERNAL cache entries and `Python3_*` result vars.
# Call this before each iteration of the auto-detect loop.
# -----------------------------------------------------------------------------
function(_ida_reset_python_cache)
    foreach(_v
            Python3_EXECUTABLE
            Python3_INCLUDE_DIR Python3_INCLUDE_DIRS
            Python3_LIBRARY Python3_LIBRARIES
            Python3_LIBRARY_RELEASE Python3_LIBRARY_DEBUG
            Python3_LIBRARY_DIRS
            Python3_RUNTIME_LIBRARY_DIRS
            _Python3_EXECUTABLE
            _Python3_INCLUDE_DIR
            _Python3_LIBRARY_RELEASE _Python3_LIBRARY_DEBUG
            _Python3_Compiler_REASON_FAILURE
            _Python3_Development_REASON_FAILURE
            _Python3_Interpreter_REASON_FAILURE
            _Python3_DEVELOPMENT_MODULE_SIGNATURE
            _Python3_DEVELOPMENT_EMBED_SIGNATURE)
        unset(${_v} CACHE)
    endforeach()
    foreach(_v
            Python3_FOUND Python3_VERSION
            Python3_VERSION_MAJOR Python3_VERSION_MINOR Python3_VERSION_PATCH
            Python3_Interpreter_FOUND Python3_Development_FOUND
            Python3_Development.Module_FOUND Python3_Development.Embed_FOUND)
        unset(${_v})
        unset(${_v} PARENT_SCOPE)
    endforeach()
endfunction()

# -----------------------------------------------------------------------------
# Full detection - post-project() use.
# -----------------------------------------------------------------------------
function(ida_find_python)
    set(IDA_PYTHON_VERSION_SUFFIX "${IDA_PYTHON_VERSION_SUFFIX}"
        CACHE STRING "Python version suffix (e.g. 'd' for debug)")

    # macOS: prefer non-framework pythons (Xcode's dev files are broken).
    if(APPLE)
        set(Python3_FIND_FRAMEWORK LAST)
    endif()

    # Honour CMake's own knob as well: it is what the standalone build documents,
    # and the auto-detect loop below resets the Python3_* cache, which would
    # otherwise discard it.
    if(NOT DEFINED IDA_PYTHON AND NOT DEFINED IDA_PYTHON_VERSION_MINOR
            AND Python3_EXECUTABLE)
        set(IDA_PYTHON "${Python3_EXECUTABLE}")
    endif()

    if(DEFINED IDA_PYTHON AND DEFINED IDA_PYTHON_VERSION_MINOR)
        message(WARNING
            "Both IDA_PYTHON (${IDA_PYTHON}) and IDA_PYTHON_VERSION_MINOR "
            "(${IDA_PYTHON_VERSION_MINOR}) are set. Using IDA_PYTHON "
            "(executable wins).")
    endif()

    # Component set:
    # - Windows: we generate python3.lib from the stable-ABI .def, no dev files.
    # - Linux cross-compile / Android: skip Development to avoid arch mismatch.
    # - IDA_CODE_CHECKER: headers only - the .Embed probe wants a real linker,
    #   which that build replaces with a stub.
    # Everywhere else the full Development component is needed: macOS weak-links
    # libpython into idapython3, and only its .Embed half locates the library
    # (Development.Module leaves Python3_LIBRARY_DIRS empty, so -weak-l gets no
    # -L and the link fails). Override with IDA_PYTHON_COMPONENTS.
    if(IDA_NT
            OR (IDA_LINUX AND IDA_CROSS_COMPILING)
            OR IDA_ANDROID)
        set(_components Interpreter)
    elseif(IDA_CODE_CHECKER)
        set(_components Interpreter Development.Module)
    else()
        if(NOT DEFINED IDA_PYTHON_COMPONENTS)
            set(IDA_PYTHON_COMPONENTS Interpreter Development)
        endif()
        set(_components ${IDA_PYTHON_COMPONENTS})
    endif()

    if(DEFINED IDA_PYTHON)
        find_program(_ida_python_resolved "${IDA_PYTHON}")
        if(NOT _ida_python_resolved)
            message(FATAL_ERROR "IDA_PYTHON executable not found: ${IDA_PYTHON}")
        endif()
        # Drop stale results first: FindPython3 reuses cached per-component
        # outcomes, so a previous run that failed Development would stick.
        _ida_reset_python_cache()
        set(Python3_EXECUTABLE "${_ida_python_resolved}" CACHE FILEPATH "" FORCE)
        find_package(Python3 REQUIRED COMPONENTS ${_components})
    elseif(DEFINED IDA_PYTHON_VERSION_MINOR)
        find_package(Python3 3.${IDA_PYTHON_VERSION_MINOR} EXACT REQUIRED
                     COMPONENTS ${_components})
    else()
        # Auto-detect: find lowest supported version.
        # Do NOT use version range (3.9...<3.15): it doesn't guarantee
        # lowest-first order and hits CMake arch-check bugs with find_msvc
        # on Windows.
        set(_found FALSE)
        foreach(_minor IN LISTS _IDA_PYTHON_SUPPORTED_MINORS)
            _ida_reset_python_cache()
            find_package(Python3 3.${_minor} EXACT COMPONENTS ${_components} QUIET)
            if(Python3_FOUND)
                if(NOT Python3_VERSION_MAJOR)
                    set(Python3_VERSION_MAJOR 3)
                    set(Python3_VERSION_MINOR ${_minor})
                endif()
                set(_found TRUE)
                break()
            endif()
        endforeach()
        if(NOT _found)
            message(FATAL_ERROR
                "No Python 3.9-3.14 found. Install Python or set "
                "-DIDA_PYTHON_VERSION_MINOR=<minor> or -DIDA_PYTHON=<path>")
        endif()
    endif()

    # Get Development separately when it wasn't requested above.
    if(NOT Python3_Development_FOUND
            AND IDA_BUILD_IDA
            AND NOT IDA_NT)
        find_package(Python3 ${Python3_VERSION_MAJOR}.${Python3_VERSION_MINOR}
                     EXACT COMPONENTS Development QUIET)
    endif()

    # Windows: generate python3.lib from the stable ABI .def file so that no
    # Python "Development" component (headers + libs) needs to be installed.
    # Non-Windows cross-compile: override include/lib dirs with target-arch.
    if(IDA_NT OR (IDA_CROSS_COMPILING AND (NOT Python3_INCLUDE_DIRS)))
        if(DEFINED IDA_ARM64_CROSS_PYTHON_INCLUDE)
            set(Python3_INCLUDE_DIRS "${IDA_ARM64_CROSS_PYTHON_INCLUDE}")
        elseif(IDA_NT)
            get_filename_component(_py_root "${Python3_EXECUTABLE}" DIRECTORY)
            set(Python3_INCLUDE_DIRS "${_py_root}/include")

            set(_py_def "${_IDAPYTHON_PY_DIR}/python3_stable_abi.def")
            set(_py_lib_dir "${CMAKE_BINARY_DIR}/python_lib")
            set(_py_lib_out "${_py_lib_dir}/python3.lib")
            if(NOT EXISTS "${_py_lib_out}")
                file(MAKE_DIRECTORY "${_py_lib_dir}")
                # A standalone build may be CXX-only, leaving CMAKE_C_COMPILER unset.
                set(_py_cl "${CMAKE_C_COMPILER}")
                if(NOT _py_cl)
                    set(_py_cl "${CMAKE_CXX_COMPILER}")
                endif()
                get_filename_component(_cl_dir "${_py_cl}" DIRECTORY)
                set(_lib_exe "${_cl_dir}/lib.exe")
                message(STATUS "Generating python3.lib for ${IDA_ARCH} from stable ABI .def")
                execute_process(
                    COMMAND "${_lib_exe}"
                        /def:${_py_def} /out:${_py_lib_out}
                        /machine:${IDA_ARCH} /nologo
                    RESULT_VARIABLE _py_lib_result
                    OUTPUT_QUIET)
                if(_py_lib_result)
                    message(FATAL_ERROR
                        "Failed to generate python3.lib (exit ${_py_lib_result})")
                endif()
            endif()
            set(Python3_LIBRARY_DIRS "${_py_lib_dir}")
        endif()
        if(Python3_INCLUDE_DIRS)
            message(STATUS "Python cross-compile include: ${Python3_INCLUDE_DIRS}")
            message(STATUS "Python cross-compile libs: ${Python3_LIBRARY_DIRS}")
        endif()
    endif()

    # Propagate to parent scope (function-local by default).
    foreach(_v
            Python3_EXECUTABLE Python3_VERSION
            Python3_VERSION_MAJOR Python3_VERSION_MINOR Python3_VERSION_PATCH
            Python3_INCLUDE_DIRS Python3_LIBRARIES Python3_LIBRARY_DIRS
            Python3_Development_FOUND Python3_Interpreter_FOUND
            Python3_FOUND)
        set(${_v} "${${_v}}" PARENT_SCOPE)
    endforeach()

    # Aliases consumed downstream.
    set(IDA_PYTHON "${Python3_EXECUTABLE}" PARENT_SCOPE)
    set(IDA_PYTHON_VERNAME
        "python${Python3_VERSION_MAJOR}.${Python3_VERSION_MINOR}${IDA_PYTHON_VERSION_SUFFIX}"
        PARENT_SCOPE)
    message(STATUS "Python: ${Python3_EXECUTABLE} (${Python3_VERSION})")
endfunction()
