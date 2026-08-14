# ===========================================================================
# plugins/idapython/cmake/idapython_swig.cmake
# ===========================================================================
# Provisions SWIG for the IDAPython build and sets, in the includer's scope:
#   IDA_SWIG        - the swig binary
#   IDA_SWIG_LIB    - its library dir (-I'd by the codegen)
#   IDA_SWIG_CCACHE - ccache-swig binary, when caching is on (else empty)
# Resolution order: explicit IDA_SWIG > find_package(SWIG) > pip-installed wheel.
# Included by idapython_shims.cmake.
# ===========================================================================

# Provision a pinned SWIG from PyPI into a venv under IDA_SWIG_ROOT. In a venv the
# `swig` launcher runs and self-reports its swiglib (a `pip --target` install does
# not); wheels exist for every platform we target (incl. Windows x64/arm64), so no
# compiler/autotools is needed. Installs at configure time (guarded) so the binary
# is present for the version/swiglib probe below. Ships no ccache-swig.
function(_ida_build_swig version)
    # swig is a host tool, identical across flavors - install it once in a shared,
    # version-pinned venv (IDA_SWIG_ROOT); default is the current build dir
    # (fine for a standalone build against a read-only SDK).
    if(NOT DEFINED IDA_SWIG_ROOT)
        set(IDA_SWIG_ROOT "${CMAKE_BINARY_DIR}")
    endif()
    set(_venv "${IDA_SWIG_ROOT}/swig-${version}")
    if(WIN32)
        set(_swig "${_venv}/Scripts/swig${CMAKE_EXECUTABLE_SUFFIX}")
        set(_py "${_venv}/Scripts/python${CMAKE_EXECUTABLE_SUFFIX}")
    else()
        set(_swig "${_venv}/bin/swig")
        set(_py "${_venv}/bin/python")
    endif()
    if(NOT EXISTS "${_swig}")
        # Need venv (+ensurepip for its pip) to provision; fail clearly if absent.
        execute_process(COMMAND "${IDA_PYTHON}" -c "import venv, ensurepip"
            RESULT_VARIABLE _rc)
        if(NOT _rc EQUAL 0)
            message(FATAL_ERROR
                "SWIG not found, and ${IDA_PYTHON} has no venv/ensurepip to install "
                "it from PyPI. Install swig (on PATH, or via -DIDA_SWIG=<swig>), or "
                "add python venv support (e.g. the python3-venv package).")
        endif()
        message(STATUS "Provisioning SWIG ${version} from PyPI into ${_venv}")
        execute_process(COMMAND "${IDA_PYTHON}" -m venv "${_venv}" RESULT_VARIABLE _rc)
        if(_rc EQUAL 0)
            execute_process(COMMAND "${_py}" -m pip install
                --disable-pip-version-check --only-binary=:all: "swig==${version}"
                RESULT_VARIABLE _rc)
        endif()
        if(NOT _rc EQUAL 0 OR NOT EXISTS "${_swig}")
            message(FATAL_ERROR
                "Could not provision SWIG ${version} from PyPI (${_venv}); install "
                "swig and pass -DIDA_SWIG=<swig>, or check pip/network.")
        endif()
    endif()
    set(IDA_SWIG "${_swig}" PARENT_SCOPE)
endfunction()

# SWIG: explicit IDA_SWIG > find_package > pip-installed wheel. IDA_SWIG_VERSION is
# unset here by default (public); when set it pins find + pip. Floor is the min.
set(IDA_SWIG_MIN_VERSION "4.2.0")
option(IDA_SWIG_FROM_PYPI "Skip the search and install SWIG from PyPI" OFF)
# Pip-installed when IDA_SWIG_VERSION is unset. 4.4.1 is the first release with
# arm wheels, and carries the PyImport_AddModuleRef fix 4.4.0 lacked.
set(_swig_build_default "4.4.1")
# A pinned version below the floor can never pass the check below - fail now,
# before find_package or a pointless pip download.
if(IDA_SWIG_VERSION AND IDA_SWIG_VERSION VERSION_LESS IDA_SWIG_MIN_VERSION)
    message(FATAL_ERROR
        "IDA_SWIG_VERSION ${IDA_SWIG_VERSION} is below IDA_SWIG_MIN_VERSION "
        "${IDA_SWIG_MIN_VERSION}.")
endif()
if(NOT IDA_SWIG)
    if(NOT IDA_SWIG_FROM_PYPI)
        if(IDA_SWIG_VERSION)
            # EXACT: pinning a version is how you steer away from a particular
            # release, so a newer one on the PATH must not satisfy it. The PyPI
            # fallback below installs that same version exactly.
            find_package(SWIG "${IDA_SWIG_VERSION}" EXACT)
        else()
            find_package(SWIG "${IDA_SWIG_MIN_VERSION}")
        endif()
        if(SWIG_FOUND)
            set(IDA_SWIG "${SWIG_EXECUTABLE}")
        endif()
    endif()
    if(NOT IDA_SWIG)
        if(IDA_SWIG_VERSION)
            _ida_build_swig("${IDA_SWIG_VERSION}")
        else()
            _ida_build_swig("${_swig_build_default}")
        endif()
    endif()
    # Persist so reconfigures reuse it and skip the find_package re-probe.
    set(IDA_SWIG "${IDA_SWIG}" CACHE FILEPATH "Resolved SWIG executable" FORCE)
endif()
if(NOT IDA_SWIG)
    message(FATAL_ERROR "No SWIG found or built; install swig or pass -DIDA_SWIG=<swig>.")
endif()
# Validate the resolved swig and derive its swiglib via `swig -swiglib`, unless an
# includer already set IDA_SWIG_LIB (e.g. third_party). Every path yields a binary
# that exists now (explicit, found, or venv-installed above).
if(EXISTS "${IDA_SWIG}")
    execute_process(COMMAND "${IDA_SWIG}" -version OUTPUT_VARIABLE _swig_ver)
    if(_swig_ver MATCHES "SWIG Version ([0-9]+\\.[0-9]+\\.[0-9]+)"
            AND CMAKE_MATCH_1 VERSION_LESS "${IDA_SWIG_MIN_VERSION}")
        message(FATAL_ERROR
            "IDAPython requires SWIG ${IDA_SWIG_MIN_VERSION}+, found ${CMAKE_MATCH_1} (${IDA_SWIG}).")
    endif()
    if(NOT IDA_SWIG_LIB)
        execute_process(COMMAND "${IDA_SWIG}" -swiglib
            OUTPUT_VARIABLE IDA_SWIG_LIB OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE _swiglib_rc)
        if(NOT _swiglib_rc EQUAL 0 OR NOT IDA_SWIG_LIB)
            message(FATAL_ERROR "Could not determine SWIG library dir (swig -swiglib).")
        endif()
        set(IDA_SWIG_LIB "${IDA_SWIG_LIB}" CACHE PATH "SWIG library dir" FORCE)
    endif()
endif()

# ccache-swig: built one, else next to IDA_SWIG, else PATH; absent = no cache.
option(IDA_SWIG_CACHE "Wrap SWIG runs with ccache-swig when available" ON)
if(IDA_SWIG_CACHE)
    if(NOT IDA_SWIG_CCACHE)
        get_filename_component(_swig_bindir "${IDA_SWIG}" DIRECTORY)
        find_program(IDA_SWIG_CCACHE NAMES ccache-swig HINTS "${_swig_bindir}")
    endif()
    if(NOT IDA_SWIG_CCACHE)
        message(WARNING "ccache-swig not found; SWIG runs will not be cached.")
    endif()
    # ccache-swig picks ~/.ccache but cannot create it (no mkdir -p) - do both here.
    # Guard the expansion: with no HOME/USERPROFILE, EXPAND_TILDE would silently
    # resolve ~ against the current directory.
    if(IDA_SWIG_CCACHE AND NOT IDA_SWIG_CCACHE_DIR
            AND "$ENV{CCACHE_DIR}" STREQUAL "")
        if(DEFINED ENV{HOME} OR DEFINED ENV{USERPROFILE})
            file(REAL_PATH "~/.ccache" IDA_SWIG_CCACHE_DIR EXPAND_TILDE)
        else()
            set(IDA_SWIG_CCACHE_DIR "${CMAKE_BINARY_DIR}/swig-cache")
            message(WARNING
                "SWIG cache: ${IDA_SWIG_CCACHE_DIR}\n"
                "No HOME/USERPROFILE, so it is wiped with the build directory. "
                "Pass -DIDA_SWIG_CCACHE_DIR=<dir> or set CCACHE_DIR to keep it.")
        endif()
        file(MAKE_DIRECTORY "${IDA_SWIG_CCACHE_DIR}")
    endif()
else()
    set(IDA_SWIG_CCACHE "")
endif()
