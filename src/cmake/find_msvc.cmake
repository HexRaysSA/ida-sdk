# find_msvc.cmake - Auto-detect MSVC toolchain on Windows
#
# Included before project() when using Ninja generator on Windows.
# Detection steps:
#   1. Find Visual Studio installation (via vswhere.exe)
#   2. Find MSVC tools version (Microsoft.VCToolsVersion.default.txt,
#      then fall back to scanning Tools/MSVC/14.*)
#   3. Find Windows SDK and its version (scanning Include/10.*)
#   4. Set CMAKE_C/CXX_COMPILER, CMAKE_RC_COMPILER, CMAKE_MT
#   5. Set INCLUDE/LIB environment variables for cl.exe/link.exe

# Only relevant on Windows
if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    return()
endif()

# Skip if compiler is already specified as MSVC (e.g., -DCMAKE_C_COMPILER
# on the command line, or previous successful configure). A stale cache
# entry pointing at a non-MSVC compiler (Strawberry Perl GCC, etc.) is
# intentionally overridden below.
# Exception: cross-compile (x86 or ARM64) needs arch-specific cl.exe even if
# x64 cl.exe is in PATH.
# Exception: IDA_FORCE_MSVC_DETECTION forces full detection (used by host
# tools ExternalProject where the parent's target-arch cl.exe is in PATH).
if(NOT IDA_FORCE_MSVC_DETECTION)
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(i[3456]86|x86|aarch64|arm64|ARM64)$")
        if(DEFINED CMAKE_C_COMPILER AND CMAKE_C_COMPILER MATCHES "[Cc][Ll]\\.exe$")
            return()
        endif()
        # Intentionally do NOT early-return when cl.exe is merely findable in
        # PATH: on CI runners with a VS Developer Command Prompt but also
        # Cygwin on PATH, cl.exe is findable, but mt.exe / rc.exe may not be,
        # and CMake's default MSVC init leaves CMAKE_MT-NOTFOUND. Running the
        # full probe below sets CMAKE_RC_COMPILER and CMAKE_MT to absolute
        # Windows-SDK paths unconditionally, which is what the sub-configure
        # for sdk-build needs.
    endif()
endif()

message(STATUS "MSVC not in environment, auto-detecting...")

# =========================================================================
# Find Visual Studio installation
# Strategy:
#   1. Try vswhere.exe (-products * finds Build Tools too)
#   2. Fall back to VCINSTALLDIR environment variable
# =========================================================================
set(_msvc_root "")

# Try vswhere first
set(_vswhere "C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")
if(EXISTS "${_vswhere}")
    execute_process(
        COMMAND "${_vswhere}" -latest -products * -property installationPath
        OUTPUT_VARIABLE _vs_root
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE _vswhere_result
    )
    if(_vswhere_result EQUAL 0 AND _vs_root)
        set(_msvc_root "${_vs_root}/VC")
        message(STATUS "Visual Studio: ${_vs_root} (via vswhere)")
    endif()
endif()

# Fall back to VCINSTALLDIR (set by vcvarsall.bat or CI environments)
if(NOT _msvc_root AND DEFINED ENV{VCINSTALLDIR})
    # Strip trailing backslash, normalize separators
    string(REGEX REPLACE "[/\\\\]$" "" _msvc_root "$ENV{VCINSTALLDIR}")
    file(TO_CMAKE_PATH "${_msvc_root}" _msvc_root)
    message(STATUS "Visual Studio VC: ${_msvc_root} (via VCINSTALLDIR)")
endif()

if(NOT _msvc_root)
    message(FATAL_ERROR
        "Could not find Visual Studio installation.\n"
        "Tried: vswhere.exe and VCINSTALLDIR environment variable.\n"
        "Please install Visual Studio or set VCINSTALLDIR.")
endif()

# =========================================================================
# Find MSVC tools version: try Microsoft.VCToolsVersion.default.txt first,
# then scan Tools/MSVC/14.*
# =========================================================================
set(_msvc_toolsver "")
set(_msvc_toolsver_path "${_msvc_root}/Auxiliary/Build/Microsoft.VCToolsVersion.default.txt")
if(EXISTS "${_msvc_toolsver_path}")
    file(READ "${_msvc_toolsver_path}" _msvc_toolsver)
    string(STRIP "${_msvc_toolsver}" _msvc_toolsver)
endif()

if(NOT _msvc_toolsver)
    # Fall back to scanning directory names
    file(GLOB _msvc_versions "${_msvc_root}/Tools/MSVC/14.*")
    if(_msvc_versions)
        list(SORT _msvc_versions COMPARE NATURAL ORDER DESCENDING)
        list(GET _msvc_versions 0 _msvc_latest)
        get_filename_component(_msvc_toolsver "${_msvc_latest}" NAME)
    endif()
endif()

if(NOT _msvc_toolsver)
    message(FATAL_ERROR
        "Could not find Visual C++ Tools Version.\n"
        "Checked: ${_msvc_toolsver_path}\n"
        "Scanned: ${_msvc_root}/Tools/MSVC/14.*")
endif()

set(_msvc_path "${_msvc_root}/Tools/MSVC/${_msvc_toolsver}")
if(NOT EXISTS "${_msvc_path}")
    message(FATAL_ERROR "MSVC tools directory does not exist: ${_msvc_path}")
endif()
message(STATUS "MSVC tools version: ${_msvc_toolsver}")

# =========================================================================
# Find Windows SDK: WindowsSdkDir + version scanning
# =========================================================================
set(_wsdk_path "C:/Program Files (x86)/Windows Kits/10")
if(NOT EXISTS "${_wsdk_path}")
    message(FATAL_ERROR "Windows SDK not found at ${_wsdk_path}")
endif()

# Detect latest SDK version by scanning Include/10.*
file(GLOB _wsdk_versions "${_wsdk_path}/Include/10.*")
if(NOT _wsdk_versions)
    message(FATAL_ERROR "Could not find Windows SDK version in ${_wsdk_path}/Include/10.*")
endif()
list(SORT _wsdk_versions COMPARE NATURAL ORDER DESCENDING)
list(GET _wsdk_versions 0 _wsdk_latest)
get_filename_component(_wsdk_ver "${_wsdk_latest}" NAME)
message(STATUS "Windows SDK: ${_wsdk_ver}")

# =========================================================================
# Determine target architecture
# =========================================================================
if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64)$")
    set(_target_arch "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(i[3456]86|x86)$")
    set(_target_arch "x86")
else()
    set(_target_arch "x64")
endif()

# =========================================================================
# Set compilers
# =========================================================================
set(_compiler_path "${_msvc_path}/bin/Hostx64/${_target_arch}/cl.exe")
if(NOT EXISTS "${_compiler_path}")
    message(FATAL_ERROR
        "MSVC compiler for ${_target_arch} not found at: ${_compiler_path}\n"
        "Install the '${_target_arch}' build tools component in Visual Studio.")
endif()
set(CMAKE_C_COMPILER   "${_compiler_path}" CACHE FILEPATH "C compiler" FORCE)
set(CMAKE_CXX_COMPILER "${_msvc_path}/bin/Hostx64/${_target_arch}/cl.exe" CACHE FILEPATH "C++ compiler" FORCE)
set(CMAKE_RC_COMPILER  "${_wsdk_path}/bin/${_wsdk_ver}/x64/rc.exe"        CACHE FILEPATH "Resource compiler" FORCE)
set(CMAKE_MT           "${_wsdk_path}/bin/${_wsdk_ver}/x64/mt.exe"        CACHE FILEPATH "Manifest tool" FORCE)

# =========================================================================
# System include and library paths
# =========================================================================
set(_msvc_include "${_msvc_path}/Include")
set(_include_ucrt "${_wsdk_path}/Include/${_wsdk_ver}/ucrt")
set(_include_um   "${_wsdk_path}/Include/${_wsdk_ver}/um")
set(_include_shared "${_wsdk_path}/Include/${_wsdk_ver}/shared")

set(_lib_msvc "${_msvc_path}/lib/${_target_arch}")
set(_lib_ucrt "${_wsdk_path}/Lib/${_wsdk_ver}/ucrt/${_target_arch}")
set(_lib_um   "${_wsdk_path}/Lib/${_wsdk_ver}/um/${_target_arch}")

# Assemble INCLUDE/LIB strings (semicolon-separated)
set(_ida_msvc_include "${_msvc_include};${_include_ucrt};${_include_um};${_include_shared}")
set(_ida_msvc_lib     "${_lib_msvc};${_lib_ucrt};${_lib_um}")

# Persist as cache variables so custom commands (e.g. PIN build) can use them
set(IDA_MSVC_INCLUDE "${_ida_msvc_include}" CACHE STRING "MSVC INCLUDE for sub-builds" FORCE)
set(IDA_MSVC_LIB     "${_ida_msvc_lib}"     CACHE STRING "MSVC LIB for sub-builds"     FORCE)

# Set INCLUDE/LIB environment for project() compiler detection (try_compile)
set(ENV{INCLUDE} "${_ida_msvc_include}")
set(ENV{LIB} "${_ida_msvc_lib}")
set(ENV{PATH} "${_msvc_path}/bin/Hostx64/${_target_arch};${_wsdk_path}/bin/${_wsdk_ver}/x64;$ENV{PATH}")

# Embed system include dirs in generated build rules so they persist
# beyond the configure step (ENV{INCLUDE} only lasts during configure).
set(CMAKE_C_STANDARD_INCLUDE_DIRECTORIES
    "${_msvc_include}" "${_include_ucrt}" "${_include_um}" "${_include_shared}"
    CACHE STRING "MSVC system include directories" FORCE)
set(CMAKE_CXX_STANDARD_INCLUDE_DIRECTORIES
    "${_msvc_include}" "${_include_ucrt}" "${_include_um}" "${_include_shared}"
    CACHE STRING "MSVC system include directories" FORCE)

# Embed system library dirs in linker flags so link.exe finds system .lib
# files without needing the LIB environment variable at build time.
string(JOIN " " _libpath_flags
    "/LIBPATH:\"${_lib_msvc}\""
    "/LIBPATH:\"${_lib_ucrt}\""
    "/LIBPATH:\"${_lib_um}\"")
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_libpath_flags}" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_libpath_flags}" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_libpath_flags}" CACHE STRING "" FORCE)
set(CMAKE_STATIC_LINKER_FLAGS_INIT ""                  CACHE STRING "" FORCE)

message(STATUS "MSVC environment configured automatically")
