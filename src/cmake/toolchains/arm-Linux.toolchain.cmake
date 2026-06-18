# x64 Linux host -> ARM64 Linux target. clang + lld + target triple,
# consuming the standard CMAKE_SYSROOT variable.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

if(NOT DEFINED CMAKE_SYSROOT OR CMAKE_SYSROOT STREQUAL "")
    message(FATAL_ERROR
        "ARM Linux cross-compile requires CMAKE_SYSROOT to point at an "
        "aarch64 Linux sysroot.\n"
        "\n"
        "Pass it on the cmake configure line:\n"
        "    cmake --preset arm -DCMAKE_SYSROOT=/path/to/aarch64-sysroot\n"
        "\n"
        "On Ubuntu/Debian, install a system cross-toolchain:\n"
        "    sudo apt install crossbuild-essential-arm64\n"
        "    cmake --preset arm -DCMAKE_SYSROOT=/usr/aarch64-linux-gnu\n"
        "\n"
        "Reference: https://cmake.org/cmake/help/latest/variable/CMAKE_SYSROOT.html")
endif()
if(NOT EXISTS "${CMAKE_SYSROOT}")
    message(FATAL_ERROR "CMAKE_SYSROOT='${CMAKE_SYSROOT}' does not exist.")
endif()

set(_arm64_triple "aarch64-linux-gnu")
set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

# Host strip/objcopy don't understand ARM64 ELF; use llvm-* counterparts.
find_program(_llvm_strip llvm-strip REQUIRED)
find_program(_llvm_objcopy llvm-objcopy REQUIRED)
set(CMAKE_STRIP "${_llvm_strip}" CACHE FILEPATH "Strip" FORCE)
set(CMAKE_OBJCOPY "${_llvm_objcopy}" CACHE FILEPATH "Objcopy" FORCE)

find_program(_lld_linker ld.lld REQUIRED)

set(_arm64_c_flags "--target=${_arm64_triple}")
set(_arm64_cxx_flags "--target=${_arm64_triple} -nostdinc++")

# Pick the newest C++ stdlib version found under the sysroot. Debian/Ubuntu
# layout: generic headers at usr/include/c++/<ver>, arch-specific bits at
# usr/include/aarch64-linux-gnu/c++/<ver> (where bits/c++config.h lives).
file(GLOB _arm64_cxx_versions LIST_DIRECTORIES TRUE
    "${CMAKE_SYSROOT}/usr/include/c++/*")
if(_arm64_cxx_versions)
    list(SORT _arm64_cxx_versions COMPARE NATURAL ORDER DESCENDING)
    list(GET _arm64_cxx_versions 0 _arm64_cxx_dir)
    cmake_path(GET _arm64_cxx_dir FILENAME _arm64_cxx_version)
    string(APPEND _arm64_cxx_flags " -isystem ${_arm64_cxx_dir}")
    string(APPEND _arm64_cxx_flags
        " -isystem ${CMAKE_SYSROOT}/usr/include/aarch64-linux-gnu/c++/${_arm64_cxx_version}")
endif()

set(_arm64_common_flags "-mno-outline-atomics")
set(_arm64_warn_flags
    "-Wno-nontrivial-memaccess -Wno-reserved-user-defined-literal -Wno-narrowing")

set(CMAKE_C_FLAGS_INIT
    "${_arm64_c_flags} ${_arm64_common_flags} ${_arm64_warn_flags}")
set(CMAKE_CXX_FLAGS_INIT
    "${_arm64_cxx_flags} ${_arm64_common_flags} ${_arm64_warn_flags}")

set(CMAKE_EXE_LINKER_FLAGS_INIT    "-fuse-ld=lld --target=${_arm64_triple}")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld --target=${_arm64_triple}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld --target=${_arm64_triple}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
