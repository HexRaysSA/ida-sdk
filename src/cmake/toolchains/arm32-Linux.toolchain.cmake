# x64 Linux host -> 32-bit ARM Linux; IDA_ARM_HF=ON selects hard-float ABI
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR armv7l)
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES IDA_ARM_HF)

if(IDA_ARM_HF)
    set(_arm32_triple "arm-linux-gnueabihf")
    set(_arm32_flags "-mhard-float")
else()
    set(_arm32_triple "arm-linux-gnueabi")
    set(_arm32_flags "-msoft-float")
endif()

# Ubuntu/Debian: apt install g++-arm-linux-gnueabi (or g++-arm-linux-gnueabihf)
if(NOT CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER "${_arm32_triple}-gcc")
endif()
if(NOT CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER "${_arm32_triple}-g++")
endif()

set(CMAKE_C_FLAGS_INIT "${_arm32_flags}")
set(CMAKE_CXX_FLAGS_INIT "${_arm32_flags}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
