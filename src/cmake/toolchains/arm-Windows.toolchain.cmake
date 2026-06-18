# x64 Windows host -> ARM64 Windows target.
# Requires the "ARM64 build tools" component in the installed Visual Studio.

set(CMAKE_SYSTEM_NAME      Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)

# Run find_msvc here (after CMAKE_SYSTEM_PROCESSOR is set) so the cross-cl.exe
# is picked. Top-level CMakeLists.txt skips find_msvc when a toolchain file
# is in use.
include("${CMAKE_CURRENT_LIST_DIR}/../find_msvc.cmake")
