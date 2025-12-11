# ============================================================================
# Linux Debugger Plugin (linux_user.so)
# Only builds on Linux platform
# ============================================================================

if(IDA_PLATFORM_NAME STREQUAL "linux")
    ida_add_plugin(linux_user
    SOURCES
        linux_user.cpp
        linuxbase_debmod.cpp
        linux_debmod.cpp
        linux_wait.cpp
        stack_unwind.cpp
        symelf.cpp

        # #included files for dependency tracking
        linux_local_impl.cpp
        linux_threads.cpp
        android.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
        ../arm_local_impl.cpp

        # External dependencies from other SDK components
        ../../plugins/dwarf/look_for_debug_file.cpp
        ../../ldr/elf/common.cpp
        ../../ldr/elf/reader.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    linux_local_impl.cpp
    linux_threads.cpp
    android.cpp
    ../common_stub_impl.cpp
    ../common_local_impl.cpp
    ../arm_local_impl.cpp
    ../../plugins/dwarf/look_for_debug_file.cpp
    ../../ldr/elf/common.cpp
    ../../ldr/elf/reader.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link debugger static libraries
target_link_libraries(linux_user PRIVATE
    dbg_plugin
    dbg_rpc
    dbg_proc
)

# Link SDK static library using ida-cmake variables
target_link_libraries(linux_user PRIVATE
    ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
)

# Platform-specific system libraries
target_link_libraries(linux_user PRIVATE
    rt pthread dl thread_db
)

# Version script for symbol visibility control
set_target_properties(linux_user PROPERTIES
    LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/linux_debmod.script"
)

# Copy exceptions.cfg only if source is newer
add_custom_command(TARGET linux_user POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${IDABIN}/cfg
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/../exceptions.cfg
        ${IDABIN}/cfg/exceptions.cfg
    COMMENT "Copying exceptions.cfg if newer"
)
endif() # IDA_PLATFORM_NAME STREQUAL "linux"

# ============================================================================
# Linux Debugger Server (linux_server executable)
# Only builds on Linux platform
# ============================================================================

if(IDA_PLATFORM_NAME STREQUAL "linux")
    add_executable(linux_server
    # Same sources as linux_user except linux_user.cpp
    linuxbase_debmod.cpp
    linux_debmod.cpp
    linux_wait.cpp
    stack_unwind.cpp
    symelf.cpp

    # #included files for dependency tracking
    linux_local_impl.cpp
    linux_threads.cpp
    android.cpp
    ../common_stub_impl.cpp
    ../common_local_impl.cpp
    ../arm_local_impl.cpp

    # External dependencies
    ../../plugins/dwarf/look_for_debug_file.cpp
    ../../ldr/elf/common.cpp
    ../../ldr/elf/reader.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    linux_local_impl.cpp
    linux_threads.cpp
    android.cpp
    ../common_stub_impl.cpp
    ../common_local_impl.cpp
    ../arm_local_impl.cpp
    ../../plugins/dwarf/look_for_debug_file.cpp
    ../../ldr/elf/common.cpp
    ../../ldr/elf/reader.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link all static libraries with grouping to resolve circular dependencies
# Use --start-group/--end-group to handle circular dependencies between libraries
target_link_libraries(linux_server PRIVATE
    -Wl,--start-group
    dbg_server   # <- Different from plugin!
    dbg_rpc
    dbg_proc
    ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
    ${IDA_LIB_DIR}/dumb.o
    ${IDA_LIB_DIR}/unicode${IDA_STATIC_EXT}
    ${IDA_LIB_DIR}/pro${IDA_STATIC_EXT}
    ${IDA_LIB_DIR}/compress${IDA_STATIC_EXT}
    -Wl,--end-group
)

# Platform-specific system libraries
target_link_libraries(linux_server PRIVATE
    rt pthread c dl thread_db
)

# Include directories
target_include_directories(linux_server PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${IDASDK}/include
)

# Link to platform and compiler settings for defines
target_link_libraries(linux_server PRIVATE
    ida_platform_settings
    ida_compiler_settings
)

# Match makefile: compile with -fno-rtti
target_compile_options(linux_server PRIVATE -fno-rtti)

# Server output goes to bin/dbgsrv/ NOT bin/plugins/
set_target_properties(linux_server PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${IDABIN}/dbgsrv"
    LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/linux_debmod.script"
)
endif() # IDA_PLATFORM_NAME STREQUAL "linux"

# ============================================================================
# Linux Remote Debugging Stub (linux_stub.so/.dll)
# Builds on Windows and Linux (macOS has RTTI linkage issues with SDK libs)
# ============================================================================

if(NOT APPLE)
ida_add_plugin(linux_stub
    SOURCES
        linux_stub.cpp
        stack_unwind.cpp

        # #included files for dependency tracking
        linux_local_impl.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    linux_local_impl.cpp
    ../common_stub_impl.cpp
    ../common_local_impl.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link debugger static libraries
target_link_libraries(linux_stub PRIVATE
    dbg_plugin
    dbg_rpc
    dbg_proc
)

# Link SDK static library
target_link_libraries(linux_stub PRIVATE
    ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
)

# On Windows with MSVC, override runtime library to match network.lib (/MD)
if(MSVC)
    set_target_properties(linux_stub PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()
endif() # NOT APPLE

# ============================================================================
# ARM Linux Remote Debugging Stub (armlinux_stub.so/.dll)
# Builds on Windows and Linux (macOS has RTTI linkage issues with SDK libs)
# ============================================================================

if(NOT APPLE)
ida_add_plugin(armlinux_stub
    SOURCES
        armlinux_stub.cpp
        stack_unwind.cpp

        # #included files for dependency tracking
        linux_local_impl.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
        ../arm_local_impl.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    linux_local_impl.cpp
    ../common_stub_impl.cpp
    ../common_local_impl.cpp
    ../arm_local_impl.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link debugger static libraries
target_link_libraries(armlinux_stub PRIVATE
    dbg_plugin
    dbg_rpc
    dbg_proc
)

# Link SDK static library
target_link_libraries(armlinux_stub PRIVATE
    ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
)

# On Windows with MSVC, override runtime library to match network.lib (/MD)
if(MSVC)
    set_target_properties(armlinux_stub PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()
endif() # NOT APPLE
