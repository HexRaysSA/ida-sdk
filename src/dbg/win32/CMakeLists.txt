# ============================================================================
# Windows Debugger Stub (win32_stub.so)
# Builds on ALL platforms for remote debugging support
# ============================================================================

ida_add_plugin(win32_stub
    SOURCES
        win32_stub.cpp
        w32sehch.cpp

        # #included files for dependency tracking
        win32_local_impl.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    win32_local_impl.cpp
    ../common_stub_impl.cpp
    ../common_local_impl.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link debugger static libraries
target_link_libraries(win32_stub PRIVATE
    dbg_plugin
    dbg_rpc
    dbg_proc
)

# Link SDK static library using ida-cmake variables
target_link_libraries(win32_stub PRIVATE
    ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
)

# On Windows with MSVC, override runtime library to match network.lib (/MD)
if(MSVC)
    set_target_properties(win32_stub PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()

# ============================================================================
# Windows Local Debugger Plugin (win32_user.dll)
# Only builds on Windows platform
# ============================================================================

if(WIN32)
    ida_add_plugin(win32_user
        SOURCES
            win32_user.cpp
            w32sehch.cpp
            win32_debmod.cpp
            win32_util.cpp
            winbase_debmod.cpp

            # #included files for dependency tracking
            win32_local_impl.cpp
            ../common_stub_impl.cpp
            ../common_local_impl.cpp
    )

    # Mark #included files as HEADER_FILE_ONLY
    set_source_files_properties(
        win32_local_impl.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
        PROPERTIES HEADER_FILE_ONLY TRUE
    )

    # Link debugger static libraries
    target_link_libraries(win32_user PRIVATE
        dbg_plugin
        dbg_rpc
        dbg_proc
    )

    # Link SDK static library
    target_link_libraries(win32_user PRIVATE
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
    )

    # Windows system libraries
    target_link_libraries(win32_user PRIVATE
        user32
    )

    # On Windows with MSVC, override runtime library to match network.lib (/MD)
    if(MSVC)
        set_target_properties(win32_user PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
        )
    endif()
endif()

# ============================================================================
# Windows Debugger Server (win32_remote.exe / win64_remote.exe)
# Only builds on Windows platform
# ============================================================================

if(WIN32)
    add_executable(win32_remote
        # Server entry point and Windows-specific code
        win32_server.cpp
        tilfuncs.cpp
        win32_debmod.cpp
        win32_util.cpp
        winbase_debmod.cpp

        # Debugger framework sources (dbg_server + dbg_rpc + dbg_proc)
        # Compiled directly instead of using static libs to avoid /MD vs /MT conflict
        ../bin_search.cpp
        ../dbg_rpc_handler.cpp
        ../debmod.cpp
        ../server.cpp
        ../dbg_rpc_engine.cpp
        ../dbg_rpc_hlp.cpp
        ../arm_debmod.cpp
        ../arm_regs.cpp
        ../pc_debmod.cpp
        ../pc_regs.cpp

        # #included files for dependency tracking
        ../arm_local_impl.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
        ../dbg_pe_hlp.cpp
    )

    # Mark #included files as HEADER_FILE_ONLY
    set_source_files_properties(
        ../arm_local_impl.cpp
        ../common_stub_impl.cpp
        ../common_local_impl.cpp
        ../dbg_pe_hlp.cpp
        PROPERTIES HEADER_FILE_ONLY TRUE
    )

    # Windows server needs static libraries from the _s directory
    # Replace x64_win_vc_64 with x64_win_vc_64_s (or x86_win_vc_32_s for 32-bit)
    string(REPLACE "_64" "_64_s" IDA_STATIC_LIB_DIR "${IDA_LIB_DIR}")
    string(REPLACE "_32" "_32_s" IDA_STATIC_LIB_DIR "${IDA_STATIC_LIB_DIR}")

    # Link SDK static libraries (using /MT versions from _s directory)
    target_link_libraries(win32_remote PRIVATE
        ${IDA_STATIC_LIB_DIR}/network${IDA_STATIC_EXT}
        ${IDA_STATIC_LIB_DIR}/dumb.obj
        ${IDA_STATIC_LIB_DIR}/unicode${IDA_STATIC_EXT}
        ${IDA_STATIC_LIB_DIR}/pro${IDA_STATIC_EXT}
        ${IDA_STATIC_LIB_DIR}/compress${IDA_STATIC_EXT}
    )

    # Windows system libraries
    target_link_libraries(win32_remote PRIVATE
        ole32
        oleaut32
    )

    # Include directories
    target_include_directories(win32_remote PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/..
        ${IDASDK}/include
    )

    # Link to platform and compiler settings for defines
    target_link_libraries(win32_remote PRIVATE
        ida_platform_settings
        ida_compiler_settings
    )

    # Match makefile: compile with -fno-rtti (MSVC will use /GR-)
    target_compile_options(win32_remote PRIVATE -fno-rtti)

    # NOTE: Server uses static libraries from x64_win_vc_64_s which are built with /MT
    # Do NOT override to /MD - use the default /MT from ida-cmake platform.cmake

    # Server output goes to bin/dbgsrv/ NOT bin/plugins/
    set_target_properties(win32_remote PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${IDABIN}/dbgsrv"
    )
endif()
