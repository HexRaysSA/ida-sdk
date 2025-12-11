# ============================================================================
# Static Library 1: dbg_rpc (RPC communication)
# ============================================================================
add_library(dbg_rpc STATIC
    dbg_rpc_engine.cpp
    dbg_rpc_hlp.cpp
)

target_include_directories(dbg_rpc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IDASDK}/include
)

target_link_libraries(dbg_rpc PUBLIC
    ida_platform_settings
    ida_compiler_settings
)

target_compile_options(dbg_rpc PRIVATE -fno-rtti)

# On Windows/MSVC: Use /MD runtime to match SDK libraries (network.lib)
if(MSVC)
    set_target_properties(dbg_rpc PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()

# ============================================================================
# Static Library 2: dbg_server (Server-side infrastructure)
# ============================================================================
add_library(dbg_server STATIC
    bin_search.cpp
    dbg_rpc_handler.cpp
    debmod.cpp
    server.cpp
)

target_include_directories(dbg_server PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IDASDK}/include
)

target_link_libraries(dbg_server PUBLIC
    ida_platform_settings
    ida_compiler_settings
)

target_compile_options(dbg_server PRIVATE -fno-rtti)

# On Windows/MSVC: Use /MD runtime to match SDK libraries
if(MSVC)
    set_target_properties(dbg_server PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()

# ============================================================================
# Static Library 3: dbg_plugin (Plugin-side infrastructure)
# ============================================================================
add_library(dbg_plugin STATIC
    bin_search.cpp      # Shared with dbg_server
    dbg_rpc_client.cpp
    debmod.cpp          # Shared with dbg_server
    rpc_debmod.cpp
)

target_include_directories(dbg_plugin PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IDASDK}/include
)

target_link_libraries(dbg_plugin PUBLIC
    ida_platform_settings
    ida_compiler_settings
)

target_compile_options(dbg_plugin PRIVATE -fno-rtti)

# On Windows/MSVC: Use /MD runtime to match SDK libraries
if(MSVC)
    set_target_properties(dbg_plugin PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()

# ============================================================================
# Static Library 4: dbg_proc (Processor-specific code: ARM + PC)
# ============================================================================
add_library(dbg_proc STATIC
    arm_debmod.cpp
    arm_regs.cpp
    pc_debmod.cpp
    pc_regs.cpp

    # #included files for dependency tracking
    arm_local_impl.cpp
    common_stub_impl.cpp
    common_local_impl.cpp
    dbg_pe_hlp.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    arm_local_impl.cpp
    common_stub_impl.cpp
    common_local_impl.cpp
    dbg_pe_hlp.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

target_include_directories(dbg_proc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${IDASDK}/include
)

target_link_libraries(dbg_proc PUBLIC
    ida_platform_settings
    ida_compiler_settings
)

target_compile_options(dbg_proc PRIVATE -fno-rtti)

# On Windows/MSVC: Use /MD runtime to match SDK libraries
if(MSVC)
    set_target_properties(dbg_proc PROPERTIES
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL"
    )
endif()

# ============================================================================
# Platform-specific subdirectories
# ============================================================================

# Linux debugger and stubs (always added - contains cross-platform stubs)
add_subdirectory(linux)

# Windows debugger and stub (always added - contains cross-platform stub)
add_subdirectory(win32)
