# Public debugger SDK build.
# SDK libs are Release-only -- skip dbg in single-config Debug (CRT mismatch).
get_property(_is_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _is_multi_config AND CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Debugger components: Skipped in Debug build (SDK libraries are Release-only)")
    return()
endif()

# Local helpers for the four dbg core static libs.
function(_ida_dbg_no_rtti tgt)
    if(MSVC)
        target_compile_options(${tgt} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:/GR->)
    else()
        target_compile_options(${tgt} PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
    endif()
endfunction()

function(_ida_dbg_setup tgt)
    target_include_directories(${tgt} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR} ${IDASDK} ${IDASDK}/include)
    target_link_libraries(${tgt} PUBLIC ida_platform_settings ida_compiler_settings)
    _ida_dbg_no_rtti(${tgt})
endfunction()

add_library(dbg_rpc STATIC dbg_rpc_engine.cpp dbg_rpc_hlp.cpp)
_ida_dbg_setup(dbg_rpc)

add_library(dbg_server STATIC bin_search.cpp dbg_rpc_handler.cpp debmod.cpp server.cpp)
_ida_dbg_setup(dbg_server)

# pc_debmod.cpp uses x86/x64 CONTEXT structures -- skip on Windows ARM64.
set(_dbg_proc_sources arm_debmod.cpp arm_regs.cpp pc_regs.cpp
    arm_local_impl.cpp common_stub_impl.cpp common_local_impl.cpp dbg_pe_hlp.cpp)
if(NOT (IDA_NT AND IDA_ARM))
    list(APPEND _dbg_proc_sources pc_debmod.cpp)
endif()
add_library(dbg_proc STATIC ${_dbg_proc_sources})
set_source_files_properties(
    arm_local_impl.cpp common_stub_impl.cpp common_local_impl.cpp dbg_pe_hlp.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE)
_ida_dbg_setup(dbg_proc)

# dbg_plugin: stub/user only -- server-only flavors skip it.
if(NOT IDA_ANDROID AND NOT IDA_ARMLINUX AND NOT IDA_USE_STATIC_RUNTIME)
    add_library(dbg_plugin STATIC bin_search.cpp dbg_rpc_client.cpp debmod.cpp rpc_debmod.cpp)
    _ida_dbg_setup(dbg_plugin)
endif()

add_subdirectory(win32)
add_subdirectory(linux)

ida_dbg_verify_servers()
