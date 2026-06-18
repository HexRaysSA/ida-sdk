# Windows debugger SDK build.

set(_win32_hdrs
    win32_local_impl.cpp ../common_stub_impl.cpp ../common_local_impl.cpp)
set(_win32_base
    win32_debmod.cpp win32_util.cpp winbase_debmod.cpp)

# Remote-debugging stub for host IDA (cross-platform, not macOS). Needs libida (EA64).
if(NOT APPLE AND IDA_BUILD_IDA AND IDA_EA64)
    ida_add_plugin(win32_stub
        SOURCES win32_stub.cpp w32sehch.cpp ${_win32_hdrs})
    set_source_files_properties(${_win32_hdrs} PROPERTIES HEADER_FILE_ONLY TRUE)
    target_link_libraries(win32_stub PRIVATE
        dbg_plugin dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT})
    if(MSVC)
        set_target_properties(win32_stub PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    endif()
endif()

# win32_user and win32_remote pull in win32_debmod.cpp which uses
# CONTEXT.Rax/Dr0-7/etc. -- x86/x64-only. ARM Windows targets skip them.

# Local Windows debugger plugin (Windows host only).
if(WIN32 AND IDA_BUILD_IDA AND IDA_EA64 AND NOT IDA_ARM)
    ida_add_plugin(win32_user
        SOURCES win32_user.cpp w32sehch.cpp ${_win32_base} ${_win32_hdrs})
    set_source_files_properties(${_win32_hdrs} PROPERTIES HEADER_FILE_ONLY TRUE)
    target_link_libraries(win32_user PRIVATE
        dbg_plugin dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
        user32)
    if(MSVC)
        set_target_properties(win32_user PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    endif()
endif()

# Debug server (Windows host only).
if(WIN32 AND IDA_BUILD_DBGSRV AND NOT IDA_ARM)
    if(IDA_X64)
        set(_win32_server_name "win64_remote${IDA_SUFF32}")
    else()
        set(_win32_server_name "win32_remote${IDA_SUFF32}")
    endif()
    add_executable(${_win32_server_name}
        win32_server.cpp tilfuncs.cpp ${_win32_base}
        ${_win32_hdrs} ../dbg_pe_hlp.cpp)
    set_source_files_properties(${_win32_hdrs} ../dbg_pe_hlp.cpp
        PROPERTIES HEADER_FILE_ONLY TRUE)
    target_include_directories(${_win32_server_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/.. ${IDASDK} ${IDASDK}/include)
    target_link_libraries(${_win32_server_name} PRIVATE
        ida_platform_settings ida_compiler_settings
        dbg_server dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/dumb${IDA_OBJ_EXT}
        ${IDA_LIB_DIR}/unicode${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/pro${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/int128${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/compress${IDA_STATIC_EXT}
        ole32 oleaut32)
    if(MSVC)
        target_compile_options(${_win32_server_name} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:/GR->)
    else()
        target_compile_options(${_win32_server_name} PRIVATE
            $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
    endif()
    set_target_properties(${_win32_server_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${IDABIN}/dbgsrv")
    set_property(GLOBAL APPEND PROPERTY IDA_DBG_SERVERS ${_win32_server_name})

    # XP compat: 32-bit static-runtime servers redirect __imp_* symbols to
    # fallback implementations for Windows XP / 7 compatibility.
    if(IDA_USE_STATIC_RUNTIME AND IDA_X86 AND IDA_XPCOMPAT)
        target_sources(${_win32_server_name} PRIVATE crt_oldwin_compat_stubs.cpp)
        target_compile_definitions(${_win32_server_name} PRIVATE __XPCOMPAT__)
        # Assemble the .asm via 32-bit ml.exe (Hostx64/x86 cross tools dir).
        set(_compat_asm "${CMAKE_CURRENT_SOURCE_DIR}/crt_oldwin_compat_stubs.asm")
        set(_compat_asm_obj "${CMAKE_CURRENT_BINARY_DIR}/crt_oldwin_compat_stubs_asm.obj")
        get_filename_component(_msvc_bin_dir "${CMAKE_C_COMPILER}" DIRECTORY)
        get_filename_component(_msvc_host_dir "${_msvc_bin_dir}" DIRECTORY)
        set(_ml_exe "${_msvc_host_dir}/x86/ml.exe")
        if(NOT EXISTS "${_ml_exe}")
            message(FATAL_ERROR "32-bit MASM (ml.exe) not found at ${_ml_exe}")
        endif()
        add_custom_command(
            OUTPUT "${_compat_asm_obj}"
            COMMAND "${_ml_exe}" /nologo /c "/Fo${_compat_asm_obj}" "${_compat_asm}"
            DEPENDS "${_compat_asm}"
            COMMENT "Assembling XP compat stubs (ml.exe)"
            VERBATIM)
        target_sources(${_win32_server_name} PRIVATE "${_compat_asm_obj}")
        set_source_files_properties("${_compat_asm_obj}" PROPERTIES
            EXTERNAL_OBJECT TRUE GENERATED TRUE)
        target_link_libraries(${_win32_server_name} PRIVATE shlwapi)
    endif()
endif()
