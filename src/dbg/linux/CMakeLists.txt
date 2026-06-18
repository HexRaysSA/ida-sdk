# Linux debugger SDK build.

set(_linux_base
    linuxbase_debmod.cpp linux_debmod.cpp linux_wait.cpp
    stack_unwind.cpp symelf.cpp)
set(_linux_hdrs
    linux_local_impl.cpp linux_threads.cpp android.cpp
    ../common_stub_impl.cpp ../common_local_impl.cpp ../arm_local_impl.cpp
    ../../plugins/dwarf/look_for_debug_file.cpp
    ../../ldr/elf/common.cpp ../../ldr/elf/reader.cpp)
# --undefined-version: lld rejects PLUGIN-naming scripts that gnu ld tolerates.
set(_linux_script
    "-Wl,--undefined-version -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/linux_debmod.script")

# Local Linux debugger plugin (Linux host only).
if(IDA_PLATFORM_NAME STREQUAL "linux" AND IDA_BUILD_IDA AND IDA_EA64)
    ida_add_plugin(linux_user
        SOURCES linux_user.cpp ${_linux_base} ${_linux_hdrs})
    set_source_files_properties(${_linux_hdrs} PROPERTIES HEADER_FILE_ONLY TRUE)
    target_link_libraries(linux_user PRIVATE
        dbg_plugin dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
        rt pthread dl thread_db)
    set_target_properties(linux_user PROPERTIES LINK_FLAGS "${_linux_script}")
    copy_cfg(linux_user ${CMAKE_CURRENT_SOURCE_DIR}/../exceptions.cfg)
endif()

# Debug server (Linux host only).
if(IDA_PLATFORM_NAME STREQUAL "linux" AND IDA_BUILD_DBGSRV)
    set(_linux_server_name "linux_server${IDA_SUFF32}")
    add_executable(${_linux_server_name} ${_linux_base} ${_linux_hdrs})
    set_source_files_properties(${_linux_hdrs} PROPERTIES HEADER_FILE_ONLY TRUE)
    target_include_directories(${_linux_server_name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/.. ${IDASDK} ${IDASDK}/include)
    # GNU ld: --start/--end-group resolves circular deps among the libs.
    target_link_libraries(${_linux_server_name} PRIVATE
        ida_platform_settings ida_compiler_settings
        -Wl,--start-group
        dbg_server dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/dumb${IDA_OBJ_EXT}
        ${IDA_LIB_DIR}/unicode${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/pro${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/int128${IDA_STATIC_EXT}
        ${IDA_LIB_DIR}/compress${IDA_STATIC_EXT}
        -Wl,--end-group
        rt pthread c dl thread_db)
    target_compile_options(${_linux_server_name} PRIVATE
        $<$<COMPILE_LANGUAGE:CXX>:-fno-rtti>)
    set_target_properties(${_linux_server_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${IDABIN}/dbgsrv"
        LINK_FLAGS "${_linux_script}")
    set_property(GLOBAL APPEND PROPERTY IDA_DBG_SERVERS ${_linux_server_name})
endif()

# Remote-debugging stubs (cross-platform; not macOS).
if(NOT APPLE AND IDA_BUILD_IDA AND IDA_EA64)
    ida_add_plugin(linux_stub
        SOURCES linux_stub.cpp stack_unwind.cpp
            linux_local_impl.cpp ../common_stub_impl.cpp ../common_local_impl.cpp)
    set_source_files_properties(
        linux_local_impl.cpp ../common_stub_impl.cpp ../common_local_impl.cpp
        PROPERTIES HEADER_FILE_ONLY TRUE)
    target_link_libraries(linux_stub PRIVATE
        dbg_plugin dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT})
    if(MSVC)
        set_target_properties(linux_stub PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    endif()

    ida_add_plugin(armlinux_stub
        SOURCES armlinux_stub.cpp stack_unwind.cpp
            linux_local_impl.cpp ../common_stub_impl.cpp ../common_local_impl.cpp
            ../arm_local_impl.cpp)
    set_source_files_properties(
        linux_local_impl.cpp ../common_stub_impl.cpp ../common_local_impl.cpp
        ../arm_local_impl.cpp
        PROPERTIES HEADER_FILE_ONLY TRUE)
    target_link_libraries(armlinux_stub PRIVATE
        dbg_plugin dbg_rpc dbg_proc
        ${IDA_LIB_DIR}/network${IDA_STATIC_EXT})
    if(MSVC)
        set_target_properties(armlinux_stub PROPERTIES
            MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
    endif()
endif()
