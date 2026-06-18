# dbg.cmake -- sanity check for server-only flavors. Targets are defined
# directly via ida_add_plugin / add_executable; this module just enforces
# that IDA_BUILD_DBGSRV=ON produces at least one server binary.

option(IDA_SDK_VERIFY_BINARIES
    "Fail configuration if a debugger-server flavor would produce no binary" ON)

function(ida_dbg_verify_servers)
    if(NOT IDA_SDK_VERIFY_BINARIES)
        return()
    endif()
    get_property(_servers GLOBAL PROPERTY IDA_DBG_SERVERS)
    if(IDA_BUILD_DBGSRV AND (WIN32 OR IDA_PLATFORM_NAME STREQUAL "linux") AND NOT _servers)
        message(FATAL_ERROR
            "IDA_BUILD_DBGSRV is set but no debug-server target was configured for "
            "this host - the build would produce no server binary. Check dbg gating.")
    endif()
endfunction()
