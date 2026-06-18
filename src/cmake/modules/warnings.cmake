# warnings.cmake -- shared warning helpers. Policy in warnings_configure.cmake.
# Module suppressions at SOURCE level so -Wno-* wins over INTERFACE -Wall/-Werror.

# $<COMPILE_LANGUAGE:C,CXX>: ml64/rc.exe reject MSVC /Wall, /wd<N>, /we<N>.
function(ida_apply_global_warnings target scope)
    if(_w_global)
        target_compile_options(${target} ${scope}
            "$<$<COMPILE_LANGUAGE:C,CXX>:${_w_global}>")
    endif()
endfunction()

# Apply module suppressions to <target>'s sources. ARGV1 picks per-module set. Call AFTER all sources added.
function(ida_module_warnings target)
    set(_key "${ARGV1}")
    if(_key AND DEFINED IDA_MODULE_WNO_${_key}_${IDA_WARNINGS})
        set(_set "${IDA_MODULE_WNO_${_key}_${IDA_WARNINGS}}")
    else()
        set(_set "${IDA_MODULE_WNO_${IDA_WARNINGS}}")
    endif()
    if(NOT _set)
        return()
    endif()
    get_target_property(_srcs ${target} SOURCES)
    if(NOT _srcs)
        message(FATAL_ERROR "ida_module_warnings: target '${target}' has no SOURCES")
    endif()
    set_source_files_properties(${_srcs}
        TARGET_DIRECTORY ${target}
        PROPERTIES COMPILE_OPTIONS "${_set}")
endfunction()
