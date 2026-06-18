# warnings_configure.cmake -- SDK warning policy data (lenient, no -Werror). Keyed by IDA_WARNINGS=none|default|all.

# Global set: applied to ida_compiler_settings, propagated via IDASDK::*.
if(MSVC)
    if(IDA_WARNINGS STREQUAL "none")
        set(_w_global /w)
    elseif(IDA_WARNINGS STREQUAL "all")
        set(_w_global /W4)
    else() # default
        set(_w_global /W3)
    endif()
elseif(IDA_WARNINGS STREQUAL "none")
    set(_w_global -w)
else() # gcc / clang, default|all -- warn, but never error
    set(_w_global -Wall -Wextra)
endif()

# Module suppression set: source-level so it wins over INTERFACE -Wall.
if(MSVC)
    set(_w_module
        /wd4244 /wd4267 /wd4996 /wd4018 /wd4146
        /wd4800 /wd4251 /wd4005 /wd4099 /wd4065)
else()
    set(_w_module
        -Wno-unused-parameter
        -Wno-sign-compare
        -Wno-format-zero-length
        -Wno-format
        -Wno-parentheses
        -Wno-unused-variable
        -Wno-unused-function
        -Wno-switch)
endif()
set(IDA_MODULE_WNO_none    "")
set(IDA_MODULE_WNO_default "${_w_module}")
set(IDA_MODULE_WNO_all     "${_w_module}")

# Shared application functions (ida_apply_global_warnings / ida_module_warnings).
include(${CMAKE_CURRENT_LIST_DIR}/warnings.cmake)

# Public SDK helpers (part of the idasdkConfig API).

# Silence noisy warnings via source-level set (wins over INTERFACE -Wall/-Wextra).
function(ida_disable_warnings target)
    ida_module_warnings(${target})
endfunction()

# Opt-in strict warnings for a target (customer convenience; unused in-tree).
function(ida_enable_strict_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Werror -pedantic)
    endif()
endfunction()
