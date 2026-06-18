# idasdkConfig.cmake -- consumed by find_package(idasdk REQUIRED).

cmake_minimum_required(VERSION 3.25)

list(PREPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/modules")
set(IDA_CMAKE_DIR "${CMAKE_CURRENT_LIST_DIR}" CACHE PATH "IDA SDK helpers")
include("${CMAKE_CURRENT_LIST_DIR}/modules/deploy.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/modules/dbg.cmake")

# 1. IDASDK / IDABIN
block(SCOPE_FOR VARIABLES PROPAGATE IDASDK IDABIN)
    if(NOT IDASDK)
        if(DEFINED ENV{IDASDK})
            set(IDASDK "$ENV{IDASDK}")
        else()
            message(FATAL_ERROR
                "IDASDK must be defined (cache var or env var).")
        endif()
    endif()
    cmake_path(ABSOLUTE_PATH IDASDK NORMALIZE)

    if(NOT IDABIN)
        if(DEFINED ENV{IDABIN})
            set(IDABIN "$ENV{IDABIN}")
        else()
            cmake_path(APPEND IDASDK "bin" OUTPUT_VARIABLE IDABIN)
        endif()
    endif()
    cmake_path(ABSOLUTE_PATH IDABIN NORMALIZE)
endblock()

# 2. Target triple: platform booleans, arch, EA size, lib paths, output dirs.
option(IDA_EA64 "64-bit address space" ON)
option(IDA_FORCE_X86 "Force x86 cross-build from a 64-bit host" OFF)
option(IDA_USE_STATIC_RUNTIME "Static CRT (MSVC only)" OFF)

set(IDA_NT FALSE)
set(IDA_LINUX FALSE)
set(IDA_MAC FALSE)
set(IDA_UNIX FALSE)

# Host dispatch table. Columns (separator '~' so cmake's ';' list semantics
# stay free for foreach, and '|' stays usable inside regex bodies): system ~
# host-flag ~ platform-name ~ platform-def ~ dllext ~ static-ext ~ obj-ext ~
# lib-name ~ idalib-name.
set(_ida_hosts
    "Windows~NT~win~__NT__~.dll~.lib~.obj~ida.lib~idalib.lib"
    "Linux~LINUX~linux~__LINUX__~.so~.a~.o~libida.so~libidalib.so"
    "Darwin~MAC~mac~__MAC__~.dylib~.a~.o~libida.dylib~libidalib.dylib"
)
set(_ida_host_resolved FALSE)
foreach(_row IN LISTS _ida_hosts)
    string(REPLACE "~" ";" _cols "${_row}")
    list(GET _cols 0 _sys)
    if(CMAKE_SYSTEM_NAME STREQUAL "${_sys}")
        list(GET _cols 1 _host)
        list(GET _cols 2 IDA_PLATFORM_NAME)
        list(GET _cols 3 IDAPROPLAT)
        list(GET _cols 4 IDA_DLLEXT)
        list(GET _cols 5 IDA_STATIC_EXT)
        list(GET _cols 6 IDA_OBJ_EXT)
        list(GET _cols 7 IDA_LIB_NAME)
        list(GET _cols 8 IDALIB_NAME)
        set(IDA_${_host} TRUE)
        if(NOT _host STREQUAL "NT")
            set(IDA_UNIX TRUE)
        endif()
        set(_ida_host_resolved TRUE)
        break()
    endif()
endforeach()
if(NOT _ida_host_resolved)
    message(FATAL_ERROR "Unsupported host: ${CMAKE_SYSTEM_NAME}")
endif()

# Arch dispatch table. First match wins on lower-cased input. Columns
# (separator '~' since regexes use '|'): regex ~ arch-name ~ macos-single-ok
# (YES/NO). "NO" keeps macOS single-arch strict (x86 is never a macOS arch).
set(_ida_archs
    "^(arm64|aarch64)$~arm64~YES"
    "^(x86[_-]64|amd64)$~x64~YES"
    "^(i[3-6]86|x86)$~x86~NO"
)

# Arch precedence: CMAKE_OSX_ARCHITECTURES (macOS) > IDA_FORCE_X86 >
# CMAKE_SYSTEM_PROCESSOR (regex) > CMAKE_SIZEOF_VOID_P fallback.
set(IDA_UNIVERSAL FALSE)
unset(IDA_ARCH)
list(LENGTH CMAKE_OSX_ARCHITECTURES _osx_n)
if(IDA_MAC AND _osx_n GREATER 1)
    set(IDA_ARCH "universal")
    set(IDA_UNIVERSAL TRUE)
elseif(IDA_MAC AND _osx_n EQUAL 1)
    string(TOLOWER "${CMAKE_OSX_ARCHITECTURES}" _arch_input)
    foreach(_row IN LISTS _ida_archs)
        string(REPLACE "~" ";" _cols "${_row}")
        list(GET _cols 0 _re)
        list(GET _cols 1 _ar)
        list(GET _cols 2 _mac_ok)
        if(_mac_ok STREQUAL "YES" AND _arch_input MATCHES "${_re}")
            set(IDA_ARCH "${_ar}")
            break()
        endif()
    endforeach()
    if(NOT DEFINED IDA_ARCH)
        message(FATAL_ERROR
            "Unsupported CMAKE_OSX_ARCHITECTURES: ${CMAKE_OSX_ARCHITECTURES}")
    endif()
elseif(IDA_FORCE_X86)
    set(IDA_ARCH "x86")
else()
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _arch_input)
    foreach(_row IN LISTS _ida_archs)
        string(REPLACE "~" ";" _cols "${_row}")
        list(GET _cols 0 _re)
        list(GET _cols 1 _ar)
        if(_arch_input MATCHES "${_re}")
            set(IDA_ARCH "${_ar}")
            break()
        endif()
    endforeach()
    if(NOT DEFINED IDA_ARCH)
        if(CMAKE_SIZEOF_VOID_P EQUAL 4)
            set(IDA_ARCH "x86")
        else()
            set(IDA_ARCH "x64")
        endif()
    endif()
endif()

unset(_ida_hosts)
unset(_ida_archs)
unset(_ida_host_resolved)
unset(_row)
unset(_cols)
unset(_sys)
unset(_host)
unset(_re)
unset(_ar)
unset(_mac_ok)
unset(_arch_input)
unset(_osx_n)

set(IDA_X64 FALSE)
set(IDA_X86 FALSE)
set(IDA_ARM FALSE)
if(IDA_ARCH STREQUAL "x64")
    set(IDA_X64 TRUE)
elseif(IDA_ARCH STREQUAL "x86")
    set(IDA_X86 TRUE)
elseif(IDA_ARCH STREQUAL "arm64")
    set(IDA_ARM TRUE)
endif()

if(IDA_EA64)
    set(IDA_EA32 FALSE)
    set(IDA_ADRSIZE 64)
    set(IDA_SUFF32 "")
else()
    set(IDA_EA32 TRUE)
    set(IDA_ADRSIZE 32)
    set(IDA_SUFF32 "32")
endif()

# XP compat: static-runtime MSVC builds redirect __imp_* symbols to fallback
# implementations for Windows XP / 7.
if(MSVC AND IDA_USE_STATIC_RUNTIME)
    set(IDA_XPCOMPAT ON)
else()
    set(IDA_XPCOMPAT OFF)
endif()

# /MD vs /MT (must be set pre-add_library on MSVC).
if(MSVC)
    if(IDA_USE_STATIC_RUNTIME)
        set(CMAKE_MSVC_RUNTIME_LIBRARY
            "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    else()
        set(CMAKE_MSVC_RUNTIME_LIBRARY
            "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
endif()

# lib/<arch>_<plat>_<bits>[_s] -- the _s suffix is Windows-static only.
set(_static_marker "")
if(IDA_USE_STATIC_RUNTIME AND IDA_NT)
    set(_static_marker "_s")
endif()
set(IDA_LIB_SUFFIX
    "${IDA_ARCH}_${IDA_PLATFORM_NAME}_${IDA_ADRSIZE}${_static_marker}")
unset(_static_marker)
cmake_path(APPEND IDASDK "lib" "${IDA_LIB_SUFFIX}" OUTPUT_VARIABLE IDA_LIB_DIR)
cmake_path(APPEND IDA_LIB_DIR "${IDA_LIB_NAME}"    OUTPUT_VARIABLE IDA_LIB_PATH)
cmake_path(APPEND IDA_LIB_DIR "${IDALIB_NAME}"     OUTPUT_VARIABLE IDALIB_PATH)

# Universal mac builds: merge per-arch dylibs with lipo into a single file.
if(IDA_UNIVERSAL)
    set(_merged_root "${CMAKE_BINARY_DIR}/_ida_universal")
    file(MAKE_DIRECTORY "${_merged_root}")
    foreach(_kind ida idalib)
        set(_parts "")
        foreach(_a IN LISTS CMAKE_OSX_ARCHITECTURES)
            if(_a STREQUAL "arm64")
                set(_iarch "arm64")
            elseif(_a MATCHES "^(x86_64|x64|amd64)$")
                set(_iarch "x64")
            else()
                message(FATAL_ERROR "Universal build: unsupported '${_a}'")
            endif()
            set(_p "${IDASDK}/lib/${_iarch}_${IDA_PLATFORM_NAME}_${IDA_ADRSIZE}/lib${_kind}.dylib")
            if(EXISTS "${_p}")
                list(APPEND _parts "${_p}")
            endif()
        endforeach()
        if(_parts)
            set(_out "${_merged_root}/lib${_kind}.dylib")
            execute_process(
                COMMAND lipo -create ${_parts} -output "${_out}"
                RESULT_VARIABLE _rc)
            if(NOT _rc EQUAL 0)
                message(FATAL_ERROR "lipo failed for lib${_kind} (rc=${_rc})")
            endif()
            if(_kind STREQUAL "ida")
                set(IDA_LIB_PATH "${_out}")
            else()
                set(IDALIB_PATH "${_out}")
            endif()
        endif()
    endforeach()
    unset(_merged_root)
endif()

# Default output dirs (consumer may override before calling ida_add_*).
if(NOT DEFINED IDA_PLUGIN_DIR)
    cmake_path(APPEND IDABIN "plugins" OUTPUT_VARIABLE IDA_PLUGIN_DIR)
endif()
if(NOT DEFINED IDA_LOADER_DIR)
    cmake_path(APPEND IDABIN "loaders" OUTPUT_VARIABLE IDA_LOADER_DIR)
endif()
if(NOT DEFINED IDA_PROCMOD_DIR)
    cmake_path(APPEND IDABIN "procs" OUTPUT_VARIABLE IDA_PROCMOD_DIR)
endif()

# 3. Interface lib for compile/link settings + idasdk::* imported targets.
if(NOT TARGET ida_addon_base)
    add_library(ida_addon_base INTERFACE)
    target_compile_features(ida_addon_base INTERFACE cxx_std_17)
    set_property(TARGET ida_addon_base PROPERTY
        INTERFACE_POSITION_INDEPENDENT_CODE ON)

    # __ARM__ / __X86__ are guards in some SDK sources; absence implies x64.
    set(_addon_defs "${IDAPROPLAT}")
    if(IDA_UNIX)
        list(APPEND _addon_defs "__UNIX__")
    endif()
    if(IDA_ARM)
        list(APPEND _addon_defs "__ARM__")
    elseif(IDA_X86)
        list(APPEND _addon_defs "__X86__")
    endif()
    if(IDA_EA64)
        list(APPEND _addon_defs "__EA64__=1")
    endif()
    target_compile_definitions(ida_addon_base INTERFACE ${_addon_defs})
    unset(_addon_defs)

    if(MSVC)
        target_compile_options(ida_addon_base INTERFACE
            /EHsc /Zc:wchar_t /Zc:inline /utf-8
            /wd4244 /wd4267 /wd4146 /wd4018 /wd4996)
    else()
        target_compile_options(ida_addon_base INTERFACE
            -fno-strict-aliasing -fvisibility=hidden)
    endif()

    if(IDA_X86 AND IDA_LINUX)
        target_compile_options(ida_addon_base INTERFACE -m32)
        target_link_options(ida_addon_base INTERFACE -m32)
    endif()
endif()

# Back-compat aliases for dbg/* and older two-target naming.
if(NOT TARGET ida_platform_settings)
    add_library(ida_platform_settings INTERFACE)
    target_link_libraries(ida_platform_settings INTERFACE ida_addon_base)
endif()
if(NOT TARGET ida_compiler_settings)
    add_library(ida_compiler_settings INTERFACE)
    target_link_libraries(ida_compiler_settings INTERFACE ida_addon_base)
endif()

# SDK root is included because example sources reach across to module/, ldr/.
set(_idasdk_includes "${IDASDK}/include" "${IDASDK}")
if(EXISTS "${IDASDK}/include/sdk")
    list(APPEND _idasdk_includes "${IDASDK}/include/sdk")
endif()

set(_kind_plugin_include  "")
set(_kind_plugin_define   "__IDP__")
set(_kind_loader_include  "${IDASDK}/ldr")
set(_kind_loader_define   "__LOADER__")
set(_kind_procmod_include "${IDASDK}/module")
set(_kind_procmod_define  "__IDP__")
set(_kind_idalib_include  "")
set(_kind_idalib_define   "IDALIB_IMPL")

foreach(_kind plugin loader procmod idalib)
    set(_tgt "idasdk::${_kind}")
    if(TARGET ${_tgt})
        continue()
    endif()
    add_library(${_tgt} INTERFACE IMPORTED)
    set(_inc "${_idasdk_includes}")
    if(_kind_${_kind}_include)
        list(APPEND _inc "${_kind_${_kind}_include}")
    endif()
    set_target_properties(${_tgt} PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES  "${_inc}"
        INTERFACE_COMPILE_DEFINITIONS  "${_kind_${_kind}_define}")
    # idalib references symbols provided by libida -- link both.
    if(_kind STREQUAL "idalib")
        target_link_libraries(${_tgt} INTERFACE
            ida_addon_base "${IDALIB_PATH}" "${IDA_LIB_PATH}")
    else()
        target_link_libraries(${_tgt} INTERFACE
            ida_addon_base "${IDA_LIB_PATH}")
    endif()
endforeach()
unset(_idasdk_includes)
foreach(_k plugin loader procmod idalib)
    unset(_kind_${_k}_include)
    unset(_kind_${_k}_define)
endforeach()

# 4. Public addon helpers (each ida_add_<kind> delegates here).
function(_idasdk_define_addon kind target_name out_dir)
    cmake_parse_arguments(P
        ""
        "TYPE;OUTPUT_NAME"
        "SOURCES;LIBRARIES;INCLUDES;DEFINES;QT_COMPONENTS"
        ${ARGN})

    if(P_TYPE STREQUAL "QT" AND IDACMAKE_SKIP_QT)
        message(STATUS "${target_name}: skipped (IDACMAKE_SKIP_QT)")
        return()
    endif()

    # When called from an orchestrator one level up, bare names resolve to ${target_name}/.
    set(_resolved "")
    set(_have_subdir FALSE)
    if(IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${target_name}")
        set(_have_subdir TRUE)
    endif()
    foreach(_s IN LISTS P_SOURCES)
        if(IS_ABSOLUTE "${_s}")
            list(APPEND _resolved "${_s}")
        elseif(_have_subdir)
            list(APPEND _resolved "${target_name}/${_s}")
        else()
            list(APPEND _resolved "${_s}")
        endif()
    endforeach()

    if(kind STREQUAL "idalib")
        if(NOT P_TYPE)
            message(FATAL_ERROR
                "ida_add_idalib(${target_name}): TYPE EXECUTABLE|SHARED|STATIC required")
        endif()
        if(P_TYPE STREQUAL "EXECUTABLE")
            add_executable(${target_name} ${_resolved})
        elseif(P_TYPE MATCHES "^(SHARED|STATIC)$")
            add_library(${target_name} ${P_TYPE} ${_resolved})
        else()
            message(FATAL_ERROR
                "ida_add_idalib(${target_name}): bad TYPE '${P_TYPE}'")
        endif()
    else()
        add_library(${target_name} SHARED ${_resolved})
    endif()

    # Customer overrides apply after the SDK target so they win on collisions.
    target_link_libraries(${target_name} PRIVATE "idasdk::${kind}")
    if(P_LIBRARIES)
        target_link_libraries(${target_name} PRIVATE ${P_LIBRARIES})
    endif()
    if(P_INCLUDES)
        target_include_directories(${target_name} PRIVATE ${P_INCLUDES})
    endif()
    if(P_DEFINES)
        target_compile_definitions(${target_name} PRIVATE ${P_DEFINES})
    endif()

    set_target_properties(${target_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${out_dir}"
        LIBRARY_OUTPUT_DIRECTORY "${out_dir}")
    if(NOT IDA_NT)
        set_target_properties(${target_name} PROPERTIES PREFIX "")
    endif()
    if(P_OUTPUT_NAME)
        set_target_properties(${target_name} PROPERTIES
            OUTPUT_NAME "${P_OUTPUT_NAME}")
    endif()
    if(IDA_NT AND NOT P_TYPE STREQUAL "EXECUTABLE")
        target_link_options(${target_name} PRIVATE /SUBSYSTEM:WINDOWS)
    endif()

    if(P_TYPE STREQUAL "QT")
        set(_qt_comp "${P_QT_COMPONENTS}")
        if(NOT _qt_comp)
            set(_qt_comp Core Gui Widgets)
        endif()
        find_package(Qt6 QUIET COMPONENTS ${_qt_comp})
        if(NOT Qt6_FOUND)
            message(STATUS
                "${target_name}: Qt6 ${_qt_comp} not found; target skipped")
            set_target_properties(${target_name} PROPERTIES
                EXCLUDE_FROM_ALL TRUE)
            return()
        endif()
        set_target_properties(${target_name} PROPERTIES
            AUTOMOC ON AUTORCC ON AUTOUIC ON)
        foreach(_c IN LISTS _qt_comp)
            if(TARGET "Qt6::${_c}")
                target_link_libraries(${target_name} PRIVATE "Qt6::${_c}")
            endif()
        endforeach()
        target_compile_definitions(${target_name} PRIVATE
            __QT__ QT_DLL QT_THREAD_SUPPORT)
        if(MSVC)
            target_compile_options(${target_name} PRIVATE /GR)
        endif()
    endif()

    # SDK headers are warning-noisy; silence per-target by default.
    if(MSVC)
        target_compile_options(${target_name} PRIVATE /w)
    else()
        target_compile_options(${target_name} PRIVATE -w)
    endif()
endfunction()

foreach(_pair "plugin;${IDA_PLUGIN_DIR}"
              "loader;${IDA_LOADER_DIR}"
              "procmod;${IDA_PROCMOD_DIR}"
              "idalib;${IDABIN}")
    list(GET _pair 0 _kind)
    list(GET _pair 1 _outdir)
    cmake_language(EVAL CODE "
        function(ida_add_${_kind} name)
            _idasdk_define_addon(${_kind} \${name} \"${_outdir}\" \${ARGN})
        endfunction()
    ")
endforeach()
unset(_pair)
unset(_kind)
unset(_outdir)

function(copy_cfg target src)
    if(NOT EXISTS "${src}")
        return()
    endif()
    cmake_path(GET src FILENAME _name)
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E make_directory "${IDABIN}/cfg"
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different
                "${src}" "${IDABIN}/cfg/${_name}")
endfunction()

function(ida_disable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W0)
    else()
        target_compile_options(${target} PRIVATE -w)
    endif()
endfunction()

# 5. SDK version probe (reads include/pro.h).
block(SCOPE_FOR VARIABLES PROPAGATE
        idasdk_FOUND idasdk_VERSION idasdk_INCLUDE_DIRS idasdk_LIBRARY_DIRS
        IDA_SDK_VERSION IDA_SDK_VERSION_NUM IDA_SDK_MAJOR IDA_SDK_MINOR)
    set(_pro "${IDASDK}/include/pro.h")
    if(EXISTS "${_pro}")
        file(STRINGS "${_pro}" _v_lines
             REGEX "^#[ \t]*define[ \t]+IDA_SDK_VERSION[ \t]+[0-9]+")
        foreach(_l IN LISTS _v_lines)
            if(_l MATCHES "IDA_SDK_VERSION[ \t]+([0-9]+)")
                set(_n "${CMAKE_MATCH_1}")
                math(EXPR _maj "${_n} / 100")
                math(EXPR _min "(${_n} % 100) / 10")
                set(IDA_SDK_VERSION_NUM "${_n}")
                set(IDA_SDK_MAJOR       "${_maj}")
                set(IDA_SDK_MINOR       "${_min}")
                set(IDA_SDK_VERSION     "${_maj}.${_min}")
                set(idasdk_VERSION      "${_maj}.${_min}")
                break()
            endif()
        endforeach()
    endif()
    set(idasdk_FOUND TRUE)
    if(NOT idasdk_VERSION)
        set(idasdk_VERSION "unknown")
    endif()
    set(idasdk_INCLUDE_DIRS "${IDASDK}/include")
    set(idasdk_LIBRARY_DIRS "${IDASDK}/lib")
endblock()
