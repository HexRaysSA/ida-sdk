# deploy.cmake -- file-tracked deploy targets (concrete OUTPUTs so repeat
# builds elide). ida_add_deploy_files = per-file; ida_add_deploy_stamp = stamp.

include_guard(GLOBAL)

# ida_add_deploy_files(NAME FILES <src dst>... [POST_COPY_COMMAND ...] [DEPENDS ...] [COMMENT ...] [ALL])
function(ida_add_deploy_files NAME)
    cmake_parse_arguments(ARG
        "ALL"
        "COMMENT"
        "FILES;POST_COPY_COMMAND;DEPENDS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "ida_add_deploy_files(${NAME}): unexpected args: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_FILES)
        message(FATAL_ERROR "ida_add_deploy_files(${NAME}): FILES is required")
    endif()

    list(LENGTH ARG_FILES _nfiles)
    math(EXPR _odd "${_nfiles} % 2")
    if(_odd)
        message(FATAL_ERROR
            "ida_add_deploy_files(${NAME}): FILES must be an even number of items (src;dst pairs)")
    endif()

    set(_all_dsts "")
    math(EXPR _last "${_nfiles} - 1")
    foreach(_i RANGE 0 ${_last} 2)
        math(EXPR _j "${_i} + 1")
        list(GET ARG_FILES ${_i} _src)
        list(GET ARG_FILES ${_j} _dst)

        get_filename_component(_dst_dir "${_dst}" DIRECTORY)

        set(_cmds
            COMMAND ${CMAKE_COMMAND} -E make_directory "${_dst_dir}"
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${_src}" "${_dst}"
        )
        if(ARG_POST_COPY_COMMAND)
            set(_post "")
            foreach(_tok IN LISTS ARG_POST_COPY_COMMAND)
                string(REPLACE "@DST@" "${_dst}" _tok "${_tok}")
                list(APPEND _post "${_tok}")
            endforeach()
            list(APPEND _cmds COMMAND ${_post})
        endif()

        add_custom_command(
            OUTPUT "${_dst}"
            ${_cmds}
            DEPENDS "${_src}" ${ARG_DEPENDS}
            COMMENT "${ARG_COMMENT}"
            VERBATIM
        )
        list(APPEND _all_dsts "${_dst}")
    endforeach()

    set(_all_kw "")
    if(ARG_ALL)
        set(_all_kw ALL)
    endif()
    add_custom_target(${NAME} ${_all_kw} DEPENDS ${_all_dsts})
endfunction()

# ida_add_deploy_stamp(NAME STAMP <file> COMMAND <...> [PRE_COMMAND ...] [DEPENDS ...] [COMMENT ...] [ALL] [USES_TERMINAL])
function(ida_add_deploy_stamp NAME)
    cmake_parse_arguments(ARG
        "ALL;USES_TERMINAL"
        "STAMP;COMMENT"
        "COMMAND;PRE_COMMAND;DEPENDS"
        ${ARGN}
    )
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR
            "ida_add_deploy_stamp(${NAME}): unexpected args: ${ARG_UNPARSED_ARGUMENTS}")
    endif()
    if(NOT ARG_STAMP)
        message(FATAL_ERROR "ida_add_deploy_stamp(${NAME}): STAMP is required")
    endif()
    if(NOT ARG_COMMAND)
        message(FATAL_ERROR "ida_add_deploy_stamp(${NAME}): COMMAND is required")
    endif()

    set(_cmds "")
    if(ARG_PRE_COMMAND)
        list(APPEND _cmds COMMAND ${ARG_PRE_COMMAND})
    endif()
    list(APPEND _cmds COMMAND ${ARG_COMMAND})
    list(APPEND _cmds COMMAND ${CMAKE_COMMAND} -E touch "${ARG_STAMP}")

    set(_term_kw "")
    if(ARG_USES_TERMINAL)
        set(_term_kw USES_TERMINAL)
    endif()

    add_custom_command(
        OUTPUT "${ARG_STAMP}"
        ${_cmds}
        DEPENDS ${ARG_DEPENDS}
        COMMENT "${ARG_COMMENT}"
        ${_term_kw}
        VERBATIM
    )

    set(_all_kw "")
    if(ARG_ALL)
        set(_all_kw ALL)
    endif()
    add_custom_target(${NAME} ${_all_kw} DEPENDS "${ARG_STAMP}")
endfunction()
