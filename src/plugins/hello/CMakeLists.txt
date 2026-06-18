ida_add_plugin(hello
    SOURCES
        hello.cpp
)

foreach(_s pyhello.py idchello.idc)
    add_custom_command(TARGET hello POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/${_s}
            $<TARGET_FILE_DIR:hello>/${_s}
    )
endforeach()
