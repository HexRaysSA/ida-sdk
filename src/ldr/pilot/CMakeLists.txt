# Loader: pilot
ida_add_loader(pilot
    SOURCES
        common.cpp
        pilot.cpp
        ../idaldr.h
        pilot.hpp
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(common.cpp PROPERTIES HEADER_FILE_ONLY TRUE)

add_custom_command(TARGET pilot POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "${CMAKE_CURRENT_SOURCE_DIR}/pilot.idc"
        "${IDA_IDC_DIR}/pilot.idc"
    COMMENT "  Copying pilot.idc"
)
