ida_add_plugin(hexview
    SOURCES
        hexplace.cpp
        hexview.cpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    hexplace.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)
