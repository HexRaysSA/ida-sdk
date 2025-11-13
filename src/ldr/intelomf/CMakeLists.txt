# Loader: intelomf
ida_add_loader(intelomf
    SOURCES
        common.cpp
        intelomf.cpp
        ../idaldr.h
        intelomf.hpp
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(common.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
