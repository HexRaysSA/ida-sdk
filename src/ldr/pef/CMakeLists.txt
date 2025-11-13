# Loader: pef
ida_add_loader(pef
    SOURCES
        common.cpp
        pef.cpp
        ../idaldr.h
        pef.hpp
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(common.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
