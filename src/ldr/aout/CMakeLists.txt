# Loader: aout
ida_add_loader(aout
    SOURCES
        aout.cpp
        common.cpp
        ../idaldr.h
        aout.h
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(common.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
