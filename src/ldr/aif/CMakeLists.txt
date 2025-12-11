# Loader: aif
ida_add_loader(aif
    SOURCES
        aif.cpp
        aifcmn.cpp
        ../idaldr.h
        aif.h
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(aifcmn.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
