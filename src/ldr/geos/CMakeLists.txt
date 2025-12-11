# Loader: geos
ida_add_loader(geos
    SOURCES
        common.cpp
        geos.cpp
        ../idaldr.h
        geos.h
        geos2.h
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(common.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
