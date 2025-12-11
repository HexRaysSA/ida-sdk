# Loader: hpsom
ida_add_loader(hpsom
    SOURCES
        common.cpp
        hpsom.cpp
        ../idaldr.h
        hpsom.hpp
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(common.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
