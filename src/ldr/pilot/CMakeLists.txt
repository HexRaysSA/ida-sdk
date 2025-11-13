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
