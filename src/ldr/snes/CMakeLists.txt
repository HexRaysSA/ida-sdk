# Loader: snes
ida_add_loader(snes
    SOURCES
        addr.cpp
        snes.cpp
        ../idaldr.h
        super-famicom.hpp
)

# Mark included .cpp files as header-only so they're tracked but not compiled
set_source_files_properties(addr.cpp PROPERTIES HEADER_FILE_ONLY TRUE)
