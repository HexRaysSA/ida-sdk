# Processor Module: pdp11
ida_add_procmod(pdp11
    SOURCES
        ana.cpp
        emu.cpp
        float.c
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        pdp.hpp
        pdp_ml.h
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    float.c
    PROPERTIES HEADER_FILE_ONLY TRUE
)
