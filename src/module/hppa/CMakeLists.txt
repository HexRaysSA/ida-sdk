# Processor Module: hppa
ida_add_procmod(hppa
    SOURCES
        ana.cpp
        emu.cpp
        hppa_cfh.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        hppa.hpp
        ins.hpp
        notify_codes.hpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    hppa_cfh.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)
