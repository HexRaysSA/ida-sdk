# Processor Module: java
ida_add_procmod(java
    SOURCES
        ana.cpp
        emu.cpp
        fmtstr.cpp
        ins.cpp
        jas_rw.cc
        map.cpp
        npool.cpp
        npooluti.cpp
        out.cpp
        oututil.cpp
        reg.cpp
        resword.cpp
        upgrade.cpp
        ../idaidp.hpp
        classfil.hpp
        ins.hpp
        java.hpp
        notify_codes.hpp
        npooluti.hpp
        oututil.hpp
        upgrade.hpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    jas_rw.cc
    PROPERTIES HEADER_FILE_ONLY TRUE
)
