# Processor Module: fr
ida_add_procmod(fr
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        fr.hpp
        ins.hpp
)
copy_cfg(fr ${CMAKE_CURRENT_SOURCE_DIR}/fr.cfg)