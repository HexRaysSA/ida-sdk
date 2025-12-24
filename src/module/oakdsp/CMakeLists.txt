# Processor Module: oakdsp
ida_add_procmod(oakdsp
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        oakdsp.hpp
)
copy_cfg(oakdsp ${CMAKE_CURRENT_SOURCE_DIR}/oakdsp.cfg)