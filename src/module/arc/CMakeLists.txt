# Processor Module: arc
ida_add_procmod(arc
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        arc.hpp
        ins.hpp
)
copy_cfg(arc ${CMAKE_CURRENT_SOURCE_DIR}/arc.cfg)
