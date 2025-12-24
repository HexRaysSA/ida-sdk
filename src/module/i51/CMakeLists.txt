# Processor Module: i51
ida_add_procmod(i51
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        i51.hpp
        ins.hpp
)
copy_cfg(i51 ${CMAKE_CURRENT_SOURCE_DIR}/i51.cfg)