# Processor Module: m7700
ida_add_procmod(m7700
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        m7700.hpp
)
copy_cfg(m7700 ${CMAKE_CURRENT_SOURCE_DIR}/m7700.cfg)