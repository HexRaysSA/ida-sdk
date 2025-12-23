# Processor Module: m7900
ida_add_procmod(m7900
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        7900.hpp
        ins.hpp
)
copy_cfg(m7900 ${CMAKE_CURRENT_SOURCE_DIR}/m7900.cfg)