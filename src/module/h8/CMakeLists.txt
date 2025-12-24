# Processor Module: h8
ida_add_procmod(h8
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        h8.hpp
        ins.hpp
)
copy_cfg(h8 ${CMAKE_CURRENT_SOURCE_DIR}/h8.cfg)