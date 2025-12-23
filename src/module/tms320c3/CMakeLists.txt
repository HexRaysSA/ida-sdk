# Processor Module: tms320c3
ida_add_procmod(tms320c3
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        tms320c3x.hpp
)
copy_cfg(tms320c3 ${CMAKE_CURRENT_SOURCE_DIR}/tms320c3.cfg)