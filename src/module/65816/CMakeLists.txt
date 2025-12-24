# Processor Module: m65816
ida_add_procmod(m65816
    SOURCES
        ana.cpp
        bt.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        bt.hpp
        ins.hpp
        m65816.hpp
)
copy_cfg(m65816 ${CMAKE_CURRENT_SOURCE_DIR}/m65816.cfg)
