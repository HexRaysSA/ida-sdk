# Processor Module: c39
ida_add_procmod(c39
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        c39.hpp
        ins.hpp
)
copy_cfg(c39 ${CMAKE_CURRENT_SOURCE_DIR}/c39.cfg)
