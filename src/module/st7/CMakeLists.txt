# Processor Module: st7
ida_add_procmod(st7
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        st7.hpp
)
copy_cfg(st7 ${CMAKE_CURRENT_SOURCE_DIR}/st7.cfg)