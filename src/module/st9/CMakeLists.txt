# Processor Module: st9
ida_add_procmod(st9
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        st9.hpp
)
copy_cfg(st9 ${CMAKE_CURRENT_SOURCE_DIR}/st9.cfg)