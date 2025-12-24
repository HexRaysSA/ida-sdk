# Processor Module: st20
ida_add_procmod(st20
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        st20.hpp
)
copy_cfg(st20 ${CMAKE_CURRENT_SOURCE_DIR}/st20.cfg)