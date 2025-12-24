# Processor Module: i960
ida_add_procmod(i960
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        i960.hpp
        ins.hpp
)
copy_cfg(i960 ${CMAKE_CURRENT_SOURCE_DIR}/i960.cfg)