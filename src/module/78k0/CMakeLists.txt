# Processor Module: 78k0
ida_add_procmod(78k0
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        78k0.hpp
        ins.hpp
)
copy_cfg(78k0 ${CMAKE_CURRENT_SOURCE_DIR}/78k0.cfg)
