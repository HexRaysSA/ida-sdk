# Processor Module: 78k0s
ida_add_procmod(78k0s
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        78k_0s.hpp
        ins.hpp
)
copy_cfg(78k0s ${CMAKE_CURRENT_SOURCE_DIR}/78k0s.cfg)
