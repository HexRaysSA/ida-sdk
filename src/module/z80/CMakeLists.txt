# Processor Module: z80
ida_add_procmod(z80
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        i5.hpp
        ins.hpp
)
copy_cfg(z80 ${CMAKE_CURRENT_SOURCE_DIR}/z180.cfg)
