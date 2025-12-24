# Processor Module: z8
ida_add_procmod(z8
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        z8.hpp
)
copy_cfg(z8 ${CMAKE_CURRENT_SOURCE_DIR}/z8.cfg)