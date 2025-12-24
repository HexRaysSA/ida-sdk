# Processor Module: tlcs900
ida_add_procmod(tlcs900
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        tosh.hpp
)
copy_cfg(tlcs900 ${CMAKE_CURRENT_SOURCE_DIR}/tlcs900.cfg)