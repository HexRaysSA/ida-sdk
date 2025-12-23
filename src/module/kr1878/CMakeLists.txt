# Processor Module: kr1878
ida_add_procmod(kr1878
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        kr1878.hpp
)
copy_cfg(kr1878 ${CMAKE_CURRENT_SOURCE_DIR}/kr1878.cfg)