# Processor Module: tms32055
ida_add_procmod(tms32055
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        tms320c55.hpp
)
copy_cfg(tms32055 ${CMAKE_CURRENT_SOURCE_DIR}/tms320c55.cfg)
