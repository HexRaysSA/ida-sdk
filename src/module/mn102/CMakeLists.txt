# Processor Module: mn102l00
ida_add_procmod(mn102l00
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        pan.hpp
)
copy_cfg(mn102l00 ${CMAKE_CURRENT_SOURCE_DIR}/mn102l00.cfg)
