# Processor Module: pic
ida_add_procmod(pic
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        pic.hpp
)
copy_cfg(pic ${CMAKE_CURRENT_SOURCE_DIR}/pic12.cfg)
copy_cfg(pic ${CMAKE_CURRENT_SOURCE_DIR}/pic14.cfg)
copy_cfg(pic ${CMAKE_CURRENT_SOURCE_DIR}/pic16.cfg)
