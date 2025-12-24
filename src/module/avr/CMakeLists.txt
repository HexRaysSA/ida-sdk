# Processor Module: avr
ida_add_procmod(avr
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        avr.hpp
        ins.hpp
        notify_codes.hpp
)
copy_cfg(avr ${CMAKE_CURRENT_SOURCE_DIR}/avr.cfg)
