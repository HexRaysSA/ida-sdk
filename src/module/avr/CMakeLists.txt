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
