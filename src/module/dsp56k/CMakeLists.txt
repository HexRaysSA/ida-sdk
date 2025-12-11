# Processor Module: dsp56k
ida_add_procmod(dsp56k
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        dsp56k.hpp
        ins.hpp
)
