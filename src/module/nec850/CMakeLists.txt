# Processor Module: nec850
ida_add_procmod(nec850
    SOURCES
        ana.cpp
        cfh.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        regfinder.cpp
        ../idaidp.hpp
        ins.hpp
        necv850.hpp
)
