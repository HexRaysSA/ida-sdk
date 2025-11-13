# Processor Module: m32r
ida_add_procmod(m32r
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        m32r.hpp
)
