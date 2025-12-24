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
copy_cfg(m32r ${CMAKE_CURRENT_SOURCE_DIR}/m32r.cfg)