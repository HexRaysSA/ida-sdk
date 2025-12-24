# Processor Module: m740
ida_add_procmod(m740
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        m740.hpp
)
copy_cfg(m740 ${CMAKE_CURRENT_SOURCE_DIR}/m740.cfg)