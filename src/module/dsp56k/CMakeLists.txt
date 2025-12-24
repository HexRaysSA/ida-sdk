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
copy_cfg(dsp56k ${CMAKE_CURRENT_SOURCE_DIR}/dsp56k.cfg)
copy_cfg(dsp56k ${CMAKE_CURRENT_SOURCE_DIR}/dsp561xx.cfg)
copy_cfg(dsp56k ${CMAKE_CURRENT_SOURCE_DIR}/dsp563xx.cfg)
copy_cfg(dsp56k ${CMAKE_CURRENT_SOURCE_DIR}/dsp566xx.cfg)
