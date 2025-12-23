# Processor Module: f2mc
ida_add_procmod(f2mc
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        f2mc.hpp
        ins.hpp
)
copy_cfg(f2mc ${CMAKE_CURRENT_SOURCE_DIR}/f2mc16l.cfg)
copy_cfg(f2mc ${CMAKE_CURRENT_SOURCE_DIR}/f2mc16lx.cfg)
