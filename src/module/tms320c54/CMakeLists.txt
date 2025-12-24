# Processor Module: tms32054
ida_add_procmod(tms32054
    SOURCES
        ana.cpp
        emu.cpp
        ins.cpp
        merge.cpp
        out.cpp
        reg.cpp
        ../idaidp.hpp
        ins.hpp
        notify_codes.hpp
        tms320c54.hpp
)
copy_cfg(tms32054 ${CMAKE_CURRENT_SOURCE_DIR}/tms320c54.cfg)
