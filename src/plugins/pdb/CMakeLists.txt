ida_add_plugin(pdb
    SOURCES
        common.cpp
        cvadd.h
        cvconst.h
        dbghelp.h
        dia2.h
        merge.cpp
        misc.cpp
        msdia.cpp
        msdia.hpp
        old.cpp
        oldpdb.h
        pdb.cpp
        pdb.hpp
        pdbaccess.hpp
        pdblocal.cpp
        pdblocal.hpp
        pdbremote.cpp
        pdbremote.hpp
        sip.cpp
        sip.hpp
        tilbuild.cpp
        tilbuild.hpp
        varser.hpp
)

# Mark #included files as HEADER_FILE_ONLY
set_source_files_properties(
    misc.cpp
    PROPERTIES HEADER_FILE_ONLY TRUE
)

# Link DIA SDK (set by parent CMakeLists.txt)
target_include_directories(pdb PRIVATE ${DIA_SDK_INCLUDE_DIR})
target_link_libraries(pdb PRIVATE ${DIA_SDK_LIBRARY})

# Windows system libraries needed for DIA SDK
target_link_libraries(pdb PRIVATE ole32 oleaut32)
