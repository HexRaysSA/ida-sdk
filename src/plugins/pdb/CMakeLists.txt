ida_add_plugin(pdb
    SOURCES
        pdb.cpp
        pdb.hpp
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
if(WIN32)
    target_link_libraries(pdb PRIVATE wininet ole32 oleaut32)
endif()

copy_cfg(pdb ${CMAKE_CURRENT_SOURCE_DIR}/pdb.cfg)

