# IDALib Example: idacli
ida_add_idalib(idacli
    TYPE EXECUTABLE
    SOURCES
        idacli.cpp
)

# Platform-specific settings
if(UNIX AND NOT APPLE)
    # Linux: set rpath to $ORIGIN for finding shared libraries
    set_target_properties(idacli PROPERTIES
        INSTALL_RPATH "$ORIGIN"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
elseif(APPLE)
    # macOS: set rpath to @executable_path
    set_target_properties(idacli PROPERTIES
        INSTALL_RPATH "@executable_path/"
        BUILD_WITH_INSTALL_RPATH TRUE
    )
elseif(WIN32)
    # Windows: 4MB stack, add manifest, define NOMINMAX, etc.
    target_link_options(idacli PRIVATE
        /STACK:0x400000
        /MANIFEST
    )
    target_compile_definitions(idacli PRIVATE
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
    )
endif()
