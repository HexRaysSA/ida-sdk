# Script loaders - Python and IDC loaders that get copied to bin/loaders/

# List of Python loaders
set(SCRIPT_LOADERS
    archldr_tar.py
    bios_image.py
    esp.py
    md1img.py
    pdfldr.py
    uimage.py
    wince.py
)

# IDC loader (IDAADV only, but we deploy it anyway for SDK completeness)
list(APPEND SCRIPT_LOADERS hppacore.idc)

# Support directory for esp loader
set(SCRIPT_LOADER_DIRS
    esp
)

# Create custom target to deploy script loaders during build
add_custom_target(deploy_script_loaders ALL
    COMMENT "Deploying script loaders to ${IDA_LOADER_DIR}"
)

# Copy each script file
foreach(script ${SCRIPT_LOADERS})
    add_custom_command(TARGET deploy_script_loaders POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/${script}"
            "${IDA_LOADER_DIR}/${script}"
        COMMENT "  Copying ${script}"
    )
endforeach()

# Copy support directories
foreach(dir ${SCRIPT_LOADER_DIRS})
    add_custom_command(TARGET deploy_script_loaders POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            "${CMAKE_CURRENT_SOURCE_DIR}/${dir}"
            "${IDA_LOADER_DIR}/${dir}"
        COMMENT "  Copying ${dir}/"
    )
endforeach()

message(STATUS "Script loaders: ${SCRIPT_LOADERS}")
