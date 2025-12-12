# Script plugins - Python and IDC plugin scripts that get copied to bin/plugins/

# List of script plugins
set(SCRIPT_PLUGINS
    idcplugin.idc
    pyplugin.py
    procext.py
)

# Create custom target to deploy script plugins during build
add_custom_target(deploy_script_plugins ALL
    COMMENT "Deploying script plugins to ${IDA_PLUGIN_DIR}"
)

# Copy each script file
foreach(script ${SCRIPT_PLUGINS})
    add_custom_command(TARGET deploy_script_plugins POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/${script}"
            "${IDA_PLUGIN_DIR}/${script}"
        COMMENT "  Copying ${script}"
    )
endforeach()

message(STATUS "Script plugins: ${SCRIPT_PLUGINS}")
