# Script processor modules - Python processor modules that get copied to bin/procs/

# List of Python processor modules
set(SCRIPT_PROCMODS
    ebc.py
    msp430.py
    proctemplate.py
)

# Create custom target to deploy script processor modules during build
add_custom_target(deploy_script_procmods ALL
    COMMENT "Deploying script processor modules to ${IDA_PROCMOD_DIR}"
)

# Copy each script file
foreach(script ${SCRIPT_PROCMODS})
    add_custom_command(TARGET deploy_script_procmods POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_CURRENT_SOURCE_DIR}/${script}"
            "${IDA_PROCMOD_DIR}/${script}"
        COMMENT "  Copying ${script}"
    )
endforeach()

message(STATUS "Script processor modules: ${SCRIPT_PROCMODS}")
