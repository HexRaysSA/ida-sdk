# Script processor modules - Python processor modules that get copied to bin/procs/

# List of Python processor modules
set(SCRIPT_PROCMODS
    ebc.py
    msp430.py
    proctemplate.py
)

# Build src/dst pairs for ida_add_deploy_files.
set(_script_procmod_pairs "")
foreach(_s IN LISTS SCRIPT_PROCMODS)
    list(APPEND _script_procmod_pairs
        "${CMAKE_CURRENT_SOURCE_DIR}/${_s}"
        "${IDA_PROCMOD_DIR}/${_s}"
    )
endforeach()

ida_add_deploy_files(deploy_script_procmods ALL
    FILES   ${_script_procmod_pairs}
    COMMENT "Deploying script processor module"
)

message(STATUS "Script processor modules: ${SCRIPT_PROCMODS}")
