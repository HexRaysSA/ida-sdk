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

# IDC loader
list(APPEND SCRIPT_LOADERS hppacore.idc)

# Support directory for esp loader
set(SCRIPT_LOADER_DIRS
    esp
)

# Build src/dst pairs for ida_add_deploy_files.
set(_script_loader_pairs "")
foreach(_s IN LISTS SCRIPT_LOADERS)
    list(APPEND _script_loader_pairs
        "${CMAKE_CURRENT_SOURCE_DIR}/${_s}"
        "${IDA_LOADER_DIR}/${_s}"
    )
endforeach()

ida_add_deploy_files(_deploy_script_loader_files
    FILES   ${_script_loader_pairs}
    COMMENT "Deploying script loader"
)

# Directory copies — each tracked by its own stamp (copy_directory has
# no single output CMake can stat).
set(_script_loader_dir_targets "")
foreach(_d IN LISTS SCRIPT_LOADER_DIRS)
    set(_tgt "_deploy_script_loader_dir_${_d}")
    ida_add_deploy_stamp(${_tgt}
        STAMP   "${CMAKE_CURRENT_BINARY_DIR}/deploy_${_d}.stamp"
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                "${CMAKE_CURRENT_SOURCE_DIR}/${_d}"
                "${IDA_LOADER_DIR}/${_d}"
        COMMENT "Deploying script loader support dir ${_d}/"
    )
    list(APPEND _script_loader_dir_targets ${_tgt})
endforeach()

# Umbrella — preserves the public deploy_script_loaders target name.
add_custom_target(deploy_script_loaders ALL
    DEPENDS _deploy_script_loader_files ${_script_loader_dir_targets}
)

message(STATUS "Script loaders: ${SCRIPT_LOADERS}")
