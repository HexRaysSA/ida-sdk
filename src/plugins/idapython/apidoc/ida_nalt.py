"""Definitions of various information kept in netnodes.

Each address in the program has a corresponding netnode: netnode(ea).
If we have no information about an address, the corresponding netnode is not created. Otherwise we will create a netnode and save information in it. All variable length information (names, comments, offset information, etc) is stored in the netnode.
Don't forget that some information is already stored in the flags (bytes.hpp)
netnode.
"""

def get_import_module_name(mod_index):
    """
    Returns the name of an imported module given its index

    :param mod_index: the module index
    :returns: None or the module name
    """
    pass


def enum_import_names(mod_index, callback):
    """
    Enumerate imports from a specific module.
    Please refer to list_imports.py example.

    :param mod_index: The module index
    :param callback: A callable object that will be invoked with an ea, name (could be None) and ordinal.
    :returns: 1-finished ok, -1 on error, otherwise callback return value (<=0)
    """
    pass
