"""Definitions of IDP, LDR, PLUGIN module interfaces.

This file also contains:

* functions to load files into the database
* functions to generate output files
* high level functions to work with the database (open, save, close)


The LDR interface consists of one structure: loader_t

The IDP interface consists of one structure: processor_t

The PLUGIN interface consists of one structure: plugin_t

Modules can't use standard FILE* functions. They must use functions from <fpro.h>

Modules can't use standard memory allocation functions. They must use functions
from <pro.h>

The exported entry #1 in the module should point to the the appropriate
structure. (loader_t for LDR module, for example)

.. tip::
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies
   common tasks and provides better type hints, while remaining fully compatible
   with IDAPython for advanced use cases.

   For database operations, see :mod:`ida_domain.database`."""

def mem2base(mem, ea, fpos):
    """
    Load database from the memory.

    :param mem: the buffer
    :param ea: start linear addresses
    :param fpos: position in the input file the data is taken from.
                 if == -1, then no file position correspond to the data.
    :returns: 1, or 0 in case of failure
    """
    pass

def load_plugin(name):
    """
    Loads a plugin

    :param name: short plugin name without path and extension,
                 or absolute path to the file name
    :returns: An opaque object representing the loaded plugin, or None if plugin could not be loaded
    """
    pass

def run_plugin(plg, arg):
    """
    Runs a plugin

    :param plg: A plugin object (returned by load_plugin())
    :param arg: the code to pass to the plugin's "run()" function
    :returns: Boolean
    """
    pass

def import_module(module: str, windir: str, modnode: int, importer: None, ostype: str) -> None:
    """
    Register imports in the database, the way file loaders do.

    Before calling, populate ``modnode`` with the entries to register
    using :func:`set_import_name` (named imports) and/or
    :func:`set_import_ordinal` (ordinal imports). After the call the
    module appears in the Imports view and is enumerable through
    :func:`ida_nalt.get_import_module_qty`,
    :func:`ida_nalt.get_import_module_name` and
    :func:`ida_nalt.enum_import_names`.

    :param module: DLL/library name (e.g. ``"libfoo.so"``)
    :param windir: system directory with DLLs to probe; may be None
    :param modnode: index of a netnode you previously created with
                    ``netnode().create()`` and populated
    :param importer: must be ``None``. In a C++ loader this slot
                     accepts an optional callback IDA uses to walk a
                     sibling DLL on disk and discover its exports
                     (used by the PE/NE/LX loaders); a Python loader
                     has already parsed its input and has no DLL on
                     disk for IDA to probe, so the hook is not
                     exposed. The argument is kept in the signature
                     for one-to-one parity with the C++ API.
    :param ostype: OS subdir under ``ids/`` to look in (e.g. ``"win"``,
                   ``"linux"``); None means the IDS directory root
    """
    pass
