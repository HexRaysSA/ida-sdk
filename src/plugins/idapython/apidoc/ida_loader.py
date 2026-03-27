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
