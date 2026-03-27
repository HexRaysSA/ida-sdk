"""This is the first header included in the IDA project.

It defines the most common types, functions and data. Also, it tries to make system dependent definitions.
The following preprocessor macros are used in the project (the list may be incomplete)
Platform must be specified as one of:
__NT__ - MS Windows (all platforms)
 __LINUX__ - Linux
 __MAC__ - MAC OS X
__EA64__ - 64-bit address size (sizeof(ea_t)==8)
 __X86__ - 32-bit debug servers (sizeof(void*)==4)
 __X64__ - x64 processor (sizeof(void*)==8) default
 __PPC__ - PowerPC
 __ARM__ - ARM
"""

def str2user(str):
    """
    Insert C-style escape characters to string

    :param str: the input string
    :returns: new string with escape characters inserted, or None
    """
    pass
