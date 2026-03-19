"""File I/O functions for IDA.

You should not use standard C file I/O functions in modules. Use functions from this header, pro.h and fpro.h instead.
This file also declares a call_system() function. 
"""

def enumerate_files(path, fname, callback):
    """
    Enumerate files in the specified directory while the callback returns 0.

    :param path: directory to enumerate files in
    :param fname: mask of file names to enumerate
    :param callback: a callable object that takes the filename as
                     its first argument and it returns 0 to continue
                     enumeration or non-zero to stop enumeration.
    :returns: tuple(code, fname) : If the callback returns non-zero, or None in case of script errors
    """
    pass

