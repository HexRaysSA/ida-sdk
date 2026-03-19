"""Routines for working with functions within the disassembled program.

This file also contains routines for working with library signatures (e.g. FLIRT).

Each function consists of function chunks. At least one function chunk must be present in the function definition - the function entry chunk. Other chunks are called function tails. There may be several of them for a function.

A function tail is a continuous range of addresses. It can be used in the definition of one or more functions. One function using the tail is singled out and called the tail owner. This function is considered as 'possessing' the tail. get_func() on a tail address will return the function possessing the tail. You can enumerate the functions using the tail by using func_parent_iterator_t.

Each function chunk in the disassembly is represented as an "range" (a range of addresses, see range.hpp for details) with characteristics.
A function entry must start with an instruction (code) byte. 

.. tip:: 
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies 
   common tasks and provides better type hints, while remaining fully compatible 
   with IDAPython for advanced use cases.
   
   For function management and analysis, see :mod:`ida_domain.functions`."""
# """
# Possible module replacement text
# """

def get_fchunk_referer(ea: int, idx):
    pass

def get_idasgn_desc(n):
    """
    Get information about a signature in the list.
    It returns: (name of signature, names of optional libraries)

    See also: get_idasgn_desc_with_matches

    :param n: number of signature in the list (0..get_idasgn_qty()-1)
    :returns: None on failure or tuple(signame, optlibs)
    """
    pass

def get_idasgn_desc_with_matches(n):
    """
    Get information about a signature in the list.
    It returns: (name of signature, names of optional libraries, number of matches)

    :param n: number of signature in the list (0..get_idasgn_qty()-1)
    :returns: None on failure or tuple(signame, optlibs, nmatches)
    """
    pass

class func_t(object):
    def get_name(self):
        """
        Get the function name

        :returns: the function name
        """
        pass

    def get_frame_object(self):
        """
        Retrieve the function frame, in the form of a structure
        where frame offsets that are accessed by the program, as well
        as areas for "saved registers" and "return address", are
        represented by structure members.

        If the function has no associated frame, return None

        :returns: a ida_typeinf.tinfo_t object representing the frame, or None
        """
        pass

    def get_prototype(self):
        """
        Retrieve the function prototype.

        Once you have obtained the prototype, you can:

        * retrieve the return type through ida_typeinf.tinfo_t.get_rettype()
        * iterate on the arguments using ida_typeinf.tinfo_t.iter_func()

        If the function has no associated prototype, return None

        :returns: a ida_typeinf.tinfo_t object representing the prototype, or None
        """
        pass

