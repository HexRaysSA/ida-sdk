"""Routines to manipulate function stack frames, stack variables, register variables and local labels.

The frame is represented as a structure::

  +------------------------------------------------+
  | function arguments                             |
  +------------------------------------------------+
  | return address (isn't stored in func_t)        |
  +------------------------------------------------+
  | saved registers (SI, DI, etc - func_t::frregs) |
  +------------------------------------------------+ <- typical BP
  |                                                |  |
  |                                                |  | func_t::fpd
  |                                                |  |
  |                                                | <- real BP
  | local variables (func_t::frsize)               |
  |                                                |
  |                                                |
  +------------------------------------------------+ <- SP

To access the structure of a function frame and stack variables, use:

* tinfo_t::get_func_frame(const func_t *pfn) (the preferred way)
* get_func_frame(tinfo_t *out, const func_t *pfn)
* tinfo_t::get_udt_details() gives info about stack variables: their type, 
  names, offset, etc

.. tip:: 
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies 
   common tasks and provides better type hints, while remaining fully compatible 
   with IDAPython for advanced use cases.
   
   For function frame operations, see :mod:`ida_domain.functions`."""
