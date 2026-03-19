"""Functions that deal with entry points.

Exported functions are considered as entry points as well.
IDA maintains list of entry points to the program. Each entry point:
   * has an address
   * has a name
   * may have an ordinal number 

.. tip:: 
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies 
   common tasks and provides better type hints, while remaining fully compatible 
   with IDAPython for advanced use cases.
   
   For entry point management, see :mod:`ida_domain.entries`."""
