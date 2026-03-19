"""Contains the ::inf structure definition and some functions common to the whole IDA project.

The ::inf structure is saved in the database and contains information specific 
to the current program being disassembled. Initially it is filled with values 
from ida.cfg.

Although it is not a good idea to change values in ::inf structure (because you 
will overwrite values taken from ida.cfg), you are allowed to do it if you feel 
it necessary.

.. tip:: 
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies 
   common tasks and provides better type hints, while remaining fully compatible 
   with IDAPython for advanced use cases.
   
   For database operations, see :mod:`ida_domain.database`."""
