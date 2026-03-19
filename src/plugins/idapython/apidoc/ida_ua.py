"""Functions that deal with the disassembling of program instructions.

There are 2 kinds of functions:

* functions that are called from the kernel to disassemble an instruction. 
  These functions call IDP module for it.
* functions that are called from IDP module to disassemble an instruction. 
  We will call them 'helper functions'.


Disassembly of an instruction is made in three steps:

0. analysis: ana.cpp
1. emulation: emu.cpp
2. conversion to text: out.cpp


The kernel calls the IDP module to perform these steps. At first, the kernel 
always calls the analysis. The analyzer must decode the instruction and fill 
the insn_t instance that it receives through its callback. It must not change 
anything in the database.

The second step, the emulation, is called for each instruction. This step must 
make necessary changes to the database, plan analysis of subsequent instructions, 
track register values, memory contents, etc. Please keep in mind that the kernel 
may call the emulation step for any address in the program - there is no ordering 
of addresses. Usually, the emulation is called for consecutive addresses but 
this is not guaranteed.

The last step, conversion to text, is called each time an instruction is 
displayed on the screen. The kernel will always call the analysis step before 
calling the text conversion step. The emulation and the text conversion steps 
should use the information stored in the insn_t instance they receive. They 
should not access the bytes of the instruction and decode it again - this 
should only be done in the analysis step.

.. tip:: 
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies 
   common tasks and provides better type hints, while remaining fully compatible 
   with IDAPython for advanced use cases.
   
   For instruction operations, see :mod:`ida_domain.instructions`."""

def decode_preceding_insn(out: insn_t, ea: ida_idaapi.ea_t) -> Tuple[ida_idaapi.ea_t, bool]:
    """
    Decodes the preceding instruction.

    :param out: instruction storage
    :param ea: current ea
    :returns: tuple(preceeding_ea or BADADDR, farref = Boolean)
    """
    pass

def construct_macro(*args):
    """
    See ua.hpp's construct_macro().

    This function has the following signatures

        1. construct_macro(insn: insn_t, enable: bool, build_macro: callable) -> bool
        2. construct_macro(constuctor: macro_constructor_t, insn: insn_t, enable: bool) -> bool

    :param insn: the instruction to build the macro for
    :param enable: enable macro generation
    :param build_macro: a callable with 2 arguments: an insn_t, and
                        whether it is ok to consider the next instruction
                        for the macro
    :param constructor: a macro_constructor_t implementation
    :returns: success
    """
    pass
