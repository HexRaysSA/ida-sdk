"""There are 2 representations of the binary code in the decompiler:

Hex-Rays Decompiler project Copyright (c) 1990-2025 Hex-Rays ALL RIGHTS RESERVED.

* microcode: processor instructions are translated into it and then the decompiler optimizes and transforms it
* ctree: ctree is built from the optimized microcode and represents AST-like tree with C statements and expressions. It can be printed as C code.


Microcode is represented by the following classes:
* mba_t keeps general info about the decompiled code and array of basic blocks. usually mba_t is named 'mba'
* mblock_t a basic block. includes list of instructions
* minsn_t an instruction. contains 3 operands: left, right, and destination
* mop_t an operand. depending on its type may hold various info like a number, register, stack variable, etc.
* mlist_t list of memory or register locations; can hold vast areas of memory and multiple registers. this class is used very extensively in the decompiler. it may represent list of locations accessed by an instruction or even an entire basic block. it is also used as argument of many functions. for example, there is a function that searches for an instruction that refers to a mlist_t.


See [https://hex-rays.com/blog/microcode-in-pictures](https://hex-rays.com/blog/microcode-in-pictures) for a few pictures.
Ctree is represented by:
* cfunc_t keeps general info about the decompiled code, including a pointer to mba_t. deleting cfunc_t will delete mba_t too (however, decompiler returns cfuncptr_t, which is a reference counting object and deletes the underlying function as soon as all references to it go out of scope). cfunc_t has 'body', which represents the decompiled function body as cinsn_t.
* cinsn_t a C statement. can be a compound statement or any other legal C statements (like if, for, while, return, expression-statement, etc). depending on the statement type has pointers to additional info. for example, the 'if' statement has poiner to cif_t, which holds the 'if' condition, 'then' branch, and optionally 'else' branch. Please note that despite of the name cinsn_t we say "statements", not "instructions". For us instructions are part of microcode, not ctree.
* cexpr_t a C expression. is used as part of a C statement, when necessary. cexpr_t has 'type' field, which keeps the expression type.
* citem_t a base class for cinsn_t and cexpr_t, holds common info like the address, label, and opcode.
* cnumber_t a constant 64-bit number. in addition to its value also holds information how to represent it: decimal, hex, or as a symbolic constant (enum member). please note that numbers are represented by another class (mnumber_t) in microcode.


See [https://hex-rays.com/blog/hex-rays-decompiler-primer](https://hex-rays.com/blog/hex-rays-decompiler-primer) for more pictures and more details.
Both microcode and ctree use the following class:
* lvar_t a local variable. may represent a stack or register variable. a variable has a name, type, location, etc. the list of variables is stored in mba->vars.
* lvar_locator_t holds a variable location (vdloc_t) and its definition address.
* vdloc_t describes a variable location, like a register number, a stack offset, or, in complex cases, can be a mix of register and stack locations. very similar to argloc_t, which is used in ida. the differences between argloc_t and vdloc_t are:
* vdloc_t never uses ARGLOC_REG2
* vdloc_t uses micro register numbers instead of processor register numbers
* the stack offsets are never negative in vdloc_t, while in argloc_t there can be negative offsets




The above are the most important classes in this header file. There are many auxiliary classes, please see their definitions in the header file.
See also the description of Virtual Machine used by Microcode. 
"""

class cfunc_t(object):
    def find_item_coords(self, *args):
        """
        This method has the following signatures:

            1. find_item_coords(item: citem_t) -> Tuple[int, int]
            2. find_item_coords(item: citem_t, x: int_pointer, y: int_pointer) -> bool

        NOTE: The second form is retained for backward-compatibility,
        but we strongly recommend using the first.

        :param item: The item to find coordinates for in the pseudocode listing
        """
        pass

class cfuncptr_t(object):
    def find_item_coords(self, *args):
        """
        This method has the following signatures:

            1. find_item_coords(item: citem_t) -> Tuple[int, int]
            2. find_item_coords(item: citem_t, x: int_pointer, y: int_pointer) -> bool

        NOTE: The second form is retained for backward-compatibility,
        but we strongly recommend using the first.

        :param item: The item to find coordinates for in the pseudocode listing
        """
        pass
