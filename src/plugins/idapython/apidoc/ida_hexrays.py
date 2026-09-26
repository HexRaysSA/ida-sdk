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

class mblock_t(object):
    def find_access(self, op: 'mop_t', parent: 'minsn_t', mend: 'minsn_t', fdflags: int) -> 'Tuple[minsn_t, minsn_t]':
        """Find the instruction that accesses the specified operand.
        This function searches inside one block.

        :param op: operand to search for
        :param parent: top-level instruction denoting the beginning
            of the search range (must not be None).
            parent and mend must belong to the same block.
        :param mend: end instruction of the range (must be a top level insn).
            mend is excluded from the range. None means search to the block
            boundary.
        :param fdflags: combination of FD_ bits
        :returns: (found, parent) tuple.
            found: the instruction that accesses the operand. This instruction
            may be a sub-instruction. None means 'not found'.
            parent: the top-level instruction containing 'found'."""
        pass
    def find_def(self, op: 'mop_t', p_i1: 'minsn_t', i2: 'minsn_t', fdflags: int) -> 'Tuple[minsn_t, minsn_t]':
        """Find the instruction that defines the specified operand.
        Convenience wrapper around find_access() with FD_DEF.

        :param op: operand to search for
        :param p_i1: top-level instruction denoting the beginning
            of the search range (must not be None).
            p_i1 and i2 must belong to the same block.
        :param i2: end instruction of the range (excluded). None means
            search to the block boundary.
        :param fdflags: combination of FD_ bits (see find_access)
        :returns: (found, parent) tuple. See find_access()."""
        pass
    def find_use(self, op: 'mop_t', p_i1: 'minsn_t', i2: 'minsn_t', fdflags: int) -> 'Tuple[minsn_t, minsn_t]':
        """Find the instruction that uses the specified operand.
        Convenience wrapper around find_access() with FD_USE.

        :param op: operand to search for
        :param p_i1: top-level instruction denoting the beginning
            of the search range (must not be None).
            p_i1 and i2 must belong to the same block.
        :param i2: end instruction of the range (excluded). None means
            search to the block boundary.
        :param fdflags: combination of FD_ bits (see find_access)
        :returns: (found, parent) tuple. See find_access()."""
        pass

class codegen_t(object):
    def store_operand(self, n: int, mop: 'mop_t', flags: int=0) -> 'Tuple[bool, minsn_t]':
        """Generate microcode to store an operand.
        In case of success an arbitrary number of instructions can be
        generated (and even no instruction if the source and target are the same).

        :param n: number of target insn operand
        :param mop: operand to be stored
        :param flags: reserved for future use
        :returns: (success, outins) tuple.
            outins: the last generated instruction
            (None if no instruction was generated)."""
        pass

class minsn_t(object):
    def serialize(self) -> 'Tuple[int, bytes]':
        """Serialize an instruction

        :returns: tuple(serialization format, serialized bytes)"""
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

def render_class(cls: 'class_t', flags: int=0) -> Tuple[bool, List[str]]:
    """
    Render one class exactly as the class view shows it: header lines,
    fields, methods with decompiled bodies, nested classes (recursively,
    indented as in the view), closing brace. Only cls.name is required;
    cls.ea disambiguates duplicate names. A CLF_HIDDEN class (one the view
    does not show) is refused.

    :param cls: the class to render (at least its name)
    :param flags: combination of RCF_... bits
    :returns: (ok, lines) tuple.
        ok: False if the class is unknown or the current decompiler has no
        class model.
        lines: the rendered text, one string per line, no indentation.
    """
    pass

def render_member(ea: ida_idaapi.ea_t, flags: int=0) -> Tuple[bool, List[str]]:
    """
    Render one member as the class view shows it: attribute lines, then for
    a field its declaration (with initializer), for a method its declaration
    and decompiled body followed by the decompiler warnings. A method that
    fails to decompile renders the same "#error"-style line the class view
    shows. A body-opening enum constant (e.g. Java's "GREEN { ... }") renders
    as its name and the opening brace; its body's members are separate class
    members.

    :param ea: the member's IDB entity, as reported in class_member_t.ea:
        a function or import entry, or a static field's global
    :param flags: combination of RCF_... bits
    :returns: (ok, lines) tuple.
        ok: False if ea is not a class member or the current decompiler has
        no class model.
        lines: the rendered text, one string per line, no indentation.
    """
    pass
