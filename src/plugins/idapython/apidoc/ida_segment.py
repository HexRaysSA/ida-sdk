"""Functions that deal with segments.

IDA requires that all program addresses belong to segments (each address must
belong to exactly one segment). The situation when an address doesn't belong to
any segment is allowed as a temporary situation only when the user changes
program segmentation. Bytes outside a segment can't be converted to instructions,
have names, comments, etc. Each segment has its start address, ending address
and represents a contiguous range of addresses. There might be unused holes
between segments.

Each segment has its unique segment selector. This selector is used to
distinguish the segment from other segments. For 16-bit programs the selector
is equal to the segment base paragraph. For 32-bit programs there is special
array to translate the selectors to the segment base paragraphs. A selector is
a 32/64 bit value.

The segment base paragraph determines the offsets in the segment. If the start
address of the segment == (base << 4) then the first offset in the segment will
be 0. The start address should be higher or equal to (base << 4). We will call
the offsets in the segment 'virtual addresses'. So, the virtual address of the
first byte of the segment is (start address of segment - segment base linear
address).

For IBM PC, the virtual address corresponds to the offset part of the address.
For other processors (Z80, for example), virtual addresses correspond to Z80
addresses and linear addresses are used only internally. For MS Windows programs
the segment base paragraph is 0 and therefore the segment virtual addresses are
equal to linear addresses.

.. tip::
   The `IDA Domain API <https://ida-domain.docs.hex-rays.com/>`_ simplifies
   common tasks and provides better type hints, while remaining fully compatible
   with IDAPython for advanced use cases.

   For segment operations, see :mod:`ida_domain.segments`."""

def get_defsr(s, reg):
    """
    Deprecated, use instead:
        value = s.defsr[reg]
    """
    pass


def set_defsr(s, reg, value):
    """
    Deprecated, use instead:
        s.defsr[reg] = value
    """
    pass
