"""Functions that deal with offsets.

"Being an offset" is a characteristic of an operand. This means that operand or its part represent offset from some address in the program. This linear address is called "offset base". Some operands may have 2 offsets simultaneously. Generally, IDA doesn't handle this except for Motorola outer offsets. Thus there may be two offset values in an operand: simple offset and outer offset.
Outer offsets are handled by specifying special operand number: it should be ORed with OPND_OUTER value.
See bytes.hpp for further explanation of operand numbers. 
"""
