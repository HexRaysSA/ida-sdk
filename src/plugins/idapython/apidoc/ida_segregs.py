"""Functions that deal with the segment registers.

If your processor doesn't use segment registers, then these functions are of no use for you. However, you should define two virtual segment registers - CS and DS (for code segment and data segment) and specify their internal numbers in the LPH structure (processor_t::reg_code_sreg and processor_t::reg_data_sreg). 
"""
