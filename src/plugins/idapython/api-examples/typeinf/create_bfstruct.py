"""
summary: Programatically create a bitfield structure.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
     * Create a bitfield structure. In the present case the bitfield is an int32
    made of three 'members' spanning it entirely: 
        bit0->bit19: bf1
        bit20->bit25: bf2
        bit26->bit31: bf3
     * For each member create a repeatable comment.
"""
import ida_typeinf

# Create a bitfield structure.
tif = ida_typeinf.tinfo_t()
if tif.get_named_type(None, 'bfstruct'):
    ida_typeinf.del_named_type(None, 'bfstruct', ida_typeinf.NTF_TYPE)

udt = ida_typeinf.udt_type_data_t()
idx = 0
for name, offset, size, bitfield_info in [
    ("bf1", 0, 20, (4, 20)),
    ("bf2", 20, 6, (4, 6)),
    ("bf3", 26, 6, (4, 6))
]:
    udm = ida_typeinf.udm_t()
    udm.name = name
    bftif = ida_typeinf.tinfo_t()
    bf_bucket_size, bf_nbits = bitfield_info
    bftif.create_bitfield(bf_bucket_size, bf_nbits)
    udm.type = bftif
    udm.offset = offset
    udm.size = size
    udm.cmt = f'Bitfield member {idx}'
    udt.push_back(udm)
if tif.create_udt(udt):
    tif.set_named_type(None, 'bfstruct')