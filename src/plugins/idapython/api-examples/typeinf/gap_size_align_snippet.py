import ida_typeinf
import ida_range

# Get size of struct member + alignment
def get_member_size_align(struct_name, member_off):
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(None, struct_name):
        udm = ida_typeinf.udm_t()
        udm.offset = member_off * 8
        if not tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET) == -1:
            return udm.type.get_size(), udm.effalign
    return -1, -1

## Check if offset is part of a gap

def is_struct_gap(struc_name, offset):
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, struc_name):
        return False
    rs = ida_range.rangeset_t()
    tif.calc_gaps(rs)
    for i in range(rs.nranges()):
        r = rs.getrange(i)
        if r.start_ea <= offset < r.end_ea:
            return True

    print(struc_name, hex(offset))
    return False