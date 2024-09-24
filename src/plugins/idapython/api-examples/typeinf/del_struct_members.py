import ida_typeinf

def del_struct_members(sid, offset1, offset2):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(sid) and tif.is_udt():
        udm = ida_typeinf.udm_t()
        udm.offset = offset1 * 8
        idx1 = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
        udm = ida_typeinf.udm_t()
        udm.offset = offset2 * 8
        idx2 = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
        return tif.del_udms(idx1, idx2)
    
def get_best_fit_member(sid, offset):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(sid) and tif.is_udt():
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            return udt.get_best_fit_member(offset)

def get_innermost_member(sid, offset):
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(sid) and tif.is_udt():
        (mtif, idx, _) = tif.get_innermost_udm(offset * 8)
        udt = ida_typeinf.udt_type_data_t()
        if not idx == -1:
            if tif.get_udt_details(udt):
                return mtif, udt[idx]
    return None
    
struct_str = """struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
};"""
tif = ida_typeinf.tinfo_t()
if tif.get_named_type(None, 'pcap_hdr_s'):
    ida_typeinf.del_named_type(None, 'pcap_hdr_s', ida_typeinf.NTF_TYPE)
ida_typeinf.idc_parse_types(struct_str, 0)
if not tif.get_named_type(None, 'pcap_hdr_s'):
    print('Unable to retrieve pcap_hdr_s structure')
        