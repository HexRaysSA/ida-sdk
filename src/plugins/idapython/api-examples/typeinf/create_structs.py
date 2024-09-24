"""
summary: Programatically create structures and/or unions.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
    * Create a structure using the "parsing" method.
    * Create a structure by building it member by members. For this we
    first create a udt (user data type) object. We, then, populate it with
    udms (user data type members). Finally we actually store it in the local
    types via a call to set_named_type.
    * Create a union by building it member by member. The main difference with
    the previous step is that we have to set is_union to true.
"""
import ida_typeinf

# Create a struct with parsing.
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

# Create a struct member by member.
if tif.get_named_type(None, 'pcaprec_hdr_s'):
    ida_typeinf.del_named_type(None, 'pcaprec_hdr_s', ida_typeinf.NTF_TYPE)
field_map = {'ts_sec': ida_typeinf.BTF_UINT32, 
             'ts_usec': ida_typeinf.BTF_UINT32,
             'incl_len': ida_typeinf.BTF_UINT32,
             'orig_len': ida_typeinf.BTF_UINT32}
udt = ida_typeinf.udt_type_data_t()
udm = ida_typeinf.udm_t()
for field_name in field_map:
    udm.name = field_name
    udm.type = ida_typeinf.tinfo_t(field_map[field_name])
    udt.push_back(udm)
if tif.create_udt(udt):
    tif.set_named_type(None, 'pcaprec_hdr_s')

# Create a union member by member.
if tif.get_named_type(None, 'my_union'):
    ida_typeinf.del_named_type(None, 'my_union', ida_typeinf.NTF_TYPE)
tif = ida_typeinf.tinfo_t()
udt = ida_typeinf.udt_type_data_t()
field_map = {'member1': ida_typeinf.BTF_INT32,
             'member2': ida_typeinf.BTF_CHAR,
             'member3': ida_typeinf.BTF_FLOAT}
udt.is_union = True
udm = ida_typeinf.udm_t()
for field_name in field_map:
    udm.name = field_name
    udm.type = ida_typeinf.tinfo_t(field_map[field_name])
    udt.push_back(udm)
tif.get_named_type(None, 'pcap_hdr_s')
if tif.create_ptr(tif):
    udm.name = 'header_ptr'
    udm.type = tif
    udt.push_back(udm)
    tif.clear()
    tif.create_udt(udt, ida_typeinf.BTF_UNION)
    tif.set_named_type(None, 'my_union')
