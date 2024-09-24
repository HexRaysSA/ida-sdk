"""
summary: Programatically create a bitmask enum.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we:
    * Create a bitmask enumeration member by member.
    * Flags the enumeration as a bitmask one.
"""
import ida_typeinf

tif = ida_typeinf.tinfo_t()
edt = ida_typeinf.enum_type_data_t()
edm = ida_typeinf.edm_t()
edm.name = 'field1'
edm.value = 1
edt.push_back(edm)
edm.name = 'field2'
edm.value = 2
edt.push_back(edm)
edm.name = 'field3'
edm.value = 4
edt.push_back(edm)
if tif.create_enum(edt):
    tif.set_enum_is_bitmask(ida_typeinf.tinfo_t.ENUMBM_ON)
    tif.set_named_type(None, 'bmenum')
