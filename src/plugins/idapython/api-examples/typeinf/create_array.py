"""
summary: Programatically create an array.

description:
    This script goal is to demonstrate some usage of the type API. 
    In this script, we create an array using both versions of 
    create_array tinfo_t method.
"""

import ida_typeinf

"""
Delete the types if they already exist.
"""
tif = ida_typeinf.tinfo_t()
if tif.get_named_type(None, 'my_int_array1'):
    ida_typeinf.del_named_type(None, 'my_int_array1', ida_typeinf.NTF_TYPE)

tif = ida_typeinf.tinfo_t()
if tif.get_named_type(None, 'my_int_array2'):
    ida_typeinf.del_named_type(None, 'my_int_array2', ida_typeinf.NTF_TYPE)

"""
First method:
* Create the type info object of the array element.
* Create an array of 5 integers (base index set to zero)
"""
tif = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
if tif.create_array(tif, 5, 0):
    type = tif._print()
    print(f'{type}')
    tif.set_named_type(None, 'my_int_array1')

"""
Second method:
* Create an array type data object representing an array
  of 5 integers with base index 0.
* Create the array using the just constructed object.
"""
atd = ida_typeinf.array_type_data_t()
atd.base = 0
atd.nelems = 5
atd.elem_type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT)
tif = ida_typeinf.tinfo_t()
if tif.create_array(atd):
    type = tif._print()
    print(f'{type}')
    tif.set_named_type(None, 'my_int_array2')
