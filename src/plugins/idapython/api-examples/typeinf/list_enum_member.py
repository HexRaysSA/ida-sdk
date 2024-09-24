import ida_kernwin
import ida_typeinf

name = ida_kernwin.ask_str('Dummy enum', 0, 'Enter an enum name:')
if name:
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name, ida_typeinf.BTF_ENUM, True, False):
        print(f"'{name}' is not an enum")
    elif tif.is_typedef():
        print(f"'{name}' is not a (non typedefed) enum.")
    else:
        edt = ida_typeinf.enum_type_data_t()
        if tif.get_enum_details(edt):
            idx = 0
            bitfield = ''
            if edt.is_bf():
                bitfield = '(bitfield)'
            print(f"Listing the '{name}' {bitfield} enum {edt.size()} field names:")
            for edm in edt:
                print(f'Field {idx}: {edm.name} = {edm.value}')
                idx += 1
        else:
            print(f"Unable to get udt details for enum '{name}'")
