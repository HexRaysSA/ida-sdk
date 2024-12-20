"""
summary: mark a register "spoiled" by a function

description:
    The goal of this script is to demonstrate some usage of the type API.
    At least two possibilies are offered in order to indicate that a function
    spoils registers (excluding the "normal" ones):
    * by parsing a declaration (we assume that the func object has already been created):
        func_tfinfo = ida_typeinf.tinfo_t()
        func_tinfo.parse('int _spoils<rsi> main();')
        ida_typeinf.apply_tinfo(func.start_ea, func_tinfo, ida_typeinf.TINFO_DEFINITE)
    * by editing the tinfo_t object spoiled registers vector and flags. This script uses
    this method.

level: beginner
"""

import ida_funcs
import ida_typeinf
import ida_idp
import ida_kernwin
import ida_nalt


func = ida_funcs.get_func(ida_kernwin.get_screen_ea())
func_type = ida_typeinf.tinfo_t()
ida_nalt.get_tinfo(func_type, func.start_ea)
func_details = ida_typeinf.func_type_data_t()
func_type.get_func_details(func_details)

regs = ["rsi"]
for reg in regs:
    reg_info = ida_idp.reg_info_t()
    ida_idp.parse_reg_name(reg_info, reg)
    func_details.spoiled.push_back(reg_info)
func_details.flags |= ida_typeinf.FTI_SPOILED
func_type.create_func(func_details)
ida_typeinf.apply_tinfo(func.start_ea, func_type, ida_typeinf.TINFO_DEFINITE)
