"""
summary: implement a custom calling convention

description:
  The Delphi `LStrCatN` variadic function is unusual in the sense
  that it is variadic, purges the bytes from the stack, and the
  number of bytes to purge is held in `EDX`.
  This example shows how to add support for such ad-hoc calling conventions.

  You can test this example with the IDB at `../idbs/delphi6_lstrcatn.i64`

keywords: types

level: intermediate
"""

import ida_ua
import ida_ida
import ida_idp
import ida_typeinf

EAX = 0
EDX = 2
REGARGS = [EAX, EDX]

class delphi_LStrCatN_cc(ida_typeinf.custom_callcnv_t):

    def __init__(self):
        ida_typeinf.custom_callcnv_t.__init__(self)

        self.name = "__lstrcatn"
        self.flags = ida_typeinf.CCI_VARARG | ida_typeinf.CCI_PURGE
        self.abibits = ida_ida.ABI_STACK_VARARGS

    # Check validity of the function protype
    def validate_func(self, fti):
        if not fti.is_vararg_cc():
            return "must be variadic function"
        # The number of stack arguments is passed in EDX.
        # However, to be generic, we allow any number of arguments. The last solid
        # argument will be assumed to hold the number of stack arguments.
        if len(fti) == 0:
            return "at least one solid argument is required"
        if not fti.back().type.is_integral() != 4:
            # it must hold the number of variadic stack arguments
            return "the last solid argument must be an integer"
        return True

    # Calculate the location of the return value
    def calc_retloc(self, fti):
        if not fti.rettype.is_void():
            # Just use the standard location for the return value
            fti2 = func_type_data_t()
            fti2.rettype = fti.rettype
            fti2.set_cc(ida_typeinf.CM_CC_FASTCALL)
            if not self.calc_retloc(fti2):
                return False
            fti.reloc = fti2.retloc
        return True

    # Calculate the argument locations
    def calc_arglocs(self, fti):
        # Use EAX, EDX, ECX for the first 3 arguments.
        # The rest is allocated on the stack
        i = 0
        off = 0
        for fa in fti:
            if i < 2: # only 2 registers are used
                fa.argloc.set_reg1(REGARGS[i])
            else:
                fa.argloc.set_stkoff(off)
                off += 4
            i += 1
        self.stkargs = off
        return self.calc_retloc(fti)

    def find_edx_value(self, call_ea, blk):
        # EDX contains the number of stack arguments. Find its value
        # in the current block
        # NOTE: currently this logic is disabled (see False below)
        # because the interface of find_def() is broken in IDAPython
        if False and blk is not None and idaapi.init_hexrays_plugin():
            edx = ida_hexrays.mop_t(ida_hexrays.reg2mreg(EDX), 4)
            i1 = blk.tail
            i2 = None
            mov = blk.find_def(edx, i1, i2, FD_BACKWARD)
            if mov is not None and mov.opcode == m_mov and mov.d == edx:
                n = mov.l.is_constant()
                if n:
                    return n
        # if we failed to use the decompiler, try to find the register value
        # on the assembler level
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, call_ea) <= 0:
            return None
        return ida_idp.ph_find_reg_value(insn, EDX)

    def find_varargs(self, fti, call_ea, blk):
        nvargs = self.find_edx_value(call_ea, blk)
        if nvargs is None:
            return 0 # failed to find the EDX value
        if nvargs >= 128:
            return 0 # do not accept insane values

        # append the found varargs to the function prototype
        fa = ida_typeinf.funcarg_t()
        fa.type = ida_typeinf.tinfo_t().get_stock(ida_typeinf.STI_PCHAR) # char *
        for i in range(nvargs):
            fti.push_back(fa)
        if not self.calc_arglocs(fti):
            return 0
        return fti.size()

    # Calculate the variadic argument locations
    # Use the same logic because there are no hidden regargs or stkargs
    def calc_varglocs(self, fti, regs, stkargs, nfixed):
        return self.calc_arglocs(fti)

    # What registers are usually used by the calling convention?
    # This information is used by the decompiler for deriving and checking
    # the calling convention.
    def get_cc_regs(self, callregs):
        callregs.nregs = len(REGARGS)
        callregs.gpregs.push_back(REGARGS[0])
        callregs.gpregs.push_back(REGARGS[1])
        return True

    # Get information about the stack argmument area. Since the stack arguments
    # are located without any shifts, we do not need to do anything. In fact,
    # there was no need to implement this callback.
    def get_stkarg_area_info(self, stkarg_area_info):
        return True

    # Return number of purged bytes. We could use call_ea to find the value of
    # EDX and return the number of purged bytes. However, we just return 0
    # for now because the IDA kernel is not ready to use this information.
    # Also, it always passed call_ea as BADADDR currently.
    def calc_purged_bytes(self, fti, call_ea):
        return 0

    # The CM_CC_FASTCALL convention seems to be the closest to how
    # modern compilers decorate names
    def decorate_name(self, name, should_decorate, cc, ftype):
        out = ida_typeinf.gen_decorate_name(name, should_decorate, \
                              ida_typeinf.CM_CC_FASTCALL, ftype)
        return out

    # We do not need to lower the function type in a special way
    #def lower_func_type(self, fti):
    #    return 0

ccid = ida_typeinf.register_custom_callcnv(delphi_LStrCatN_cc())
if ccid != ida_typeinf.CM_CC_INVALID:
    print("Custom calling convention installed (with ID 0x%x)" % ccid)
else:
    raise Exception("Failed registering calling convention")
