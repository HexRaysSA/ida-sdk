import ida_bytes
import ida_pro
import ida_ua
import ida_typeinf
import ida_nalt
import ida_netnode

"""
# Poor man iterator
class tid_array_iter():
    def __init__(self, path, count):
        self.path = path
        self.count = count
    
    def __iter__(self):
        self.curr = 0
        return self
    
    def __next__(self):
        if self.curr >= self.count:
            raise StopIteration
        else:
            idx = self.curr
            self.curr += 1
            return self.path[idx] """
        

def get_member_fullname(id):
    return ida_typeinf.get_tid_name(id)
    
def get_struct_accesses(ea: int, opnum: int) -> list[str]:
    flags = ida_bytes.get_full_flags(ea)

    insn = ida_ua.insn_t()
    ins_sz = ida_ua.decode_insn(insn, ea)
    if ins_sz == 0:
        # could not disassemble
        return []

    num_ops = 0
    while insn.ops[num_ops].type != ida_ua.o_void:
        num_ops += 1

    if opnum > num_ops:
        # wanted operand index larger than number of available operands
        return []

    op = insn.ops[opnum]

    if op.type == ida_ua.o_imm:
        value = op.value
    else:
        value = op.addr

    if not ida_bytes.is_stroff(flags, opnum):
        # requested operand not a structure
        return []

    delta = ida_pro.sval_pointer()
    path = ida_pro.tid_array(ida_nalt.MAXSTRUCPATH)

    count = ida_bytes.get_stroff_path(path.cast(), delta.cast(), insn.ea, opnum)

    delta = ida_pro.sval_pointer()
    path = ida_pro.tid_array(count)

    count = ida_bytes.get_stroff_path(path.cast(), delta.cast(), insn.ea, opnum)
    delta = delta.value()

    # Bonus: This segfaults
    #tids = [p for p in path]
    #path_iter = tid_array_iter(path, count)
    #tids = [ p for p in path_iter ]

    out = []
    for s in range(count):
        tid = path[s]
        tif = ida_typeinf.tinfo_t()
        tif.get_type_by_tid(tid)
        sz = tif.get_size()
        base_name = tif.get_type_name()

        if delta + value == sz:
            out.append(f"size {base_name}")
        else:
            for m in range(tif.get_udt_nmembers()):
                mem = ida_typeinf.udm_t()
                mem.offset = m
                tif.find_udm(mem, ida_typeinf.STRMEM_INDEX)
                off = mem.offset // 8 # udm.offset is in bits
                size = mem.size // 8 # udm.size is in bits
                if value >= off - delta and value < off - delta + size:
                    name = get_member_fullname(tif.get_udm_tid(m))
                    diff = value - (off - delta)
                    if diff > 0:
                        out.append(f"{name}+{diff}")
                    else:
                        out.append(f"{name}")


    return out
    