
import sys

import idaapi
import ida_loader
import ida_typeinf
import idc
import ida_funcs
import ida_ida
import ida_auto

import lzma
import ctypes
from ctypes import Structure, c_uint32, c_char, sizeof
import struct
from io import BytesIO

# -----------------------------------------------------------------------
class Header(Structure):
    _fields_ = [
        ("magic", c_uint32),
        ("dsize", c_uint32),
        ("name", c_char * 32),
        ("maddr", c_uint32),
        ("mode", c_uint32),
        ("ext_magic", c_uint32),
        ("hdr_size", c_uint32),
        ("hdr_version", c_uint32),
        ("img_type", c_uint32),
        ("img_list_end", c_uint32),
        ("align_size", c_uint32),
        ("dsize_extend", c_uint32),
        ("maddr_extend", c_uint32),
    ]

    def __repr__(self):
        return "\n".join([f"{field_name, getattr(self, field_name)}" for field_name, _ in self._fields_])

def read_header(li) -> Header:
    header_data = li.read(sizeof(Header))
    if len(header_data) != sizeof(Header):
        return None
    header = Header.from_buffer_copy(header_data)
    if header.magic != 0x58881688 or header.ext_magic != 0x58891689:
        return None
    if header.hdr_size < sizeof(Header):
        return None
    reserved_size = header.hdr_size - sizeof(Header)
    if len(li.read(reserved_size)) != reserved_size:
        return None
    return header

def read_section(li):
    header = read_header(li)
    if header == None:
        return None
    data = li.read(header.dsize)
    li.read((header.align_size - header.dsize) % header.align_size)
    return (header, data)

# -----------------------------------------------------------------------
def map_section(offset: int, data: bytes, name: str, clas: str, file_pos: int):
    segment = idaapi.segment_t()
    segment.start_ea = offset
    segment.end_ea   = offset + len(data)
    segment.sel      = idaapi.setup_selector(0)
    segment.perm     = 0b111
    segment.bitness  = 1
    segment.align    = idaapi.saAbs
    segment.comb     = idaapi.scPub
    idaapi.add_segm_ex(segment, name, clas, idaapi.ADDSEG_NOSREG|idaapi.ADDSEG_OR_DIE)
    ida_loader.mem2base(data, offset, file_pos)

# -----------------------------------------------------------------------
def read_c_string(data: BytesIO) -> str:
    buffer = bytes()
    while True:
       c = data.read(1)
       if c == b'\0': break
       buffer += c
    return buffer.decode()

def read_uint32(data: BytesIO) -> int:
    return int.from_bytes(data.read(4), "little")

# -----------------------------------------------------------------------
def parse_dbginfo(data: bytes):
    data = BytesIO(lzma.decompress(data))
    data.read(0x1c)
    target = read_c_string(data)
    print(f"target : {target}")
    platform = read_c_string(data)
    print(f"platform : {platform}")
    version = read_c_string(data)
    print(f"version : {version}")
    build_time = read_c_string(data)
    print(f"build_time : {build_time}")

    read_uint32(data)
    file_symbols_size = read_uint32(data)
    while data.tell() < file_symbols_size:
        try:
            name = read_c_string(data)
        except UnicodeDecodeError:
            continue
        finally:
            start = read_uint32(data)
            end = read_uint32(data)
        idaapi.set_name(start, name, idaapi.SN_NOCHECK|idaapi.SN_NOWARN|idaapi.SN_NODUMMY)
        ida_auto.auto_make_proc(start)

# -----------------------------------------------------------------------
def accept_file(li, filename):
    li.seek(0)
    if read_header(li) == None:
        return None
    return {"format": "Mediatek Firmware Image",
            "processor":"mipsl",
            "options": ida_ida.f_MD1IMG}

# -----------------------------------------------------------------------
def load_file(li, neflags, format):
    li.seek(0)
    file_size = li.size()

    idaapi.set_processor_type("mipsl", idaapi.SETPROC_LOADER)
    idaapi.inf_set_app_bitness(32)

    offset = 0
    while li.tell() < file_size:
        section_start_in_file = li.tell()
        result = read_section(li)
        if result == None:
            break
        header, data = result
        section_start_in_file += header.hdr_size

        if header.name == b"md1rom":
            # Set the P32 abi if we are using nanomips
            # This checks if the first instruction is a load immediate
            if data[0:2] == b"\xc0\x60":
                ida_typeinf.set_abi_name("p32")
            map_section(0x90000000, data, header.name.decode(), "CODE", section_start_in_file)
        elif header.name == b"md1_dbginfo":
            print("parsing md1_dbginfo")
            parse_dbginfo(data)
        map_section(offset, data, header.name.decode(), "DATA", section_start_in_file)

        offset += header.dsize
        offset += (header.align_size - header.dsize) % header.align_size
    return ida_ida.f_MD1IMG

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    idc.warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0
