from __future__ import print_function
#---------------------------------------------------------------------
# IDAPython - Python plugin for Interactive Disassembler
#
# (c) The IDAPython Team <https://github.com/HexRaysSA/ida-sdk/issues>
#
# All rights reserved.
#
# For detailed copyright information see the file COPYING in
# the root of the distribution archive.
#---------------------------------------------------------------------
#
# dex.py - module to access DEX-file related information
#
#---------------------------------------------------------------------
# pylint: disable=C0103, C0111, C0301, C0326, W0511, R0903
import sys
import ctypes
import idaapi
import ida_idaapi
import ida_bytes
import ida_segment
import idc

uint8  = ctypes.c_ubyte
char   = ctypes.c_char
uint32 = ctypes.c_uint
uint64 = ctypes.c_uint64
uint16 = ctypes.c_ushort
ushort = uint16
# __EA64__ is set if IDA is running in 64-bit mode
__EA64__ = ida_idaapi.BADADDR == 0xFFFFFFFFFFFFFFFF
ea_t = uint64 if __EA64__ else uint32

# Dalvik indices are stored as uint32
def to_uint32(v):
    return int.from_bytes(v, byteorder='little') & 0xFFFFFFFF

# parse a ctypes struct from byte data in str_ at 'off'
def get_struct(str_, off, struct):
    s = struct()
    slen = ctypes.sizeof(s)
    bytebuf = str_[off:off+slen]
    fit = min(len(bytebuf), slen)
    if fit < slen:
        raise Exception("can't read struct: %d bytes available but %d required" % (fit, slen))
    ctypes.memmove(ctypes.addressof(s), bytebuf, fit)
    return s

_byte = ord if sys.version_info.major < 3 else lambda t: t

# unpack base address
def unpack_db(buf, off):
    x = 0
    if off < len(buf):
        x = _byte(buf[off])
        off += 1
    return (x, off)

def get_dw(buf, off):
    x = 0
    if off < len(buf):
        x = _byte(buf[off]) << 8
        off += 1
    if off < len(buf):
        x |= _byte(buf[off])
        off += 1
    return (x, off)

def unpack_dw(buf, off):
    (x, off) = unpack_db(buf, off)
    if (x & 0x80) == 0x80:
        if (x & 0xC0) == 0xC0:
            (x, off) = get_dw(buf, off)
        else:
            if off < len(buf):
                x = ((x & ~0x80) << 8) | _byte(buf[off])
                off += 1
    return (x, off)

def unpack_dd(buf, off):
    (x, off) = unpack_db(buf, off)
    if (x & 0x80) == 0x80:
        if (x & 0xC0) == 0xC0:
            if (x & 0xE0) == 0xE0:
                (xh, off) = get_dw(buf, off)
            else:
                xh = 0
                if off < len(buf):
                    xh = ((x & ~0xC0) << 8) | _byte(buf[off])
                    off += 1
            (xl, off) = get_dw(buf, off)
            x = (xh << 16) | xl
        else:
            if off < len(buf):
                x = ((x & ~0x80) << 8) | _byte(buf[off])
                off += 1
    return (x, off)

def unpack_dq(buf, off):
    (xl, off) = unpack_dd(buf, off)
    (xh, off) = unpack_dd(buf, off)
    x = (xh << 32) | xl
    if x > 0x8000000000000000:
        x = x - 0x10000000000000000
    return (x, off)

def unpack_ea(buf, off):
    if __EA64__:
        return unpack_dq(buf, off)
    else:
        return unpack_dd(buf, off)

def unpack_eavec(buf, base_ea):
    (n, off) = unpack_dw(buf, 0)
    ba = []
    old_ea = base_ea
    for i in range(0, n):
        (ea, off) = unpack_ea(buf, off)
        old_ea += ea
        ba.append(old_ea)
    return ba

#---------------------------------------------------------------------------
# The raw dex_method_t dump DEXVAR_METHOD held before the record was packed.
# Databases written back then are still readable, so both forms are parsed.
#
class dex_method_v11(ctypes.LittleEndianStructure):
    _fields_ = [
        ("flags",          uint32),
        ("defaddr",          ea_t),
        ("cname",          uint32),
        ("id",             uint32),
        ("proto_ret",      uint32),
        ("proto_shorty",   uint32),
        ("nparams",        ushort),
        ("proto_params",uint32*32),
        ("access_flags",   uint32),
        ("startAddr",       ea_t),
        ("endAddr",         ea_t),
        ("reg_total",      ushort),
        ("reg_params",     ushort),
        ("reg_out",        ushort),
        ("catch_handler_data",       ea_t),
        ("impaddr",          ea_t),
        ("proto_idx",      ushort),
    ]

#---------------------------------------------------------------------------
# This structure is used both for imported methods and locally defined ones
#
class dex_method_t(object):
    # flags
    IS_LOCAL = 1
    HAS_CODE = 2
    IS_LINKED = 4
    NO_PROTO = 8
    # first byte of a packed record; a raw dump starts with the low byte of
    # 'flags', which the four flag bits keep below this
    PACK_V1 = 0x80
    # how many of a prototype's parameter types proto_params keeps
    MAX_PROTO_PARAMS = 32

    def __init__(self):
        self.defaddr = 0        # address of the DexMethodId record, in this
                                # method's own file
        self.impaddr = 0        # bodyless methods: the IMPORTS entry
        self.startAddr = 0      # function start and end address
        self.endAddr = 0        #
        self.catch_handler_data = 0     # offset to the method's catch handler data
        self.flags = 0
        self.cname = 0          # class type where this method is defined
        self.id = 0             # id of method; key to look up name
        self.proto_ret = 0      # name of return type
        self.proto_shorty = 0   # 'shorty' parameter descriptor name
        self.access_flags = 0   # access flags; only for local methods
        self.proto_params = [0] * dex_method_t.MAX_PROTO_PARAMS
        self.nparams = 0        # no of parameters to method. May be >32
        self.reg_total = 0      # registers total, parameters and out
        self.reg_params = 0     #
        self.reg_out = 0        #
        self.proto_idx = 0      # index into the file's proto_ids

    @staticmethod
    def unpack(buf):
        """parse a DEXVAR_METHOD record, in either of the two forms.
           returns None if buf is neither"""
        if not buf:
            return None
        m = dex_method_t()
        if _byte(buf[0]) != dex_method_t.PACK_V1:
            if len(buf) < ctypes.sizeof(dex_method_v11):
                return None
            v11 = get_struct(buf, 0, dex_method_v11)
            for name, _ in dex_method_v11._fields_:
                if name != "proto_params":
                    setattr(m, name, getattr(v11, name))
            m.proto_params = list(v11.proto_params)
            return m
        off = 1
        (m.defaddr, off) = unpack_ea(buf, off)
        (m.impaddr, off) = unpack_ea(buf, off)
        (m.startAddr, off) = unpack_ea(buf, off)
        (m.endAddr, off) = unpack_ea(buf, off)
        (m.catch_handler_data, off) = unpack_ea(buf, off)
        (m.flags, off) = unpack_dd(buf, off)
        (m.cname, off) = unpack_dd(buf, off)
        (m.id, off) = unpack_dd(buf, off)
        (m.proto_ret, off) = unpack_dd(buf, off)
        (m.proto_shorty, off) = unpack_dd(buf, off)
        (m.access_flags, off) = unpack_dd(buf, off)
        (m.nparams, off) = unpack_dw(buf, off)
        (m.reg_total, off) = unpack_dw(buf, off)
        (m.reg_params, off) = unpack_dw(buf, off)
        (m.reg_out, off) = unpack_dw(buf, off)
        (m.proto_idx, off) = unpack_dw(buf, off)
        for i in range(0, min(m.nparams, dex_method_t.MAX_PROTO_PARAMS)):
            (m.proto_params[i], off) = unpack_dd(buf, off)
        return m

    def is_local(self):
        return (self.flags & dex_method_t.IS_LOCAL) != 0

    def has_code(self):
        return (self.flags & dex_method_t.HAS_CODE) != 0

    def is_linked(self):
        """the body is declared elsewhere -- by a superclass, by another file
           of the multidex set, or both -- and startAddr names it there"""
        return (self.flags & dex_method_t.IS_LINKED) != 0

    def owns_body(self):
        """does this record own the body it names, rather than point at one
           declared elsewhere? enumerating the bodies of a file means keeping
           only these: a linked reference carries its definition's address,
           so counting it too would list the same function once per file
           that refers to it"""
        return self.has_code() and not self.is_linked()

    def has_proto(self):
        """do nparams and proto_params describe the prototype? when they do
           not, the shorty still gives the parameter count and the rough
           kinds; only the type ids are out of reach"""
        return (self.flags & dex_method_t.NO_PROTO) == 0

    def callable_ea(self):
        """the address that stands for this method: its code when we know
           it, else its IMPORTS entry"""
        return self.startAddr if self.has_code() else self.impaddr


"""
struct dex_field_t
{
  uint32 ctype, name, type;
  ea_t maddr;            // Address used for xrefs.
  uint32 access_flags;   // populated by the loader from class_data_item;
                         // for fields of external classes only ACC_STATIC
                         // is derived (from sget/sput uses).
  // appended for interface version 10; zero-padded in older records:
  ea_t saddr;            // static fields: typed data slot in SFIELDS
                         // (BADADDR/0 if none)
  uint32 flags;          // IS_LOCAL: declared by a class of this dex
  uint32 reserved;
};

"""
class dex_field_t(ctypes.LittleEndianStructure):
    # flags
    IS_LOCAL = 1
    _fields_ = [
        ("ctype",        uint32), #
        ("name",         uint32), #
        ("type",         uint32), #
        ("maddr",        ea_t),   # Address used for xrefs.
        ("access_flags", uint32), # see dex_access_flags
        ("saddr",        ea_t),   # static-field slot in SFIELDS, 0 if none
        ("flags",        uint32), # IS_LOCAL
        ("reserved",     uint32), #
    ]
    def is_local(self):
        return (self.flags & dex_field_t.IS_LOCAL) != 0

"""
struct longname_director_t
{
  char zero;
  netnode node;
};
"""
class longname_director_t(ctypes.LittleEndianStructure):
    # flags
    _pack_ = 1
    _fields_ = [
        ("zero",   uint8), #
        ("node",   ea_t), # netnode index with the actual string blob
    ]


class Dex(object):

    # meta-data
    HASHVAL_MAGIC      = "version"      # Interface version
    HASHVAL_OPTIMIZED  = "optimized"    # 1 for optimized dex files, 0 - for others
    HASHVAL_DEXVERSION = "dex_version"  # DEX File version
    META_BASEADDRS     = 1              # eavec_t blob at index 0
    META_XTRNADDRS     = 2              # eavec_t blob at index 0

    # ea-based indexes
    DEXCMN_STRING_ID  = ord('S')    # string ea => string_id
    DEXCMN_METHOD_ID  = ord('M')    # dex_method_t::func.start_ea => method_id
    DEXCMN_TRY_TYPES  = ord('E')    # ea (handler start) => list of type_id, handled types
    DEXCMN_TRY_IDS    = ord('Y')    # ea (handler start) => list of try_item_id
    DEXCMN_DEBINFO    = ord('D')    # line start ea => dex_lineinfo_t
    DEXCMN_DEBSTR     = ord('B')    # line start ea => human readable debug info string

    # var indexes
    DEXVAR_OLD_STRIDS = ord('S')    # string_id => ea (obsolete)
    DEXVAR_STRING_EAS = ord('s')    # string_id => ea (delta-encoded blob)
    DEXVAR_OLD_TYPIDS = ord('T')    # type_id => descriptor string_id (obsolete)
    DEXVAR_OLD_TYPSTR  = ord('U')    # type_id => type string (obsolete per-index)
    DEXVAR_OLD_TYPSTRO = ord('V')    # type_id => type string original (obsolete per-index)
    DEXVAR_TYPE_RENS   = ord('v')    # user-renamed type strings (blob)
    DEXVAR_METHOD     = ord('M')    # method_id => packed dex_method_t, supval
    DEXVAR_METH_STR   = ord('N')    # method_id => method name, char data
    DEXVAR_METH_STRO  = ord('O')    # method_id => method name fromdex file, char data
    DEXVAR_FIELD      = ord('F')    # field_id => struct dex_field_t
    DEXVAR_FIELD_NAME = ord('G')    # field_id => user-chosen field name
    DEXVAR_TRYLIST    = ord('Y')    # method_id => try_item

    # debug info representation
    DEBINFO_LINEINFO = 1        # Line start EA => dex_lineinfo_t

    #---------------------------------------------------------------------------
    @staticmethod
    def _load_string_eas(nn_var):
        """Load delta-encoded string EAs blob from netnode."""
        packed = nn_var.getblob(0, Dex.DEXVAR_STRING_EAS)
        if packed is None:
            return None
        off = 0
        (n, off) = unpack_dd(packed, off)
        eas = []
        prev = 0
        for _ in range(n):
            (delta, off) = unpack_ea(packed, off)
            prev += delta
            if __EA64__:
                prev &= 0xFFFFFFFFFFFFFFFF
            else:
                prev &= 0xFFFFFFFF
            eas.append(prev)
        return eas


    @staticmethod
    def _unpack_str(packed, off):
        """Unpack a null-terminated string (matches C++ pack_str/unpack_str)."""
        end = packed.index(0, off) if 0 in packed[off:] else len(packed)
        s = packed[off:end].decode('utf-8', errors='replace')
        return (s, end + 1)  # skip past the null terminator

    @staticmethod
    def _load_type_renames(nn_var):
        """Load user-renamed type strings blob from netnode."""
        packed = nn_var.getblob(0, Dex.DEXVAR_TYPE_RENS)
        if packed is None:
            return None
        off = 0
        (nrenames, off) = unpack_dd(packed, off)
        renames = {}
        for _ in range(nrenames):
            (tid, off) = unpack_dd(packed, off)
            (s, off) = Dex._unpack_str(packed, off)
            renames[tid] = s
        return renames

    #---------------------------------------------------------------------------
    def __init__(self):
        self.nn_meta = idaapi.netnode("$ dex_meta")
        self.nn_cmn = idaapi.netnode("$ dex_cmn")
        packed = self.nn_meta.getblob(0, Dex.META_BASEADDRS)
        self.baseaddrs = unpack_eavec(packed, 0)
        # start of each file's extern block; empty in a database whose
        # extern segments still sit inside the file images
        packed = self.nn_meta.getblob(0, Dex.META_XTRNADDRS)
        self.xtrnaddrs = unpack_eavec(packed, 0) if packed else []
        self.nn_vars = []
        self.string_eas = []
        self.type_renames = []
        self.nn_vars.append(idaapi.netnode("$ dex_var"))
        for i in range(2, len(self.baseaddrs) + 1):
            nn_var_name = "$ dex_var%d" % i
            self.nn_vars.append(idaapi.netnode(nn_var_name))
        for nn_var in self.nn_vars:
            self.string_eas.append(Dex._load_string_eas(nn_var))
            self.type_renames.append(Dex._load_type_renames(nn_var))

    #---------------------------------------------------------------------------
    def get_dexnum(self, from_ea):
        # the extern blocks come after every file image, in file order
        addrs = self.baseaddrs
        if self.xtrnaddrs and from_ea >= self.xtrnaddrs[0]:
            addrs = self.xtrnaddrs
        dexnum = 0
        for ba in addrs:
            if from_ea < ba:
                break
            dexnum += 1
        return dexnum

    #---------------------------------------------------------------------------
    def get_nn_var(self, from_ea):
        return self.nn_vars[self.get_dexnum(from_ea) - 1]

    #---------------------------------------------------------------------------
    ACCESS_FLAGS = {
        "public"        : 0x00000001,
        "private"       : 0x00000002,
        "protected"     : 0x00000004,
        "static"        : 0x00000008,
        "final"         : 0x00000010,
        "synchronized"  : 0x00000020,
        "volatile"      : 0x00000040,
        "bridge"        : 0x00000040,
        "transient"     : 0x00000080,
        "varargs"       : 0x00000080,
        "native"        : 0x00000100,
        "interface"     : 0x00000200,
        "abstract"      : 0x00000400,
        "strictfp"      : 0x00000800,
        "synthetic"     : 0x00001000,
        "annotation"    : 0x00002000,
        "enum"          : 0x00004000,
        "constructor"   : 0x00010000,
        "dsynchronized" : 0x00020000, }

    #---------------------------------------------------------------------------
    @staticmethod
    def access_string(flags):
        res = ""
        for access_bit in ("synchronized", "synthetic", "public",
                           "private", "protected", "interface",
                           "abstract", "strictfp", "final",
                           "native", "static"):
            if flags & Dex.ACCESS_FLAGS[access_bit] != 0:
                res += " " + access_bit
        return res[1:] if res else ""

    #---------------------------------------------------------------------------
    @staticmethod
    def as_string(s):
        return s.decode("UTF-8") if sys.version_info.major >= 3 else s

    #---------------------------------------------------------------------------
    def get_string_ea(self, from_ea, string_idx):
        idx = self.get_dexnum(from_ea) - 1
        if idx < len(self.string_eas) and self.string_eas[idx] is not None:
            eas = self.string_eas[idx]
            if string_idx < len(eas):
                return eas[string_idx]
            return ida_idaapi.BADADDR
        # fallback for old IDBs
        nn_var = self.get_nn_var(from_ea)
        return nn_var.eaget_idx(string_idx, Dex.DEXVAR_OLD_STRIDS)

    #---------------------------------------------------------------------------
    def get_string(self, from_ea, string_idx):
        addr = self.get_string_ea(from_ea, string_idx)
        if addr == ida_idaapi.BADADDR:
            return None
        length = ida_bytes.get_max_strlit_length(addr, idc.STRTYPE_C, ida_bytes.ALOPT_IGNHEADS|ida_bytes.ALOPT_IGNPRINT)
        raw = ida_bytes.get_strlit_contents(addr, length, idc.STRTYPE_C)
        return Dex.as_string(raw)

    def get_method_idx(self, ea):
        return to_uint32(self.nn_cmn.supval_ea(ea, Dex.DEXCMN_METHOD_ID))

    def get_method(self, from_ea, method_idx):
        nn_var = self.get_nn_var(from_ea)
        val = nn_var.supval(method_idx, Dex.DEXVAR_METHOD)
        method = dex_method_t.unpack(val)
        if method is None:
            print("bad data in DEXVAR_METHOD for index 0x%X" % method_idx)
        return method

    #---------------------------------------------------------------------------
    @staticmethod
    def get_string_by_index(node, idx, tag):
        if idx is None:
            return None
        val = node.supval(idx, tag)
        if val is None:
            return None
        # check for long line
        if len(val) == ctypes.sizeof(longname_director_t):
            longname_director = get_struct(val, 0, longname_director_t)
            if longname_director.zero == 0:
                nn = idaapi.netnode(longname_director.node)
                blob = nn.getblob(0, tag)
                # strip trailing zero if present (old IDBs)
                if blob and blob[-1:] == b'\x00':
                    blob = blob[:-1]
                return Dex.as_string(blob)
        if len(val) > 0:
            # strip trailing zero if present (old IDBs)
            if val[-1:] == b'\x00':
                val = val[:-1]
            return Dex.as_string(val)
        return ""

    #---------------------------------------------------------------------------
    # Converts a single-char primitive type into its human-readable equivalent
    PRIMITVE_TYPES = {
        'B': "byte",
        'C': "char",
        'D': "double",
        'F': "float",
        'I': "int",
        'J': "long",
        'S': "short",
        'V': "void",
        'Z': "boolean",
        'L': "ref" }
    @staticmethod
    def _primitive_type_label(typechar):
        if typechar in Dex.PRIMITVE_TYPES:
            return Dex.PRIMITVE_TYPES[typechar]
        return "UNKNOWN"

    @staticmethod
    def is_wide_type(typechar):
        return typechar[0] == 'J' or typechar[0] == 'D'

    #---------------------------------------------------------------------------
    # Converts a type descriptor to human-readable "dotted" form.  For
    # example, "Ljava/lang/String;" becomes "java.lang.String", and
    # "[I" becomes "int[]".  Also converts '$' to '.', which means this
    # form can't be converted back to a descriptor.
    @staticmethod
    def decorate_java_typename(desc):
        target_len = len(desc)
        offset = 0
        # strip leading [s; will be added to end
        while target_len > 1 and desc[offset] == '[':
            offset += 1
            target_len -= 1
        array_depth = offset
        if target_len == 1:
            # primitive type
            desc = Dex._primitive_type_label(desc[offset])
            offset = 0
            target_len = len(desc)
        else:
            # account for leading 'L' and trailing ';'
            if target_len >= 2 and desc[offset] == 'L' and desc[offset + target_len - 1] == ';':
                target_len -= 2
                offset += 1
        # copy class name over
        res = ""
        for _i in range(0, target_len):
            ch = desc[offset + _i]
            res += '.' if ch == '/' else ch
        # add the appropriate number of brackets for arrays
        res += "[]"*array_depth
        return res

    #---------------------------------------------------------------------------
    def get_type_string(self, from_ea, type_idx):
        idx = self.get_dexnum(from_ea) - 1
        # check in-memory rename map first
        if idx < len(self.type_renames) and self.type_renames[idx] is not None:
            renames = self.type_renames[idx]
            if type_idx in renames:
                return renames[type_idx]
        # read from the TYPES segment: type_id -> string_id -> string
        dexnum = idx + 1
        segname = "TYPES" if dexnum == 1 else "TYPES%d" % dexnum
        seg_ea = ida_segment.get_segment_ea_by_name(segname)
        if seg_ea != ida_idaapi.BADADDR:
            type_ea = seg_ea + type_idx * 4
            if ida_bytes.is_mapped(type_ea):
                string_id = ida_bytes.get_dword(type_ea)
                return self.get_string(from_ea, string_id)
        # fallback for old IDBs
        nn_var = self.get_nn_var(from_ea)
        return Dex.get_string_by_index(nn_var, type_idx, Dex.DEXVAR_OLD_TYPSTR)

    def get_method_name(self, from_ea, method_idx):
        nn_var = self.get_nn_var(from_ea)
        return Dex.get_string_by_index(nn_var, method_idx, Dex.DEXVAR_METH_STR)

    def get_parameter_name(self, from_ea, idx):
        return self.get_string(from_ea, idx)

    #---------------------------------------------------------------------------
    @staticmethod
    def get_short_type_name(longname):
        if not longname:
            return "unknown"
        deco = Dex.decorate_java_typename(longname)
        if not deco:
            return "unknown"
        start = deco.rfind('.')
        if start == -1:
            start = 0
        else:
            start += 1
        return deco[start:].replace('<', '_').replace('>', '_')

    @staticmethod
    def get_full_type_name(longname):
        if not longname:
            return "unknown"
        return Dex.decorate_java_typename(longname)

    #---------------------------------------------------------------------------
    def get_short_method_name(self, method):
        res = Dex.get_short_type_name(self.get_type_string(method.defaddr, method.cname))
        res += '.'
        res += self.get_method_name(method.defaddr, method.id)
        res += '@'
        res += self.get_string(method.defaddr, method.proto_shorty)
        return res

    def get_full_method_name(self, method):
        res = Dex.get_full_type_name(self.get_type_string(method.defaddr, method.proto_ret))
        res += ' '
        res += self.get_full_type_name(self.get_type_string(method.defaddr, method.cname))
        res += '.'
        res += self.get_method_name(method.defaddr, method.id)

    def get_call_method_name(self, method):
        shorty = self.get_string(method.defaddr, method.proto_shorty)
        res = Dex._primitive_type_label(shorty[0])
        res += ' '
        res += Dex.get_short_type_name(self.get_type_string(method.defaddr, method.cname))
        res += '.'
        res += self.get_method_name(method.defaddr, method.id)
        res += '('
        last_idx = len(shorty) - 1
        for s in range(1, last_idx + 1):
            res += Dex._primitive_type_label(shorty[s])
            if s != last_idx:
                res += ", "
        res += ')'
        return res


    #---------------------------------------------------------------------------
    def get_field(self, from_ea, field_idx):
        nn_var = self.get_nn_var(from_ea)
        val = nn_var.supval(field_idx, Dex.DEXVAR_FIELD)
        # Legacy IDBs (saved before access_flags was appended to dex_field_t)
        # store a shorter blob; pad with zeros so access_flags reads as 0.
        full_size = ctypes.sizeof(dex_field_t)
        legacy_size = dex_field_t.access_flags.offset
        if val is None or len(val) < legacy_size:
            print("bad data in DEXVAR_FIELD for index 0x%X" % field_idx)
            return None
        if len(val) < full_size:
            val = val + b'\x00' * (full_size - len(val))
        field = get_struct(val, 0, dex_field_t)
        return field


    def get_field_name(self, from_ea, field_idx):
        nn_var = self.get_nn_var(from_ea)
        name = Dex.get_string_by_index(
            nn_var, field_idx, Dex.DEXVAR_FIELD_NAME)
        if name:
            return name
        field = self.get_field(from_ea, field_idx)
        return self.get_string(from_ea, field.name)


    def get_full_field_name(self, field_idx, field, field_name):
        res = Dex.get_full_type_name(self.get_type_string(field.maddr, field.type))
        res += ' '
        res += Dex.get_full_type_name(self.get_type_string(field.maddr, field_idx))
        res += '.'
        res += field_name if field_name else self.get_field_name(field.maddr, field_idx)
        return res


    def get_short_field_name(self, field_idx, field, field_name):
        res = Dex.get_short_type_name(self.get_type_string(field.maddr, field.ctype))
        res += '_'
        res += field_name if field_name else self.get_field_name(field.maddr, field_idx)


# compatibility
dex_method = dex_method_t
dex_field = dex_field_t

#---------------------------------------------------------------------------
if __name__ == '__main__':
    dex = Dex()
    # reproduce IDA function header
    f = idaapi.get_func(here())
    if not f:
        print("ERROR: must be in a function!")
        exit(1)

    func_start_ea = f.start_ea
    methno = dex.get_method_idx(func_start_ea)
    func_method = dex.get_method(func_start_ea, methno)
    if func_method is None:
        print("ERROR: Missing method info")
        exit(1)
    out = ""
    # Return type
    out += Dex.access_string(func_method.access_flags) + " "
    method_proto = dex.get_type_string(func_start_ea, func_method.proto_ret)
    if method_proto:
        out += Dex.get_full_type_name(method_proto)
    else:
        out += "%x" % func_method.proto_ret
    out += ' '
    # Class name
    method_classnm = dex.get_type_string(func_start_ea, func_method.cname)
    if method_classnm:
        out += Dex.get_full_type_name(method_classnm)
    else:
        out += "%x" % func_method.cname
    out += '.'
    # Method name
    method_name = dex.get_method_name(func_start_ea, methno)
    if method_name:
        out += method_name
    else:
        out += "%x" % methno
    # Method parameters
    if func_method.nparams == 0:
        print(out + "()")
    else:
        print(out + "(")
        out = ""
        maxp = min(func_method.nparams, 32)
        start_reg = func_method.reg_total - func_method.reg_params
        if func_method.access_flags & Dex.ACCESS_FLAGS["static"] == 0:
            start_reg += 1
        for i in range(0, maxp):
            ptype = dex.get_type_string(func_start_ea, func_method.proto_params[i])

            out = "  %s " % dex.get_full_type_name(ptype)
            regbuf = "v%u" % start_reg
            start_reg += 1
            r = idaapi.find_regvar(f, f.start_ea, regbuf)
            if r is None:
                out += regbuf
                if Dex.is_wide_type(ptype):
                    out += ':'
                    regbuf = "v%u" % start_reg
                    start_reg += 1
            else:
                out += r.user
            out += ')' if i + 1 == maxp else ','
            print(out)
