"""
summary: a plugin that extracts images of an Apple cache as standalone Mach-Os

description:
  Apple ships system code in caches rather than as files: a dyld shared
  cache holds thousands of dylibs, a kernelcache holds the XNU kernel
  and hundreds of KEXTs. Either way the builder splits each image's
  segments across the container, merges everybody's __LINKEDIT into
  one blob, and shares a single string pool between all of them, so an
  image inside one is not a file you can hand to another tool.

  This plugin reassembles one: it reads the image's own load commands,
  lays its segments out contiguously, and rebuilds a private
  __LINKEDIT out of that image's symbols, plus whatever function
  starts, data-in-code table and export trie it carries. The private
  string pool is typically two to three orders of magnitude smaller
  than the container's shared one.

  It works on both caches. The Mach-O assembly is the same for either;
  only three things are container-specific, and they live in a backend
  class -- where the image's header is, which address spans hold its
  content, and how the shared __LINKEDIT gets mapped.

  Everything comes from the public APIs (ida_dscu, ida_kcu) plus
  ida_bytes, so the bytes written out are the ones in the database:
  the container's pointer chains are already resolved, and your
  patches are included. The result is not runtime-loadable -- no
  rebase/bind information is regenerated -- but it opens on its own,
  with its code, its data and its symbols at the addresses the
  container gives them.

  Using it: drop this file in your plugins directory. There is nothing
  to run -- it loads itself for any database opened from a
  dyld_shared_cache or a kernelcache, and does nothing for anything
  else.

  Select one or more images in the "DSC Index" or "KC Index" and pick
  "Extract Mach-O image to file..." from its context menu. One image
  asks where to save it; several ask once for a directory, and are
  written under it -- a cache image keeping the tree of its install
  name, a KEXT its bundle id. Anything already there is reported
  before a byte is written.

  In the disassembly, Ctrl-Alt-Shift-M extracts the image under the
  cursor. It is deliberately not in that context menu.

  Adapting it: extract(name, path) is the whole job, and takes a
  backend. Everything container-specific is in the two backend
  classes.

level: intermediate
"""

import os
import struct

import ida_bytes
import ida_idaapi
import ida_kernwin

PAGE = 0x4000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_DYSYMTAB = 0x0B
LC_CODE_SIGNATURE = 0x1D
LC_SEGMENT_SPLIT_INFO = 0x1E
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLD_EXPORTS_TRIE = 0x80000033
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022

# load commands that describe the container, not the image
DROP_LCS = {LC_CODE_SIGNATURE, LC_SEGMENT_SPLIT_INFO}

# __LINKEDIT blobs a linkedit_data_command locates, copied over verbatim.
# Apple's dsc_extractor drops the export trie; we keep it -- it is
# address-relative, so it stays valid in the extracted file.
BLOB_LCS = (LC_FUNCTION_STARTS, LC_DATA_IN_CODE, LC_DYLD_EXPORTS_TRIE)

# LC_DYLD_INFO's ten offset/size pairs describe rebase, bind and export
# streams the container's builder consumed and threw away. Older caches still
# carry the command; its offsets would dangle into the shared __LINKEDIT, so
# it is emitted empty -- the same thing Apple's dsc_extractor does.
DYLD_INFO_LCS = (LC_DYLD_INFO, LC_DYLD_INFO_ONLY)
DYLD_INFO_NFIELDS = 10
DYLD_INFO_EXPORT = 8                # index of export_off among those fields

# the load commands a dylib ordinal counts through, and the one that makes a
# whole dylib's exports ours
DYLIB_LCS = (0x0C,                  # LC_LOAD_DYLIB
             0x80000018,            # LC_LOAD_WEAK_DYLIB
             0x1F,                  # LC_REEXPORT_DYLIB
             0x80000023)            # LC_LOAD_UPWARD_DYLIB
LC_REEXPORT_DYLIB = 0x1F

N_INDR, N_SECT, N_EXT = 0x0A, 0x0E, 0x01

# an indirect symbol table entry that is a marker, not an index
INDIRECT_SYMBOL_LOCAL, INDIRECT_SYMBOL_ABS = 0x80000000, 0x40000000
EXPORT_KIND_MASK, EXPORT_KIND_REGULAR = 0x03, 0x00
EXPORT_FLAG_REEXPORT = 0x08

MH_HDR_SIZE = 32
SEG_CMD_SIZE = 72
SECT_SIZE = 80
NLIST_SIZE = 16

MH_NCMDS_OFF = 16
MH_SIZEOFCMDS_OFF = 20
MH_FLAGS_OFF = 24
SEG_VMADDR_OFF = 24                 # segment_command_64::vmaddr
SECT_ADDR_OFF = 32                  # section_64::addr
LEDATA_DATAOFF_OFF = 8              # linkedit_data_command::dataoff
MH_DYLIB_IN_CACHE = 0x80000000

# a segment this much bigger than the image itself belongs to the container,
# shared by every image that declares it (libobjc's __OBJC_RO, ...)
HUGE_SEGMENT = 0x1000000


class report_t:
    """What one extraction produced, and what it had to approximate."""

    def __init__(self):
        self.counts = {}
        self.notes = []

    def bump(self, key, n=1):
        self.counts[key] = self.counts.get(key, 0) + n

    def note(self, fmt, *args):
        self.notes.append(fmt % args if args else fmt)

    def lines(self):
        out = ["%-20s %d" % (k, self.counts[k]) for k in sorted(self.counts)]
        out.extend("! " + n for n in self.notes)
        return out


class section_t:
    __slots__ = ("segname", "sectname", "addr", "size", "offset", "flags",
                 "lc_off", "zerofill")


class segment_t:
    __slots__ = ("name", "vmaddr", "vmsize", "fileoff", "filesize", "nsects",
                 "lc_off", "sections", "new_fileoff")


def read_db(ea, size, rep):
    """Database bytes, zero-filled wherever the database has nothing."""
    if size == 0:
        return b""
    data = ida_bytes.get_bytes(ea, size)
    if data is not None and len(data) == size:
        return data
    # one unmapped hole must not cost us the rest of the span
    out = bytearray(size)
    got = 0
    for i in range(size):
        if ida_bytes.is_loaded(ea + i):
            out[i] = ida_bytes.get_byte(ea + i)
            got += 1
    rep.bump("bytes_zero_filled", size - got)
    return bytes(out)


def parse_load_commands(hdr_ea):
    """The Mach-O header at `hdr_ea`, as an editable model."""
    raw = ida_bytes.get_bytes(hdr_ea, MH_HDR_SIZE)
    if raw is None:
        raise RuntimeError("no bytes at the header address %#x" % hdr_ea)
    magic, _cputype, _cpusub, _filetype, ncmds, sizeofcmds, flags, _ = \
        struct.unpack("<8I", raw)
    if magic != 0xFEEDFACF:
        raise RuntimeError("bad Mach-O magic %08X at %#x" % (magic, hdr_ea))

    lcs = bytearray(ida_bytes.get_bytes(hdr_ea + MH_HDR_SIZE, sizeofcmds))
    segs, cmds, blobs, dyld_infos, off = [], [], [], [], 0
    symtab = dysymtab = trie = None
    ndylibs, reexported_dylibs = 0, set()
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", lcs, off)
        cmds.append((cmd, cmdsize, off))
        if cmd == LC_SEGMENT_64:
            sg = segment_t()
            sg.name = bytes(lcs[off + 8:off + 24]).rstrip(b"\0").decode()
            sg.vmaddr, sg.vmsize, sg.fileoff, sg.filesize = \
                struct.unpack_from("<QQQQ", lcs, off + 24)
            sg.nsects = struct.unpack_from("<I", lcs, off + 64)[0]
            sg.lc_off = off
            sg.new_fileoff = 0
            sg.sections = []
            so = off + SEG_CMD_SIZE
            for _k in range(sg.nsects):
                sc = section_t()
                sc.sectname = bytes(lcs[so:so + 16]).rstrip(b"\0").decode()
                sc.segname = bytes(lcs[so + 16:so + 32]).rstrip(b"\0").decode()
                sc.addr, sc.size = struct.unpack_from("<QQ", lcs, so + 32)
                sc.offset = struct.unpack_from("<I", lcs, so + 48)[0]
                sc.flags = struct.unpack_from("<I", lcs, so + 64)[0]
                # S_ZEROFILL, S_THREAD_LOCAL_ZEROFILL: no file content
                sc.zerofill = (sc.flags & 0xFF) in (0x1, 0xC)
                sc.lc_off = so
                sg.sections.append(sc)
                so += SECT_SIZE
            segs.append(sg)
        elif cmd == LC_SYMTAB:
            symtab = (off,) + struct.unpack_from("<IIII", lcs, off + 8)
        elif cmd == LC_DYSYMTAB:
            dysymtab = (off,) + struct.unpack_from("<18I", lcs, off + 8)
        elif cmd in BLOB_LCS:
            blobs.append((cmd, off) + struct.unpack_from("<II", lcs, off + 8))
            if cmd == LC_DYLD_EXPORTS_TRIE:
                trie = struct.unpack_from("<II", lcs, off + 8)
        elif cmd in DYLD_INFO_LCS:
            dyld_infos.append(off)
            # older images carry the trie inside LC_DYLD_INFO instead
            at = off + 8 + DYLD_INFO_EXPORT * 4
            trie = trie or struct.unpack_from("<II", lcs, at)
        if cmd in DYLIB_LCS:
            ndylibs += 1              # ordinals are 1-based, in load order
            if cmd == LC_REEXPORT_DYLIB:
                reexported_dylibs.add(ndylibs)
        off += cmdsize
    return (lcs, ncmds, sizeofcmds, flags, segs, cmds, blobs, dyld_infos,
            trie, reexported_dylibs, symtab, dysymtab)


def read_uleb(blob, at):
    """One LEB128, and where it ends."""
    value, shift = 0, 0
    while at < len(blob):
        byte = blob[at]
        at += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            break
        shift += 7
    return value, at


def walk_export_trie(blob, at, prefix, out, seen):
    """
    Collect (name, import_name, dylib_ordinal) for every re-exported symbol.

    A re-export is an export whose value is not an address: the trie stores
    the ordinal of the dylib that really defines it, and optionally the name
    it goes by there.
    """
    if at in seen or at >= len(blob):
        return                              # a malformed trie must not loop
    seen.add(at)
    terminal_size, i = read_uleb(blob, at)
    if terminal_size:
        flags, j = read_uleb(blob, i)
        if flags & EXPORT_FLAG_REEXPORT \
           and flags & EXPORT_KIND_MASK == EXPORT_KIND_REGULAR:
            ordinal, j = read_uleb(blob, j)
            end = blob.find(b"\0", j)
            import_name = blob[j:end] if end > j else b""
            out.append((prefix, import_name, ordinal))
    i += terminal_size
    if i >= len(blob):
        return
    nchildren = blob[i]
    i += 1
    for _ in range(nchildren):
        end = blob.find(b"\0", i)
        if end < 0:
            return
        edge = blob[i:end]
        child, i = read_uleb(blob, end + 1)
        walk_export_trie(blob, child, prefix + edge, out, seen)


def collect_reexports(blob, reexported_dylibs):
    """
    The re-exports that need a symbol of their own.

    One coming from a dylib this image re-exports wholesale is already
    covered by that LC_REEXPORT_DYLIB, and would be a duplicate.
    """
    found = []
    walk_export_trie(blob, 0, b"", found, set())
    return [(n, i) for n, i, ordinal in found
            if ordinal not in reexported_dylibs]


def build_macho(hdr_ea, spans, rep, local_syms=()):
    """
    Assemble a standalone Mach-O out of a header that lives inside a
    container, plus the address spans its content occupies there.

    `local_syms` is (name, address) for symbols the container moved out of
    the image, to be put back at the front of the symbol table.

    `spans` is a list of (start_ea, size). They must tile the image's
    segments: both containers scatter an image's segments across
    themselves, and the region map is what says where each piece landed.
    """
    (lcs, ncmds, sizeofcmds, flags, segs, cmds, blobs, dyld_infos,
     trie, reexported_dylibs, symtab, dysymtab) = parse_load_commands(hdr_ea)

    def set_u32(at, value):
        struct.pack_into("<I", lcs, at, value)

    def set_u64(at, value):
        struct.pack_into("<Q", lcs, at, value)

    # --- the file layout the extracted image will have
    linkedit = None
    cumulative = 0
    for sg in segs:
        if sg.name == "__LINKEDIT":
            linkedit = sg
            continue
        if sg.vmsize >= HUGE_SEGMENT:
            rep.note("%s is %#x bytes: a container-wide segment this image "
                     "only declares, written out in full", sg.name, sg.vmsize)
        sg.new_fileoff = cumulative
        cumulative += sg.vmsize
        rep.bump("segments")
    body_size = cumulative

    # --- segment payload, span by span
    body = bytearray(body_size)
    for sg in segs:
        if sg is linkedit or sg.vmsize == 0:
            continue
        mine = [(start, size) for start, size in spans
                if sg.vmaddr <= start < sg.vmaddr + sg.vmsize]
        if not mine:
            mine = [(sg.vmaddr, sg.vmsize)]
        for start, size in mine:
            data = read_db(start, size, rep)
            at = sg.new_fileoff + (start - sg.vmaddr)
            body[at:at + len(data)] = data
            rep.bump("bytes_copied", len(data))

    # --- rewrite the load commands for that layout
    for sg in segs:
        if sg is linkedit:
            continue
        set_u64(sg.lc_off + SEG_VMADDR_OFF + 16, sg.new_fileoff)
        set_u64(sg.lc_off + SEG_VMADDR_OFF + 24, sg.vmsize)
        for sc in sg.sections:
            if sc.zerofill:
                continue                      # its offset stays 0
            if sc.size == 0:
                rep.bump("marker_sections")   # a placeholder, no content
                continue
            set_u32(sc.lc_off + SECT_ADDR_OFF + 16,
                    sg.new_fileoff + (sc.addr - sg.vmaddr))
            rep.bump("sections")

    # --- a private __LINKEDIT holding only this image's metadata
    le_blob = b""
    if linkedit is not None:

        def off2ea(file_off):
            # a load command locates its tables by file offset in the
            # container; the image's own __LINKEDIT segment command is what
            # maps those onto the shared region the database has mapped
            return linkedit.vmaddr + (file_off - linkedit.fileoff)

        blob = bytearray()

        def align_ptr():
            while len(blob) % 8:
                blob.extend(b"\0")

        # the verbatim tables, in dsc_extractor's order
        for _cmd, lc_off, dataoff, datasize in blobs:
            align_ptr()
            at = len(blob)
            if dataoff and datasize:
                blob += read_db(off2ea(dataoff), datasize, rep)
                rep.bump("blob_bytes", datasize)
            set_u32(lc_off + LEDATA_DATAOFF_OFF, at)     # patched again below
            set_u32(lc_off + LEDATA_DATAOFF_OFF + 4, len(blob) - at)

        nsyms = nadded = 0
        sym_at = ind_at = str_at = len(blob)
        strs_len = 1
        if symtab is not None:
            st_off, symoff, nsyms, stroff, strsize = symtab
            nlists = read_db(off2ea(symoff), nsyms * NLIST_SIZE, rep)
            strbase = off2ea(stroff)

            new_syms = bytearray()
            new_strs = bytearray(b"\0")       # index 0 is the empty string

            # The locals the container took out go back in front: the symbol
            # table is ordered locals, then externally defined, then
            # undefined, and LC_DYSYMTAB indexes into it by that order.
            nadded = 0
            if local_syms:
                sections = []             # (start, end, 1-based ordinal)
                ordinal = 0
                for sg in segs:
                    for sc in sg.sections:
                        ordinal += 1
                        sections.append((sc.addr, sc.addr + sc.size, ordinal))
                for name, ea in local_syms:
                    sect = next((o for lo, hi, o in sections if lo <= ea < hi), 0)
                    if sect == 0:
                        rep.bump("local_symbols_unplaced")
                        continue          # in no section: nothing to point at
                    at = len(new_syms)
                    new_syms += b"\0" * NLIST_SIZE
                    struct.pack_into("<I", new_syms, at, len(new_strs))
                    new_syms[at + 4] = N_SECT   # local: no N_EXT
                    new_syms[at + 5] = sect
                    struct.pack_into("<Q", new_syms, at + 8, ea)
                    new_strs += name.encode("utf-8") + b"\0"
                    nadded += 1
                rep.bump("local_symbols", nadded)

            for i in range(nsyms):
                n_strx = struct.unpack_from("<I", nlists, i * NLIST_SIZE)[0]
                name = b""
                if 0 < n_strx < strsize:
                    name = ida_bytes.get_strlit_contents(strbase + n_strx, -1, 0) or b""
                    if not name:
                        rep.bump("symbols_unnamed")
                at = len(new_syms)
                new_syms += nlists[i * NLIST_SIZE:(i + 1) * NLIST_SIZE]
                struct.pack_into("<I", new_syms, at, len(new_strs))
                new_strs += name + b"\0"
            rep.bump("symbols", nsyms)

            # Symbols this image exports but does not define live in the
            # export trie, which a symbol-table reader (lldb, among others)
            # never looks at. Give each one an N_INDR entry naming where it
            # really lives -- what Apple's dsc_extractor synthesizes because
            # it drops the trie. We keep the trie too; this is the same facts
            # in the place a plain symbol lookup will find them.
            if trie is not None and trie[1] != 0:
                trie_blob = read_db(off2ea(trie[0]), trie[1], rep)
                for name, import_name in collect_reexports(trie_blob,
                                                           reexported_dylibs):
                    at = len(new_syms)
                    new_syms += b"\0" * NLIST_SIZE
                    struct.pack_into("<I", new_syms, at, len(new_strs))
                    new_syms[at + 4] = N_INDR | N_EXT
                    new_strs += name + b"\0"
                    # for an N_INDR, n_value is not an address: it is where
                    # the name in the providing dylib sits in the string pool
                    struct.pack_into("<Q", new_syms, at + 8, len(new_strs))
                    new_strs += (import_name or name) + b"\0"
                    nsyms += 1
                    rep.bump("reexported_symbols")

            indirect = b""
            if dysymtab is not None:
                indirectsymoff, nindirectsyms = dysymtab[13], dysymtab[14]
                if nindirectsyms:
                    indirect = bytearray(
                            read_db(off2ea(indirectsymoff), nindirectsyms * 4, rep))
                    rep.bump("indirect_symbols", nindirectsyms)
                    if nadded:
                        # every index moved by however many locals we put in
                        # front; the two markers are not indexes
                        for k in range(nindirectsyms):
                            v = struct.unpack_from("<I", indirect, k * 4)[0]
                            if not v & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS):
                                struct.pack_into("<I", indirect, k * 4, v + nadded)

            align_ptr()
            sym_at = len(blob)
            blob += new_syms
            ind_at = len(blob)
            blob += indirect
            align_ptr()
            str_at = len(blob)
            blob += new_strs
            align_ptr()
            strs_len = len(new_strs)
            rep.note("string pool rebuilt: %d bytes, from the container's %d",
                     strs_len, strsize)

        le_blob = bytes(blob)
        le_fileoff = body_size

        # everything above recorded blob-relative offsets; shift them onto
        # the segment now that its file offset is known
        for _cmd, lc_off, _dataoff, _datasize in blobs:
            at = struct.unpack_from("<I", lcs, lc_off + LEDATA_DATAOFF_OFF)[0]
            sz = struct.unpack_from("<I", lcs, lc_off + LEDATA_DATAOFF_OFF + 4)[0]
            set_u32(lc_off + LEDATA_DATAOFF_OFF, le_fileoff + at if sz else 0)
        if symtab is not None:
            st_off = symtab[0]
            set_u32(st_off + 8, le_fileoff + sym_at)
            set_u32(st_off + 12, nsyms + nadded)
            set_u32(st_off + 16, le_fileoff + str_at)
            set_u32(st_off + 20, strs_len)
        if dysymtab is not None:
            ds_off = dysymtab[0]
            if nadded:
                nextdefsym = dysymtab[4]
                nlocal = dysymtab[2] + nadded
                set_u32(ds_off + 8, 0)                    # ilocalsym
                set_u32(ds_off + 12, nlocal)              # nlocalsym
                set_u32(ds_off + 16, nlocal)              # iextdefsym
                set_u32(ds_off + 24, nlocal + nextdefsym) # iundefsym
            set_u32(ds_off + 8 + 12 * 4, le_fileoff + ind_at)
            for k in (14, 15, 16, 17):        # extreloff/nextrel, locreloff/nlocrel
                set_u32(ds_off + 8 + k * 4, 0)
        set_u64(linkedit.lc_off + SEG_VMADDR_OFF + 8,
                (len(le_blob) + PAGE - 1) & ~(PAGE - 1))
        set_u64(linkedit.lc_off + SEG_VMADDR_OFF + 16, le_fileoff)
        set_u64(linkedit.lc_off + SEG_VMADDR_OFF + 24, len(le_blob))
        rep.bump("linkedit_bytes", len(le_blob))

    # --- the dyld streams describe the container, not this image
    for at in dyld_infos:
        for k in range(DYLD_INFO_NFIELDS):
            set_u32(at + 8 + k * 4, 0)
        rep.bump("emptied_dyld_info")

    # --- drop what describes the container rather than the image
    for cmd, cmdsize, at in reversed(cmds):
        if cmd in DROP_LCS:
            del lcs[at:at + cmdsize]
            lcs += b"\0" * cmdsize
            ncmds -= 1
            sizeofcmds -= cmdsize
            rep.bump("dropped_lcs")

    out = bytearray(body)
    out[0:MH_HDR_SIZE] = ida_bytes.get_bytes(hdr_ea, MH_HDR_SIZE)
    struct.pack_into("<I", out, MH_NCMDS_OFF, ncmds)
    struct.pack_into("<I", out, MH_SIZEOFCMDS_OFF, sizeofcmds)
    struct.pack_into("<I", out, MH_FLAGS_OFF, flags & ~MH_DYLIB_IN_CACHE)
    out[MH_HDR_SIZE:MH_HDR_SIZE + len(lcs)] = lcs
    out += le_blob
    while len(out) % PAGE:
        out += b"\0"
    return bytes(out)


#---------------------------------------------------------------------------
# The container-specific half. A backend answers four questions about one
# image: where its header is, which address spans hold its content, how to
# get it (and the shared __LINKEDIT) mapped, and what it is called.
#---------------------------------------------------------------------------

class dsc_backend_t:
    """A dyld shared cache, through ida_dscu."""

    what = "image"

    def __init__(self, svc):
        self.svc = svc

    def names(self):
        return list(self.svc.get_images_names())

    def name_at(self, ea):
        region = self.ida_dscu.region_info_t()
        if self.svc.get_region_by_ea(region, ea) \
           and region.type == self.ida_dscu.rt_image_entity:
            return self.svc.get_image_name(region.image_index)
        return None

    def default_filename(self, name):
        # an install name is a path: the file keeps its own name
        return name.rsplit("/", 1)[-1]

    def relative_path(self, name):
        # ...and the tree it came from, so that two images sharing a file
        # name ("/usr/lib/libfoo.dylib", "/usr/lib/system/libfoo.dylib")
        # do not land on each other
        return name.lstrip("/")

    def local_symbols(self, spans):
        """
        The image's local symbols, which the cache builder moved into the
        `.symbols` sidecar. They come back as (name, address): the sidecar's
        nlists are not reachable, so the entries are rebuilt from the index.
        """
        if not self.svc.has_local_symbols():
            return []
        import idaapi
        out, seen = [], set()
        for start, size in spans:
            if size <= 0:
                continue
            found = self.svc.query_symbols(idaapi.range_t(start, start + size))
            if found is None:
                continue
            for i in range(found.size()):
                # image_index -1 marks the cache's own local symbol table
                if found[i].image_index != -1:
                    continue
                key = (found[i].symbol, found[i].ea)
                if key not in seen:
                    seen.add(key)
                    out.append(key)
        return out

    def name_from_region(self, region_index):
        region = self.ida_dscu.region_info_t()
        if not self.svc.get_region(region, region_index) \
           or region.type != self.ida_dscu.rt_image_entity:
            return None
        return self.svc.get_image_name(region.image_index)

    def ensure_loaded(self, name):
        index = self.svc.get_image_index(name)
        if index < 0:
            raise RuntimeError("no such image: %s" % name)
        return self.svc.is_image_loaded(index) or self.svc.load_image(index)

    def header_ea(self, name):
        return self.svc.get_image_address(self.svc.get_image_index(name))

    def spans(self, name):
        regions = self.svc.get_image_regions(self.svc.get_image_index(name), True)
        # an element borrows from the vector, so read it while that is alive
        return [(regions[i].start, regions[i].size) for i in range(regions.size())]

    def map_linkedit(self, vmaddr):
        # cache-wide data, mapped on demand
        region = self.ida_dscu.region_info_t()
        if not self.svc.get_region_by_ea(region, vmaddr):
            return False
        return self.svc.load_cache_data(region.start)


class kc_backend_t:
    """A kernelcache, through ida_kcu."""

    what = "KEXT"

    def __init__(self, svc):
        self.svc = svc

    def names(self):
        out = []
        for kc in range(self.svc.get_kcs_count()):
            out.extend(self.svc.get_kc_kexts_names(kc))
        return out

    def name_at(self, ea):
        kext = self.svc.get_kext_by_ea(ea)
        return self.svc.get_kext_name(kext) if kext.is_valid() else None

    def default_filename(self, name):
        # a bundle id is not a path; it names the file well enough as it is
        return name

    def relative_path(self, name):
        # bundle ids are unique across the collection, so no tree is needed
        return name

    def local_symbols(self, spans):
        return []                         # a kernelcache has no sidecar

    def name_from_region(self, region_index):
        region = self.ida_kcu.kcu_region_info_t()
        if not self.svc.get_region(region, region_index) \
           or not region.kext.is_valid():
            return None
        return self.svc.get_kext_name(region.kext)

    def ensure_loaded(self, name):
        kext = self._coords(name)
        return self.svc.is_kext_loaded(kext) or self.svc.load_kext(kext)

    def header_ea(self, name):
        for start, _size, rtype in self._regions(name):
            if rtype == self.ida_kcu.krt_kext_header:
                return start
        # a KEXT whose first segment declares no section gets no header
        # region; its base is then the lowest address it occupies
        return min(start for start, _size, _t in self._regions(name))

    def spans(self, name):
        return [(start, size) for start, size, _t in self._regions(name)]

    def map_linkedit(self, vmaddr):
        return self.svc.load_linkedit()

    def _coords(self, name):
        kext = self.svc.get_kext_coords(name)
        if not kext.is_valid():
            raise RuntimeError("no such KEXT: %s" % name)
        return kext

    def _regions(self, name):
        regions = self.svc.get_kext_regions(self._coords(name), True)
        # an element borrows from the vector, so read it while that is alive
        return [(regions[i].start, regions[i].size, regions[i].type)
                for i in range(regions.size())]


def backend():
    """The backend for this database, or None if it is neither cache."""
    try:
        import ida_dscu
        svc = ida_dscu.get_dscu_svc()
        if svc is not None:
            b = dsc_backend_t(svc)
            b.ida_dscu = ida_dscu
            return b
    except ImportError:
        pass
    try:
        import ida_kcu
        svc = ida_kcu.get_kcu_svc()
        if svc is not None:
            b = kc_backend_t(svc)
            b.ida_kcu = ida_kcu
            return b
    except ImportError:
        pass
    return None


def linkedit_vmaddr(hdr_ea):
    """Where the image's __LINKEDIT segment command points, if it has one."""
    raw = ida_bytes.get_bytes(hdr_ea, MH_HDR_SIZE)
    ncmds, sizeofcmds = struct.unpack_from("<II", raw, MH_NCMDS_OFF)
    lcs = ida_bytes.get_bytes(hdr_ea + MH_HDR_SIZE, sizeofcmds)
    off = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", lcs, off)
        if cmd == LC_SEGMENT_64 \
           and lcs[off + 8:off + 24].rstrip(b"\0") == b"__LINKEDIT":
            return struct.unpack_from("<Q", lcs, off + SEG_VMADDR_OFF)[0]
        off += cmdsize
    return None


def extract(name, out_path, back=None):
    """Write the image called `name` to `out_path`. Returns a report_t."""
    back = back or backend()
    if back is None:
        raise RuntimeError("this database was not opened from an Apple cache")
    rep = report_t()

    if not back.ensure_loaded(name):
        raise RuntimeError("could not load %s" % name)

    hdr_ea = back.header_ea(name)
    spans = back.spans(name)

    # the image's symbol tables live in the container's shared __LINKEDIT,
    # which is mapped on demand
    vmaddr = linkedit_vmaddr(hdr_ea)
    if vmaddr is not None and not ida_bytes.is_loaded(vmaddr):
        if not back.map_linkedit(vmaddr):
            rep.note("the shared __LINKEDIT could not be mapped; no symbols")

    data = build_macho(hdr_ea, spans, rep, back.local_symbols(spans))
    parent = os.path.dirname(out_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(out_path, "wb") as fout:
        fout.write(data)
    rep.bump("file_size", len(data))
    return rep


# the disassembly extracts whatever the cursor sits in; the two index trees
# extract every item selected in them
INDEX_WIDGETS = (ida_kernwin.BWN_DSC_INDEX, ida_kernwin.BWN_KC_INDEX)

# the disassembly extracts whatever the cursor sits in; the two index trees
# extract every item selected in them
EXTRACT_FROM_WIDGETS = (ida_kernwin.BWN_DISASM,) + INDEX_WIDGETS


# an index tree names a leaf "<region index>\x01<label>": the region resolves
# the image, the label is what the tree shows
INODE_NAME_SEP = "\x01"


def selected_names(ctx, back):
    """The images the action should extract, given where it was invoked."""
    if ctx.widget_type == ida_kernwin.BWN_DISASM:
        name = back.name_at(ida_kernwin.get_screen_ea())
        return [name] if name is not None else []

    # An index tree: the selection is a list of dirtree cursors, and only the
    # widget's own dirtree_t can resolve one. A leaf's name is
    # "<region index>\x01<label>" -- the region is what identifies the image,
    # the label is only what the tree shows.
    dirtree = ida_kernwin.get_widget_dirtree(ctx.widget)
    if dirtree is None:
        return []
    names = []
    for cursor in ctx.dirtree_selection:
        if not cursor.valid():
            continue
        path = dirtree.get_abspath(cursor)
        leaf = path.rsplit("/", 1)[-1] if path else ""
        if INODE_NAME_SEP not in leaf:
            continue                      # a folder groups images, it is not one
        name = back.name_from_region(int(leaf.split(INODE_NAME_SEP, 1)[0]))
        if name is not None and name not in names:
            names.append(name)            # several regions can share an image
    return names


MAX_REPORTED_CONFLICTS = 10


class output_dir_form_t(ida_kernwin.Form):
    def __init__(self, count, what):
        ida_kernwin.Form.__init__(
            self,
            r"""Extract %d %ss
<#The directory to write them under#~D~irectory:{path}>
""" % (count, what),
            {"path": ida_kernwin.Form.DirInput()})


def ask_output_dir(count, what):
    """The directory to extract several images into, or None."""
    form, _args = output_dir_form_t(count, what).Compile()
    try:
        return form.path.value if form.Execute() else None
    finally:
        form.Free()


def plan(names, out_dir, back):
    """Where each image would be written: a list of (name, path)."""
    return [(n, os.path.join(out_dir, back.relative_path(n))) for n in names]


def find_conflicts(targets):
    """The entries of `targets` that would overwrite something."""
    out, claimed = [], {}
    for name, path in targets:
        if path in claimed:
            out.append((path, "also where %s would go" % claimed[path]))
        elif os.path.exists(path):
            out.append((path, "already exists"))
        claimed[path] = name
    return out


def conflict_message(conflicts):
    """What to put in front of the user before overwriting anything."""
    lines = ["%d of the files to write are already taken:" % len(conflicts), ""]
    for path, why in conflicts[:MAX_REPORTED_CONFLICTS]:
        lines.append("  %s (%s)" % (path, why))
    extra = len(conflicts) - MAX_REPORTED_CONFLICTS
    if extra > 0:
        lines.append("  ...and %d more" % extra)
    lines += ["", "Overwrite them?"]
    return "\n".join(lines)


ACTION_NAME = "extract_macho_image:extract"
ACTION_SHORTCUT = "Ctrl+Alt+Shift+M"


class extract_ah_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        back = backend()
        names = selected_names(ctx, back)
        if not names:
            ida_kernwin.warning("No %s is selected." % back.what)
            return 0
        if len(names) == 1:
            name = names[0]
            path = ida_kernwin.ask_file(
                True, back.default_filename(name), "Extract %s to..." % name)
            targets = [(name, path)] if path else []
        else:
            # ask once, then settle every question about the output before
            # writing anything: a conflict found halfway through would leave
            # the extraction half done
            out_dir = ask_output_dir(len(names), back.what)
            targets = plan(names, out_dir, back) if out_dir else []
            conflicts = find_conflicts(targets)
            if conflicts \
               and ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO,
                                      conflict_message(conflicts)) \
                   != ida_kernwin.ASKBTN_YES:
                targets = []

        for name, path in targets:
            rep = extract(name, path, back)
            print("Extracted %s to %s" % (name, path))
            for line in rep.lines():
                print("  " + line)
        return 1

    def update(self, ctx):
        if backend() is None:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET
        return ida_kernwin.AST_ENABLE_FOR_WIDGET \
            if ctx.widget_type in EXTRACT_FROM_WIDGETS \
            else ida_kernwin.AST_DISABLE_FOR_WIDGET


class popup_hooks_t(ida_kernwin.UI_Hooks):
    """Offer the action where a selection of images is made."""

    def finish_populating_widget_popup(self, widget, popup):
        if ida_kernwin.get_widget_type(widget) in INDEX_WIDGETS:
            ida_kernwin.attach_action_to_popup(widget, popup, ACTION_NAME)


class extract_plugmod_t(ida_idaapi.plugmod_t):
    """One database's worth of the plugin: the action, and where to offer it."""

    def __init__(self):
        ida_idaapi.plugmod_t.__init__(self)
        self.hooks = None
        if ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    ACTION_NAME,
                    "Extract Mach-O image to file...",
                    extract_ah_t(),
                    ACTION_SHORTCUT)):
            # the index trees are where images get picked, so the action
            # belongs in their context menu; the disassembly keeps the
            # shortcut alone, its menu being long enough already
            self.hooks = popup_hooks_t()
            self.hooks.hook()

    def __del__(self):
        if self.hooks is not None:
            self.hooks.unhook()
        ida_kernwin.unregister_action(ACTION_NAME)

    def run(self, arg):
        ida_kernwin.info("Select images in the cache index and use its context "
                         "menu, or place the cursor inside one and press %s."
                         % ACTION_SHORTCUT)
        return 0


class extract_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_HIDE
    comment = "Extract an image of an Apple cache as a standalone Mach-O"
    help = __doc__
    wanted_name = "Extract Mach-O image"
    wanted_hotkey = ""

    def init(self):
        # nothing to offer unless this database came from a cache
        return extract_plugmod_t() if backend() is not None else None


def PLUGIN_ENTRY():
    return extract_plugin_t()
