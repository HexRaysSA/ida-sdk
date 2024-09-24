# an example of a file loader in Python
# The scripting loader must define at least two functions: accept_file and load_file
# other optional functions are: save_file, move_segm, ...
#
# see also loader.hpp

import idaapi
import ida_idp
import idc
import struct

ROM_SIGNATURE_OFFSET = 64
ROM_SIGNATURE        = "ECEC"
RomFormatName        = "Windows CE ROM"

# -----------------------------------------------------------------------
def dwordAt(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4:
        return 0
    return struct.unpack('<I', s)[0]

# -----------------------------------------------------------------------
def guess_processor(li):
    jump = dwordAt(li, 0)
    if jump & 0xFF000000 == 0xEA000000: # looks like an ARM branch?
        return "arm"
    else:
        return "metapc"

# -----------------------------------------------------------------------
def accept_file(li, filename):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param filename: name of the file, if it is an archive member name then the actual file doesn't exist
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # check the CECE signature
    li.seek(ROM_SIGNATURE_OFFSET)
    if li.read(4) == ROM_SIGNATURE:
        # accept the file
        proc = guess_processor(li)
        return {'format': RomFormatName, 'processor': proc}

    # unrecognized format
    return 0

# -----------------------------------------------------------------------
def load_file(li, neflags, format):

    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if format == RomFormatName:
        proc = guess_processor(li)
        idaapi.set_processor_type(proc, ida_idp.SETPROC_LOADER)

        li.seek(0, idaapi.SEEK_END)
        size = li.tell()

        #next dword after signature is a pointer to ROMHDR
        romhdr  = dwordAt(li, ROM_SIGNATURE_OFFSET + 4)

        # let's try to find such imagebase that potential ROMHDR's "physfirst" value matches it
        imgbase = (romhdr-size) & ~0xfff
        bases = []
        maxbase = 0
        while imgbase < romhdr+8:
            physfirst = dwordAt(li, romhdr - imgbase + 8)
            if physfirst == imgbase:
                bases.append(imgbase)
            imgbase += 0x1000

        if len(bases) == 1:
            start = bases[0]
        elif len(bases) > 1:
            print("warning: several potential imagebases detemined: " + ", ".join("%08X"%i for i in bases))
            start = bases[-1]
        else:
            warning("Unable to determine load image base.")
            start = 0x80000000
        print("Using imagebase %08X" % start)

        physlast = dwordAt(li, romhdr - start + 12)
        if physlast <= start:
            warning("Internal error")
            return 0
        size = physlast - start

        idc.AddSeg(start, start+size, 0, 1, idaapi.saRelPara, idaapi.scPub)

        # copy bytes to the database
        li.seek(0)
        li.file2base(0, start, start+size, 0)

        idaapi.add_entry(start, start, "start", 1)
        print("Load OK")
        return 1

    idc.warning("Unknown format name: '%s'" % format)
    return 0

# -----------------------------------------------------------------------
def move_segm(frm, to, sz, fileformatname):
    idc.warning("move_segm(from=%s, to=%s, sz=%d, formatname=%s" % (hex(frm), hex(to), sz, fileformatname))
    return 0
