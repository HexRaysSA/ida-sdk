# a file loader for U-Boot "uImage" flash images
# Copyright (c) 2011-2024 Hex-Rays
# ALL RIGHTS RESERVED.

import idaapi
import idc
import zlib
import ida_idp
import ida_typeinf

IH_TYPE_INVALID        = 0        # /* Invalid Image               */
IH_TYPE_STANDALONE     = 1        # /* Standalone Program          */
IH_TYPE_KERNEL         = 2        # /* OS Kernel Image             */
IH_TYPE_RAMDISK        = 3        # /* RAMDisk Image               */
IH_TYPE_MULTI          = 4        # /* Multi-File Image            */
IH_TYPE_FIRMWARE       = 5        # /* Firmware Image              */
IH_TYPE_SCRIPT         = 6        # /* Script file                 */
IH_TYPE_FILESYSTEM     = 7        # /* Filesystem Image (any type) */

ImageTypeNames = [ "Invalid", "Standalone Program", "OS Kernel", "RAMDisk",
                   "Multi-File", "Firmware", "Script file",  "Filesystem" ]

IH_ARCH_INVALID          = 0       # /* Invalid CPU        */
IH_ARCH_ALPHA            = 1       # /* Alpha        */
IH_ARCH_ARM              = 2       # /* ARM                */
IH_ARCH_I386             = 3       # /* Intel x86        */
IH_ARCH_IA64             = 4       # /* IA64                */
IH_ARCH_MIPS             = 5       # /* MIPS                */
IH_ARCH_MIPS64           = 6       # /* MIPS         64 Bit */
IH_ARCH_PPC              = 7       # /* PowerPC        */
IH_ARCH_S390             = 8       # /* IBM S390        */
IH_ARCH_SH               = 9       # /* SuperH        */
IH_ARCH_SPARC            = 10      # /* Sparc        */
IH_ARCH_SPARC64          = 11      # /* Sparc 64 Bit */
IH_ARCH_M68K             = 12      # /* M68K                */
IH_ARCH_NIOS             = 13      # /* Nios-32        */
IH_ARCH_MICROBLAZE       = 14      # /* MicroBlaze   */
IH_ARCH_NIOS2            = 15      # /* Nios-II        */
IH_ARCH_BLACKFIN         = 16      # /*         */
IH_ARCH_AVR32            = 17      # /*         */
IH_ARCH_ST200            = 18      # /*         */
IH_ARCH_SANDBOX          = 19      # /*         */
IH_ARCH_NDS32            = 20      # /*         */
IH_ARCH_OPENRISC         = 21      # /*         */
IH_ARCH_ARM64            = 22      # /*         */
IH_ARCH_ARC               = 23      # /*         */

CPUNames = [ "Invalid", "Alpha", "ARM", "x86", "IA64", "MIPS", "MIPS64", "PowerPC",
             "IBM S390", "SuperH", "Sparc", "Sparc64", "M68K", "Nios-32", "MicroBlaze", "Nios-II",
            "Blackfin", "AVR32", "ST200","Sandbox","NDS32", "OpenRISC", "ARM64", "ARC" ]

IDACPUNames = { IH_ARCH_ALPHA: "alphab",
                IH_ARCH_ARM:"ARM",
                IH_ARCH_I386: "metapc",
                IH_ARCH_IA64: "ia64b",
                IH_ARCH_MIPS:"mipsl",
                IH_ARCH_MIPS64:"mipsl",
                IH_ARCH_PPC: "ppc",
                IH_ARCH_SH: "SH4",
                IH_ARCH_SPARC: "sparcb",
                IH_ARCH_SPARC64:"sparcb",
                IH_ARCH_M68K:"68K",
                IH_ARCH_ARM64:"ARM",
                IH_ARCH_ARC: "arcmpct" }

IDAABINames = { IH_ARCH_MIPS:"n32",
                IH_ARCH_MIPS64:"n64" }

Arch64bit = [ IH_ARCH_ALPHA,
              IH_ARCH_IA64,
              IH_ARCH_MIPS64,
              IH_ARCH_SPARC64,
              IH_ARCH_ARM64 ]

IH_COMP_NONE            =   0     #  /*  No         Compression Used        */
IH_COMP_GZIP            =   1     #  /* gzip         Compression Used        */
IH_COMP_BZIP2           =   2     #  /* bzip2 Compression Used */
IH_COMP_LZMA            =   3     #  /* lzma Compression Used */
IH_COMP_LZO             =   4      #  /* lzo   Compression Used */
CompTypeNames = [ "", "gzip", "bzip2", "lzma", "lzo" ]

IH_MAGIC = 0x27051956        # Image Magic Number
IH_NMLEN = 32                # Image Name Length

import ctypes

uint8_t  = ctypes.c_byte
uint32_t = ctypes.c_uint

class image_header(ctypes.BigEndianStructure):
    _fields_ = [
        ("ih_magic", uint32_t), #   Image Header Magic Number
        ("ih_hcrc",  uint32_t), #   Image Header CRC Checksum
        ("ih_time",  uint32_t), #   Image Creation Timestamp
        ("ih_size",  uint32_t), #   Image Data Size
        ("ih_load",  uint32_t), #   Data Load  Address
        ("ih_ep",    uint32_t), #   Entry Point Address
        ("ih_dcrc",  uint32_t), #   Image Data CRC Checksum
        ("ih_os",    uint8_t),  #   Operating System
        ("ih_arch",  uint8_t),  #   CPU architecture
        ("ih_type",  uint8_t),  #   Image Type
        ("ih_comp",  uint8_t),  #   Compression Type
        ("ih_name",  uint8_t * IH_NMLEN),  # Image Name
    ]
RomFormatName        = "U-Boot image"

# -----------------------------------------------------------------------
def dwordAt(li, off):
    li.seek(off)
    s = li.read(4)
    if len(s) < 4:
        return 0
    return struct.unpack('<I', s)[0]

def read_struct(li, struct):
    s = struct()
    s.ih_magic = 0
    slen = ctypes.sizeof(s)
    if li.size() >= slen:
        bytes = li.read(slen)
        fit = min(len(bytes), slen)
        ctypes.memmove(ctypes.addressof(s), bytes, fit)
    return s

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

    header = read_struct(li, image_header)
    # check the signature
    if header.ih_magic == IH_MAGIC:
        # accept the file
        t = header.ih_type
        c = header.ih_arch
        if t >= len(ImageTypeNames):
          t = "unknown type(%d)" % t
        else:
          t = ImageTypeNames[t]

        if c >= len(CPUNames):
          cname = "unknown CPU(%d)" % c
        else:
          cname = CPUNames[c]

        fmt = "%s (%s for %s)" % (RomFormatName, t, cname)
        comp = header.ih_comp
        if comp != IH_COMP_NONE:
          if comp >= len (CompTypeNames):
            cmpname = "unknown compression(%d)"
          else:
            cmpname = "%s compressed" % CompTypeNames[comp]
          fmt += " [%s]" % cmpname

        proc = ''
        if c in IDACPUNames:
          proc = IDACPUNames[c]

        return {'format': fmt, 'processor': proc}

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

    if format.startswith(RomFormatName):
        li.seek(0)
        header = read_struct(li, image_header)
        c = header.ih_arch
        cname = IDACPUNames.get(c)
        if not cname:
          idc.warning("Unsupported CPU")
          #return

        if not header.ih_comp in (IH_COMP_NONE, IH_COMP_GZIP):
          idc.warning("Can only handle uncompressed or gzip-compressed images")
          return

        if cname:
          idaapi.set_processor_type(cname, ida_idp.SETPROC_LOADER)
          app64bit = c in Arch64bit
          idaapi.inf_set_app_bitness(64 if app64bit else 32)

        idc.AddSeg(header.ih_load, header.ih_load + header.ih_size, 0, 1, idaapi.saRelPara, idaapi.scPub)

        # copy bytes to the database

        if header.ih_comp  == IH_COMP_NONE:
          li.file2base(ctypes.sizeof(header), header.ih_load, header.ih_load + header.ih_size, 0)
        else:
          cdata = li.read(header.ih_size)
          d = zlib.decompressobj(zlib.MAX_WBITS|32)
          udata = d.decompress(cdata)
          udata += d.flush()
          # expand segment to fit uncompressed data
          idc.set_segment_bounds(header.ih_load, header.ih_load, header.ih_load+len(udata), idc.SEGMOD_KEEP)
          idaapi.put_bytes(header.ih_load, udata)

        if cname == "ARM" and (header.ih_ep & 1) != 0:
          # Thumb entry point
          header.ih_ep -= 1
          split_sreg_range(header.ih_ep, "T", 1)
        idaapi.add_entry(header.ih_ep, header.ih_ep, "start", 1)
        aname = IDAABINames.get(header.ih_arch)
        if aname:
          ida_typeinf.set_abi_name(aname)
        print("Load OK")
        return 1
