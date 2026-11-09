r"""
A script that extracts shellcode from PDF files

The script uses very basic shellcode extraction algorithm

Copyright (c) 1990-2024 Hex-Rays
ALL RIGHTS RESERVED.

Revision history
=========================
v1.0 - initial version


Possible enhancements:
=========================
1. From Didier:
-----------------
FYI: the regex you use to match /JavaScript /JS will fail to match
name obfuscation. Name obuscation use a feature of the PDF language
that allows a character in a name (like /JavaScript) to be replaced
with its hexcode. Example: /#4AavaScript
http://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/

It's something that's used in-the-wild.

I've updated your regex to support name obfuscation. The JavaScript
itself is now captured in group 13.

\/S\s*\/(J|#4A|#4a)(a|#61)(v|#76)(a|#61)(S|#53)(c|#63)(r|#72)(i|#69)(p|#70)(t|#74)\s*\/(J|#4A|#4a)(S|#53)
\((.+?)>>

2.
---------------

"""

import sys
import re
import zlib

SAMPLE1 = 'malware1.pdf.vir'
SAMPLE2 = 'heapspray-simpler-calc.pdf.vir'

try:
    import idaapi
    import idc
    import ida_idp
    ida = True
except:
    ida = False

# -----------------------------------------------------------------------
# Tries to find shellcode inside JavaScript statements
# The seach algorithm is simple: it searchs for anything between unescape()
# if it encounters %u or %x it correctly decodes them to characters
def extract_shellcode(lines):
    p = 0
    shellcode = [] # accumulate shellcode
    while True:
        p = lines.find(b'unescape("', p)
        if p == -1:
            break
        e = lines.find(b')', p)
        if e == -1:
            break
        expr = lines[p+9:e]
        data = []
        def put_byte(b):
            if sys.version_info.major >= 3:
                data.append(b)
            else:
                data.append(chr(b))

        for i in range(0, len(expr)):
            if expr[i:i+2] == b"%u":
                i += 2
                put_byte(int(expr[i+2:i+4], 16))
                put_byte(int(expr[i:i+2], 16))
                i += 4
            elif expr[i] == b"%":
                i += 1
                put_byte(int(expr[i:i+2], 16))
                i += 2
        # advance the match pos
        p += 8
        if sys.version_info.major >= 3:
            shellcode.append(bytes(data))
        else:
            shellcode.append("".join(data))

    # That's it
    return shellcode

# -----------------------------------------------------------------------
# Given a PDF object id and version, we return the object declaration
def find_obj(buf, id, ver):
    stream = re.search(b'%d %d obj(.*?)endobj' % (id, ver), buf, re.MULTILINE | re.DOTALL)
    if not stream:
        return None
    return buf[stream.start(1):stream.end(1)]

# -----------------------------------------------------------------------
# Find JavaScript objects and extract the referenced script object id/ver
def find_js_ref_streams(buf):
    o = []
    js_ref_streams = re.finditer(r'\/S\s*\/JavaScript\/JS (\d+) (\d+) R'.encode("UTF-8"), buf)
    for g in js_ref_streams:
        id = int(g.group(1))
        ver = int(g.group(2))
        o.append([id, ver])
    return o

# -----------------------------------------------------------------------
# Find JavaScript objects and extract the embedded script
def find_embedded_js(buf):
    r = re.finditer(r'\/S\s*\/JavaScript\s*\/JS \((.+?)>>'.encode("UTF-8"), buf, re.MULTILINE | re.DOTALL)
    if not r:
        return None

    ret = []
    for js in r:
        p = buf.rfind(b'obj', 0, js.start(1))
        if p == -1:
            return None

        scs = extract_shellcode(js.group(1))
        if not scs:
            return None

        t = buf[p - min(20, len(buf)): p + 3]
        obj = re.search(r'(\d+) (\d+) obj'.encode("UTF-8"), t)
        if not obj:
            id, ver = 0
        else:
            id = int(obj.group(1))
            ver = int(obj.group(2))
        n = 0
        for sc in scs:
            n += 1
            ret.append([id, ver, n, sc])
    return ret

# -----------------------------------------------------------------------
# Given a gzipped stream object, it returns the decompressed contents
def decompress_stream(buf):
    if buf.find(b'Filter[/FlateDecode]') == -1:
        return None
    m = re.search(rb'stream\s*(.+?)\s*endstream', buf, re.DOTALL | re.MULTILINE)
    if not m:
        return None
    # Decompress and return
    return zlib.decompress(m.group(1))


# -----------------------------------------------------------------------
def read_whole_file(li):
    li.seek(0)
    return li.read(li.size())

# -----------------------------------------------------------------------
def extract_pdf_shellcode(buf):
    ret = []

    # find all JS stream references
    r = find_js_ref_streams(buf)
    for id, ver in r:
        # extract the JS stream object
        obj = find_obj(buf, id, ver)

        # decode the stream
        stream = decompress_stream(obj)

        # extract shell code
        scs = extract_shellcode(stream)
        i = 0
        for sc in scs:
            i += 1
            ret.append([id, ver, i, sc])

    # find all embedded JS
    r = find_embedded_js(buf)
    if r:
        ret.extend(r)

    return ret

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

    # we support only one format per file
    li.seek(0)
    if li.read(5) != b'%PDF-':
        return 0

    buf = read_whole_file(li)
    r = extract_pdf_shellcode(buf)
    if not r:
        return 0

    return {'format': 'PDF with shellcode', 'processor': 'metapc'}

# -----------------------------------------------------------------------
def load_file(li, neflags, format):

    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    # Select the PC processor module
    idaapi.set_processor_type("metapc", ida_idp.SETPROC_LOADER)
    idaapi.inf_set_app_bitness(32);

    buf = read_whole_file(li)
    r = extract_pdf_shellcode(buf)
    if not r:
        return 0

    # Load all shellcode into different segments
    start = 0x10000
    seg = idaapi.segment_t()
    for id, ver, n, sc in r:
        size = len(sc)
        end  = start + size

        # Create the segment
        seg.start_ea = start
        seg.end_ea   = end
        seg.bitness  = 1 # 32-bit
        idaapi.add_segm_ex(seg, "obj_%d_%d_%d" % (id, ver, n), "CODE", 0)

        # Copy the bytes
        idaapi.mem2base(sc, start, end)

        # Mark for analysis
        idc.AutoMark(start, idc.AU_CODE)

        # Compute next loading address
        start = ((end // 0x1000) + 1) * 0x1000

    # Select the bochs debugger
    idc.load_debugger("bochs", 0)

    return 1

# -----------------------------------------------------------------------
def test1(sample = SAMPLE1):
    # open the file
    f = file(sample, 'rb')
    buf = f.read()
    f.close()

    # find all JS stream references
    r = find_js_ref_streams(buf)
    if not r:
        return

    for id, ver in r:
        obj = find_obj(buf, id, ver)

        # extract the JS stream object
        f = file('obj_%d_%d.bin' % (id, ver), 'wb')
        f.write(obj)
        f.close()

        # decode the stream
        stream = decompress_stream(obj)
        f = file('dec_%d_%d.bin' % (id, ver), 'wb')
        f.write(stream)
        f.close()

        # extract shell code
        scs = extract_shellcode(stream)
        i = 0
        for sc in scs:
            i += 1
            f = file('sh_%d_%d_%d.bin' % (id, ver, i), 'wb')
            f.write(sc)
            f.close()

# -----------------------------------------------------------------------
def test2(sample = SAMPLE1):
    # open the file
    f = file(sample, 'rb')
    buf = f.read()
    f.close()

    r = extract_pdf_shellcode(buf)
    for id, ver, n, sc in r:
        print("sc %d.%d[%d]=%d" % (id, ver, n, len(sc)))

# -----------------------------------------------------------------------
def test3(sample = SAMPLE2):
    # open the file
    f = file(sample, 'rb')
    buf = f.read()
    f.close()
    t = find_embedded_js(buf)
    print(t)

# -----------------------------------------------------------------------
def main():
    test1(SAMPLE1)

if not ida:
    main()
