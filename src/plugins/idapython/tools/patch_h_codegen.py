from __future__ import print_function

import os
from argparse import ArgumentParser

parser = ArgumentParser(description='Patch some header code generation, so it builds')
parser.add_argument("-f", "--file", required=True)
parser.add_argument("-p", "--patches", required=True)
parser.add_argument("-v", "--verbose", default=False, action="store_true")
parser.add_argument("-m", "--module", required=True)
args = parser.parse_args()

if os.path.isfile(args.patches):
    with open(args.file) as fin:
        lines = fin.readlines()

    patches = {}
    with open(args.patches) as fin:
        patches = eval(fin.read())

    all_lines = []
    for l in lines:
        l = l.replace(", ...arg0)", ", ...)")
        l = l.replace(",...arg0)", ",...)")
        all_lines.append(l)

    import sys
    import tempfile
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from _writeutil import move_if_different
    temp = tempfile.NamedTemporaryFile(mode="w", delete=False)
    temp.writelines(all_lines)
    temp.close()
    move_if_different(temp.name, args.file)
