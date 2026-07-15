from __future__ import print_function

import sys
import os
import glob

from argparse import ArgumentParser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _writeutil import write_if_different

parser = ArgumentParser()
parser.add_argument("-i", "--input", required=True)
parser.add_argument("-o", "--output", required=True)
parser.add_argument("-s", "--sdk", required=True)
args = parser.parse_args()


with open(args.input) as fin:
    parts = []

    def add_imports_from_dep(depname):
        DEPNAME = depname.upper()
        for dep in glob.glob(os.path.join(args.sdk, "%s.*" % depname)):
            parts.append("  #ifdef HAS_DEP_ON_INTERFACE_%s" % DEPNAME)
            parts.append("  %import \"{0}.i\"".format(depname))
            parts.append("  #else")
            parts.append("  %import \"{0}\"".format(os.path.basename(dep)))
            parts.append("  #endif")
            parts.append("")

    parts.append("#if defined(IDA_MODULE_PRO)")
    parts.append("// nothing; has to be handled in pro.i")
    parts.append("#else")
    required_headers = ["pro", "ida", "xref", "typeinf", "enum", "netnode", "range", "lines", "kernwin", "bytes", "auto", "nalt", "idd", "idp", "gdl"]
    # required_headers = ["pro", "ida", "xref", "typeinf", "enum", "netnode", "range", "lines", "kernwin", "bytes", "auto", "nalt", "idd", "idp", "dirtree"]
    for rh in required_headers:
        add_imports_from_dep(rh)
    parts.append("#endif")

    template = fin.read()
    write_if_different(args.output, template.replace("${ALL_IMPORTS}", "\n".join(parts)))
