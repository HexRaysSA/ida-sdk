
import os
import sys
import string

from argparse import ArgumentParser
p = ArgumentParser()
p.add_argument("-i", "--input",    required=True,  dest="input",         help="Input file")
p.add_argument("-o", "--output",   required=True,  dest="output",        help="Output file")
p.add_argument("-I", "--includes", required=True)
args = p.parse_args()

# INPUT_FILTER that blanks #include lines, to work around a doxygen 1.16+
# content-loss bug (see doxy_strip_includes.py). Run with the same
# interpreter that runs this script. -S skips site init: the filter is
# spawned once per header, so faster startup cuts the doxygen step's time.
strip_script = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "doxy_strip_includes.py")
out_dir = os.path.dirname(os.path.abspath(args.output))
if os.name == "nt":
    # doxygen runs INPUT_FILTER via cmd.exe, which strips a leading quote
    # from the command line. A quoted python path (e.g. under "C:\Program
    # Files\...") would therefore break. Point INPUT_FILTER at an unquoted,
    # space-free wrapper .bat that quotes the real paths internally.
    wrapper = os.path.join(out_dir, "doxy_input_filter.bat")
    with open(wrapper, "w") as fbat:
        fbat.write("@echo off\r\n")
        fbat.write('"%s" -S "%s" %%*\r\n'
                   % (sys.executable.replace("/", "\\"),
                      strip_script.replace("/", "\\")))
    input_filter = wrapper.replace("\\", "/")
else:
    input_filter = '"%s" -S "%s"' % (sys.executable, strip_script)

with open(args.input) as fin:
    with open(args.output, "w") as fout:
        template = string.Template(fin.read())
        kvps = {
            "INCLUDES" : " ".join(args.includes.split(",")),
            "INPUT_FILTER" : input_filter,
            }
        fout.write(template.safe_substitute(kvps))
