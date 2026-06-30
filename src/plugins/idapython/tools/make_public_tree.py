"""
Assemble the public ("out-of-tree") IDAPython source tree.

This is the CMake-era reimplementation of the old `public_tree` makefile
target. It produces the GitHub-shippable IDAPython source tree: the same
sources we build in-house, minus internal-only files, plus the
doxygen-parsed notifications already generated. Shipping the parsed
notifications lets external users build IDAPython against the released SDK
without installing or configuring doxygen.

Unlike the old target (which shelled out to rsync + zip, Unix only), this
is plain Python and runs identically on every platform. The exclude list
below is the single source of truth for what is internal-only.
"""

import argparse
import os
import shutil
import sys
from fnmatch import fnmatch

# Directories pruned wherever they appear in the tree.
PRUNE_DIRS = {
    "tests",            # in-house kernel/UI test inputs
    "examples-internal",
    "fuzzer",
    "precompiled",
    "obj",              # legacy make build output
    "build",            # cmake build output
    "__pycache__",
    ".git",
    ".pytest_cache",
    "hr-html",          # docs/hr-html: internal rendered docs
}

# Files pruned wherever they appear in the tree.
PRUNE_FILES = {
    "RELEASE.md",       # internal release instructions
    "CLAUDE.md",        # internal dev/agent instructions
    "test_idc.py",
    "copy_docs_to_p4.sh",
    "new_doxygen.txt",
    "repl.py",
    "makedep.cfg",      # legacy make dependency config
    "options.lnt",      # PC-lint config (cannot lint out-of-tree)
}

# Glob patterns pruned wherever they appear.
PRUNE_GLOBS = ["*~", "*.pyc", "*.orig", "*.rej"]


def _ignore(_dirpath, names):
    ignored = set()
    for name in names:
        if name in PRUNE_DIRS or name in PRUNE_FILES:
            ignored.add(name)
        elif any(fnmatch(name, pat) for pat in PRUNE_GLOBS):
            ignored.add(name)
    return ignored


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--src", required=True,
                    help="IDAPython source directory")
    ap.add_argument("--out", required=True,
                    help="output public-tree directory (wiped and recreated)")
    ap.add_argument("--parsed-notifications",
                    help="generated parsed_notifications dir to bundle under "
                         "out_of_tree/ (so users do not need doxygen)")
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    out = os.path.abspath(args.out)
    if not os.path.isdir(src):
        sys.exit("error: --src is not a directory: %s" % src)
    if os.path.commonpath([src, out]) == src:
        sys.exit("error: --out must not live inside --src: %s" % out)

    if os.path.exists(out):
        shutil.rmtree(out)
    shutil.copytree(src, out, ignore=_ignore)

    pn = args.parsed_notifications
    if pn:
        pn = os.path.abspath(pn)
        if not os.path.isdir(pn):
            sys.exit("error: --parsed-notifications is not a directory: %s" % pn)
        dst = os.path.join(out, "out_of_tree",
                           os.path.basename(pn.rstrip("/\\")))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copytree(pn, dst, ignore=_ignore)

    print("public tree assembled at %s" % out)


if __name__ == "__main__":
    main()
