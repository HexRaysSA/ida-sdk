#!/usr/bin/env python
""" IDAPython - Python plugin for Interactive Disassembler

 (c) The IDAPython Team https://github.com/HexRaysSA/ida-sdk/issues

 All rights reserved.

 For detailed copyright information see the file COPYING in
 the root of the distribution archive.
---------------------------------------------------------------------
 build.py - Makefile wrapper script
---------------------------------------------------------------------
"""
from __future__ import print_function

import argparse
import os
import shutil
import subprocess

from pathlib import Path

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    epilog=r"""
A very specific version of SWiG is expected in order to produce reliable
bindings. If your platform doesn't provide that version by default and you
had to build/install it yourself, you will have to specify '--swig-home'.

What follows, are example build commands

# Windows
Assume SWiG is installed with `winget swig` in the default place and added to PATH
and IDA is in C:/Program Files/IDA Professional 9.2

  python3 build.py --ida-install "C:/Program Files/IDA Professional 9.2"

If swig is not in the PATH
For simplicity next parts replaced with "<path_to_swig>":
- cmd/bat: %LOCALAPPDATA%/Microsoft/WinGet/Packages/
    SWIG.SWIG_Microsoft.Winget.Source_<hash>/swigwin-4.3.1/
- powershell: $env:LOCALAPPDATA/Microsoft/WinGet/Packages/
    SWIG.SWIG_Microsoft.Winget.Source_<hash>/swigwin-4.3.1/

  python3 build.py \
      --swig "<path_to_swig>/swig.exe" \
      --ida-install "C:/Program Files/IDA Professional 9.2"

# Linux/OSX
Assume SWiG is installed with package manager and the executable is /bin/swig,
and IDA is in /opt/my-ida-install

  python3 build.py --ida-install /opt/my-ida-install

If want use swig build from the sources
  python3 build.py --swig "<path_to_swig_executable>" \
    --ida-install /opt/my-ida-install
""")
parser.add_argument(
    "--swig", type=Path, default=None, help="Path to the SWIG executalbe")
parser.add_argument(
    "--debug", default=False, action="store_true",
    help="Build debug version of the plugin",
)
parser.add_argument(
    "-j", "--jobs", type=int,
    help="Allow N jobs at once; infinite jobs with no arg.", default=0,
)
parser.add_argument(
    "-v", "--verbose", help="Verbose mode", default=False, action="store_true")
parser.add_argument(
    "-I", "--ida-install", required=True, type=Path,
    help="IDA's installation directory",
)
parser_args = parser.parse_args()


def run(proc_argv, env=None):
    """Runs subprocess"""
    cmd = " ".join(proc_argv)
    print(f"Running: \"{cmd}\", with additional environment: \"{env}\"")
    full_env = os.environ.copy()
    full_env.update(env)
    subprocess.check_call(proc_argv, env=full_env)
    return 0


def get_swig_or_raise():
    """Get path to swig trying to find it"""
    swig = parser_args.swig or os.environ.get("SWIG") or shutil.which("swig")

    if not swig:
        raise EnvironmentError(
            "SWIG executable not found. Please install SWIG or provide "
            "its path to this script with --swig or set SWIG environment "
            "variable"
        )
    return str(Path(swig))


def main():
    """Execute IDAPython build"""
    env = {
        "OUT_OF_TREE_BUILD" : "1",
        "IDA_INSTALL": str(parser_args.ida_install),
        "SWIG": get_swig_or_raise(),
    }
    argv = ["make"]
    if parser_args.jobs > 0:
        argv.append(f"-j{parser_args.jobs}")
    if not parser_args.debug:
        env["NDEBUG"] = "1"
    if parser_args.verbose:
        argv.append("-d")
    print("### Building IDAPython plugin")
    run(argv, env=env)

# -----------------------------------------------------------------------
if __name__ == "__main__":
    main()
