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
import platform
import shutil
import subprocess
import sys

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

  python3 build.py

If swig is not in the PATH
For simplicity next parts replaced with "<path_to_swig>":
- cmd/bat: %LOCALAPPDATA%/Microsoft/WinGet/Packages/
    SWIG.SWIG_Microsoft.Winget.Source_<hash>/swigwin-4.3.1/
- powershell: $env:LOCALAPPDATA/Microsoft/WinGet/Packages/
    SWIG.SWIG_Microsoft.Winget.Source_<hash>/swigwin-4.3.1/

  python3 build.py --swig "<path_to_swig>/swig.exe"

# Linux/OSX
Assume SWiG is installed with package manager and the executable is /bin/swig

  python3 build.py

If want use swig build from the sources
  python3 build.py --swig "<path_to_swig_executable>"
""")
parser.add_argument(
    "--swig", type=Path, default=None, help="Path to the SWIG executable")
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
    "-I", "--ida-install", required=False, type=Path, default=None,
    help="IDA's installation directory. Required for idapyswitch\n"
         "and docs generation (idat); not needed for compilation only.",
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
        "SWIG": get_swig_or_raise(),
    }
    if parser_args.ida_install:
        env["IDA_INSTALL"] = str(parser_args.ida_install)
    applied_minor = os.environ.get("PYTHON_VERSION_MINOR",
                                   str(sys.version_info.minor))
    env["PYTHON_VERSION_MINOR"] = applied_minor
    if "PYTHON_ROOT" not in os.environ and platform.system() == "Windows":
        env["PYTHON_ROOT"] = str(Path(sys.executable).parent)
    argv = ["make"]
    if parser_args.jobs > 0:
        argv.append(f"-j{parser_args.jobs}")
    else:
        argv.append("-j")
    if not parser_args.debug:
        env["NDEBUG"] = "1"
    if parser_args.verbose:
        argv.append("-d")
    # On Windows, generate the MSVC .cfg files first (needed by the makefile)
    if platform.system() == "Windows":
        sdk_dir = os.environ.get("SDK_DIR", str(Path(__file__).resolve().parent.parent.parent))
        print("### Generating MSVC environment config")
        run(["make", "-C", sdk_dir, "NDEBUG=1", "env_vc"], env=env)

    print(f"### Building IDAPython plugin for Python 3.{applied_minor}")
    run(argv, env=env)

# -----------------------------------------------------------------------
if __name__ == "__main__":
    main()
