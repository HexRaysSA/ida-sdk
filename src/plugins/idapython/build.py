#!/usr/bin/env python
""" IDAPython - Python plugin for Interactive Disassembler

 (c) The IDAPython Team <https://github.com/HexRaysSA/ida-sdk/issues>

 All rights reserved.

 For detailed copyright information see the file COPYING in
 the root of the distribution archive.
---------------------------------------------------------------------
 build.py - CMake build driver
---------------------------------------------------------------------
 Configures and builds IDAPython against a released IDA SDK via
 find_package(idasdk). A convenience wrapper around:
   cmake -S . -B build -DIDASDK=<sdk> -DCMAKE_BUILD_TYPE=<type>
   cmake --build build --target idapython
"""
from __future__ import print_function

import argparse
import os
import shutil
import subprocess

from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
# This tree ships at <sdk>/plugins/idapython/, so the SDK root is two levels up.
DEFAULT_IDASDK = SCRIPT_DIR.parent.parent

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    epilog=r"""
A recent version of SWIG (4.2.0+) is required to produce reliable bindings. If
your platform's package manager ships an older SWIG, build 4.2.0+ from source and
pass its path with '--swig'.

Example build commands:

  # run from inside an SDK tree (SDK auto-detected), SWIG on PATH
  python3 build.py

  # explicit SDK + SWIG
  python3 build.py --idasdk ~/idasdk --swig /opt/swig-4.3.1/bin/swig
""")
parser.add_argument(
    "--idasdk", type=Path, default=os.environ.get("IDASDK") or DEFAULT_IDASDK,
    help="Path to a released IDA SDK (default: the SDK this tree ships in; "
         "or set the IDASDK env var).")
parser.add_argument(
    "--swig", type=Path, default=None,
    help="Path to the SWIG 4.2.0+ executable (default: SWIG env var or PATH)")
parser.add_argument(
    "--build-dir", type=Path, default=SCRIPT_DIR / "build",
    help="CMake build directory (default: ./build)")
parser.add_argument(
    "--debug", default=False, action="store_true",
    help="Build a debug version of the plugin (default: release)")
parser.add_argument(
    "-j", "--jobs", type=int, default=0,
    help="Allow N parallel jobs (default: let the build tool decide)")
parser.add_argument(
    "-v", "--verbose", default=False, action="store_true", help="Verbose mode")
parser_args = parser.parse_args()


def run(argv):
    """Run a subprocess, echoing the command."""
    print("Running: " + " ".join(str(a) for a in argv))
    subprocess.check_call([str(a) for a in argv])


def get_swig_or_raise():
    """Resolve the SWIG executable."""
    swig = parser_args.swig or os.environ.get("SWIG") or shutil.which("swig")
    if not swig:
        raise EnvironmentError(
            "SWIG executable not found. Install SWIG 4.2.0+ or pass --swig "
            "(or set the SWIG environment variable).")
    return str(Path(swig))


def main():
    """Configure and build IDAPython with CMake."""
    idasdk = Path(parser_args.idasdk).resolve()
    if not (idasdk / "cmake" / "idasdkConfig.cmake").is_file():
        parser.error(
            f"'{idasdk}' is not an IDA SDK (no cmake/idasdkConfig.cmake); "
            "pass --idasdk <sdk> or set the IDASDK env var.")

    build_dir = parser_args.build_dir
    build_type = "Debug" if parser_args.debug else "Release"

    configure = [
        "cmake", "-S", SCRIPT_DIR, "-B", build_dir,
        f"-DIDASDK={idasdk}",
        f"-DCMAKE_BUILD_TYPE={build_type}",
        f"-DIDA_SWIG={get_swig_or_raise()}",
    ]
    if shutil.which("ninja"):
        configure += ["-G", "Ninja"]
    run(configure)

    build = ["cmake", "--build", build_dir, "--target", "idapython"]
    if parser_args.jobs > 0:
        build += ["-j", str(parser_args.jobs)]
    if parser_args.verbose:
        build += ["--verbose"]
    print(f"### Building IDAPython plugin ({build_type})")
    run(build)


# -----------------------------------------------------------------------
if __name__ == "__main__":
    main()
