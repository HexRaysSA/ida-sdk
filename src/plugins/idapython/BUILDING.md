# Building From Source

## Build Requirements

- A released [IDA SDK](https://github.com/HexRaysSA/ida-sdk). IDAPython lives
  inside the SDK and consumes it via `find_package(idasdk)`, so the SDK is
  auto-detected when you build in place.
- [CMake](https://cmake.org/) 3.25+ and a generator (Ninja recommended)
- [Python 3.9-3.14](http://www.python.org/) with development headers - plus its
  `venv` + `pip` if SWIG is auto-installed (see below; e.g. Debian's `python3-venv`)
- [SWIG](https://www.swig.org/) - installed from PyPI by default (see below); no
  compiler or autotools needed, just a Python with `venv` + `pip`

### Additional Windows Requirements

- Visual Studio 2022 with the C++ workload. `vcvarsall.bat` is not required
  either way: with the Ninja generator MSVC is auto-detected (via vswhere); with
  the default Visual Studio generator CMake locates MSVC itself.

## Runtime Requirements

- An [IDA](https://www.hex-rays.com/ida-pro) install matching the SDK version you
  built against

### Python

Python 3.9 to 3.14 is supported. The build takes the **lowest** version installed
in that range: the wrappers target the 3.9 limited API, so a module built against
the oldest supported Python also loads in every newer one. To choose another, pass
any of:

- `-DPython3_EXECUTABLE=<path>` - CMake's own knob
- `-DIDA_PYTHON=<path>` - the same effect
- `-DIDA_PYTHON_VERSION_MINOR=<n>` - exact minor, e.g. `12` for 3.12

Only `Development.Module` (the headers) is needed, not a full `Development`
install. On Windows the stable-ABI `python3.lib` is generated from a `.def` shipped
with the SDK, so no Python development files are required there at all.

### SWIG

Simplified Wrapper Interface Generator (SWIG).

By default the build first looks for an existing SWIG (>= 4.2.0) via
`find_package(SWIG)`; only if none is found does it install SWIG 4.4.1 from PyPI
(the `swig` wheel) into a venv in the build folder - the first release with arm
wheels, so this covers every platform we target (incl. Windows and macOS on arm)
and needs only a Python with `venv` + `pip` and network access the first time -
no compiler or autotools.

Overrides:
- `-DIDA_SWIG=/path/to/swig` (or `build.py --swig <path>`) - use this exact binary.
- `-DIDA_SWIG_FROM_PYPI=ON` - skip the search and install from PyPI.
- `-DIDA_SWIG_VERSION=<x.y.z>` - use exactly this version: an installed one is
  accepted only if it matches, otherwise that version is installed from PyPI.

SWIG runs are cached with `ccache-swig` when one is available (next to `swig` or on
the `PATH`); the PyPI wheel ships none, so a pip-provisioned swig runs uncached.
The cache lives in `~/.ccache` - `$HOME/.ccache`, or `%USERPROFILE%\.ccache` on
Windows - and is created if missing, which ccache-swig itself will not do (it fails
outright on a missing directory). To put it elsewhere, either pass
`-DIDA_SWIG_CCACHE_DIR=<dir>` or set `CCACHE_DIR` in the environment; both override
the default. On Windows with a roaming profile, prefer a machine-local path so the
cache is not synced:

```cmd
cmake -B build -DIDA_SWIG_CCACHE_DIR=%LOCALAPPDATA%\.ccache
```

Turn caching off with `-DIDA_SWIG_CACHE=OFF`.

> Tested with 4.2.0 - the latest available via `apt` on Ubuntu 24.04
>
> Tested with 4.3.1 on Windows & Linux
>
> Tested with 4.4.1 on macOS

#### Known issues

- Always take the latest patch release of whichever SWIG minor you use.
- **SWIG 4.4.0 with Python 3.13 or 3.14** does not build: 4.4.0 emits
  `PyImport_AddModuleRef()` guarded on the Python version alone, but 3.13+ declares
  it only when `Py_LIMITED_API` is unset or `>= 0x030d0000`, and IDAPython builds
  against the 3.9 limited API. Use 4.4.1 or newer, or stay on 4.3.x. A 4.4.0
  already on the `PATH` satisfies the 4.2.0 minimum and will be picked up, so pass
  `-DIDA_SWIG` or `-DIDA_SWIG_VERSION` if you have one installed.
- **On arm hosts the auto-install needs 4.4.1+**, the first release with arm
  wheels. An older SWIG there has to come from a package manager or a local build,
  and be passed with `-DIDA_SWIG`.

The rest of this section is only relevant if you provide your own SWIG.

#### Install

The easiest cross-platform way is the SWIG pip wheel, which bundles the binary:

```shell
python3 -m venv /tmp/swig421 && /tmp/swig421/bin/pip install swig==4.2.1
```

Then point the build at it with `-DIDA_SWIG=/tmp/swig421/bin/swig` (on Windows,
`...\Scripts\swig.exe`) - or `build.py --swig <path>` - or just add it to the `PATH`.

Or use a package manager:

##### Linux

You can use your package manager: `dnf`, `apt` or `yum`

Ubuntu example:

```shell
sudo apt install swig
```

##### macOS

You can use [brew](https://brew.sh/):

```shell
brew install swig
```

##### Windows

You can use any package manager:

- winget (part of Windows since version 10)
- [cygwin](https://cygwin.com/install.html)
- [Chocolatey](https://chocolatey.org/)
- Scoop

winget example:

```cmd
winget install swig
```

Cygwin example:

```cmd
setup-x86_64.exe -q -P swig
```

Choco example:

```cmd
choco install swig
```

#### Build From Sources

On macOS & Linux, download the appropriate [swig sources](https://www.swig.org/download.html) and follow the README, which in essence says:

```shell
cd swig-<version>
./configure --prefix=$(pwd)
make
make install
```

If you face any problems, see the **Troubleshooting** section of the mentioned README.

On Windows, no build is required - just unpack and it's ready to use.

> **NOTE**: Do not move swig after building or rebuild after moving because
> SWiG do hardcore of library paths

## Building

Make sure the [build requirements](#build-requirements) are on the `PATH`.

Because IDAPython ships inside the SDK, the SDK is auto-detected from this
directory's location - so from an unpacked SDK you can just:

```shell
cmake -B build && cmake --build build
```

That uses CMake's default generator (Unix Makefiles, or the Visual Studio
generator on Windows). Ninja is recommended for faster builds - add `-G Ninja`
(`build.py` picks it up automatically when `ninja` is on the `PATH`):

```shell
cmake -B build -G Ninja && cmake --build build
```

Or use the convenience wrapper (same defaults):

```shell
python3 build.py
```

To build against a different SDK, or when building outside an SDK tree, pass it
explicitly (or set the `IDASDK` environment variable):

```shell
cmake -B build -DIDASDK=/path/to/idasdk && cmake --build build
# or: python3 build.py --idasdk /path/to/idasdk
```

Notes:

- The build uses the Python 3 that `find_package(Python3)` discovers (normally
  the first `python3` on the `PATH`); override with `-DPython3_EXECUTABLE=...`.
- SWIG is found via `find_package(SWIG)` and only installed from PyPI as a fallback;
  override with `-DIDA_SWIG=/path/to/swig` (or `build.py --swig ...`), or force the
  PyPI install with `-DIDA_SWIG_FROM_PYPI=ON`.
- Output is written to `build/bin/` and, by default, also merged into the SDK's
  `bin/` (disable with `-DIDAPYTHON_DEPLOY_TO_SDK=OFF`).

## Plug In

The build output lives in `build/bin/` (and, unless disabled, is also merged into
the SDK's `bin/`). To install it into an IDA:

1. Copy `build/bin/plugins/idapython3.*` to `<IDADIR>/plugins/`
2. Copy the entire `build/bin/python` directory to `<IDADIR>/`
3. Copy `idapython.cfg` to `<IDADIR>/cfg/` or `<IDAUSR>/cfg/`

> **Notes:**
>
> - [`IDADIR`](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/windows/environment-variables#idadir) is the IDA installation directory. On macOS the subpath is: `ida.app/Contents/MacOS/`
> - [`IDAUSR`](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/windows/environment-variables#idausr) is the IDA user-specific directory
