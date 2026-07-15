# Building From Source

## Build Requirements

- A released [IDA SDK](https://github.com/HexRaysSA/ida-sdk). IDAPython lives
  inside the SDK and consumes it via `find_package(idasdk)`, so the SDK is
  auto-detected when you build in place.
- [CMake](https://cmake.org/) 3.25+ and a generator (Ninja recommended)
- [Python 3.9-3.14](http://www.python.org/) with development headers
- [SWIG 4.2.0+](https://www.swig.org/)

### Additional Windows Requirements

- Visual Studio 2022 with the C++ workload. `vcvarsall.bat` is not required
  either way: with the Ninja generator MSVC is auto-detected (via vswhere); with
  the default Visual Studio generator CMake locates MSVC itself.

## Runtime Requirements

- An [IDA](https://www.hex-rays.com/ida-pro) install matching the SDK version you
  built against

### SWIG

Simplified Wrapper Interface Generator (SWIG)

SWIG can be installed in different ways or built from sources. In the past, only building from sources was supported. These days you can use any method you prefer.

> Requires SWIG 4.2.0+
>
> Tested with 4.2.0 - the latest available via `apt` on Ubuntu 24.04
>
> Tested with 4.3.1 on Windows & Linux
>
> Tested with 4.4.1 on macOS

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
- If `swig` is not on the `PATH`, pass `-DIDA_SWIG=/path/to/swig` (or
  `build.py --swig ...`).
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
