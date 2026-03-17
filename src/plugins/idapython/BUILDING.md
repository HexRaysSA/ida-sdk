# Building From Source

## Build Requirements

- [IDA C++ SDK](https://github.com/HexRaysSA/ida-sdk#requirements) built first (via CMake or make)
- [Python 3.9–3.14](http://www.python.org/)
- [swig](https://www.swig.org/)
- zip, unzip

### Additional Windows Requirements

- [Cygwin](https://cygwin.com/) — provides `make`, `cygpath`, and other Unix tools needed by the build system
- Visual Studio 2022 with C++ workload
- The following environment variables must be set:
  - `VCINSTALLDIR` — Visual C++ install directory (e.g., `C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\`)
  - `WindowsSdkDir` — Windows SDK install directory (e.g., `C:\Program Files (x86)\Windows Kits\10\`)

> **Tip:** These are set automatically by the Visual Studio Developer Command Prompt or by running `vcvarsall.bat`.
>
> When setting manually:
> - cmd: `set "VCINSTALLDIR=C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\"`
> - PowerShell: `$env:VCINSTALLDIR = 'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\'`

## Runtime Requirements

- [IDA 9.2+](http://www.hex-rays.com/idapro/)

### SWIG

Simplified Wrapper Interface Generator (SWIG)

SWIG can be installed in different ways or built from sources. In the past, only building from sources was supported. These days you can use any method you prefer.

> Requires SWIG 4.2+
>
> Tested with 4.2.0 — the latest available via `apt` on Ubuntu 24.04
>
> Tested with 4.3.1 on Windows & Linux
>
> Tested with 4.4.1 on macOS

#### Install

SWIG can be installed using package managers on any platform.

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
setup-x86_64.exe -q -P zip -P unzip -P swig
```

Choco example:

```cmd
choco install zip unzip swig
```

> **Note:** On Windows there are no zip & unzip commands, so they can be installed with a package manager as well.

#### Build From Sources

On macOS & Linux, download the appropriate [swig sources](https://www.swig.org/download.html) and follow the README, which in essence says:

```shell
cd swig-<version>
./configure --prefix=$(pwd)
make
make install
```

If you face any problems, see the **Troubleshooting** section of the mentioned README.

On Windows, no build is required—just unpack and it's ready to use.

> **NOTE**: Do not move swig after building or rebuild after moving because
> SWiG do hardcore of library paths

## Building

1. Make sure all the [build requirements](#build-requirements) are on the PATH.

   > **Note:** If you want to build for a specific Python version (let's say Python 3.12), please set the following environment variables:
   >
   > - `PYTHON_VERSION_MAJOR=3`
   > - `PYTHON_VERSION_MINOR=12`
   >
   > If `PYTHON_VERSION_MINOR` is not set, `build.py` will use the version of the Python that runs it.
   >
   > On Windows, `build.py` also auto-detects `PYTHON_ROOT` from the running Python if not set. You can override it to point to a specific Python installation.
   >
   > See the default values in SDK's `allmake.mk`
   >
   >> How to:
   >>
   >> - Linux/macOS: `export PYTHON_VERSION_MAJOR=3; export PYTHON_VERSION_MINOR=12`
   >> - Windows cmd/bat: `set PYTHON_VERSION_MAJOR=3 && set PYTHON_VERSION_MINOR=11`
   >> - Windows PowerShell: `$env:PYTHON_VERSION_MAJOR=3; $env:PYTHON_VERSION_MINOR=12`

2. Make sure the [SDK is built](https://github.com/HexRaysSA/ida-sdk?tab=readme-ov-file#getting-started).

3. Build the plugin:

   ```shell
   python3 build.py
   ```

   You can also run `build.py --help` for more information.

## Plug In

1. Copy all `src/bin/plugins/idapython3.*` files to `<IDADIR>/plugins/`
2. Copy the entire `src/bin/python` directory to `<IDADIR>/`
3. Copy `idapython.cfg` to `<IDADIR>/cfg/` or `<IDAUSR>/cfg/`

> **Notes:**
>
> - [`IDADIR`](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/windows/environment-variables#idadir) is the IDA installation directory. On macOS the subpath is: `ida.app/Contents/MacOS/`
> - [`IDAUSR`](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/windows/environment-variables#idausr) is the IDA user-specific directory
