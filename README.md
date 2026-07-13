# IDA SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![C++11](https://img.shields.io/badge/C++-17%2B-blue.svg)](https://isocpp.org/std/the-standard)  

A Software Development Kit for extending [IDA](https://hex-rays.com/ida-pro/), the state-of-the-art binary code analysis tool. The C++ SDK allows you to build custom plugins, loaders, processors, and scripts that integrate directly into IDA. This project also includes [IDAPython SDK](src/plugins/idapython/README.md) allowing you to write plugins using Python.  


## Documentation
- [IDA Documentation](https://docs.hex-rays.com/)
- [C++ Developer’s Guide](https://docs.hex-rays.com/developer-guide/c++-sdk)  
- [SDK reference](https://cpp.docs.hex-rays.com/)  
- Additional README files in subdirectories provide details for processor modules, loaders, and other components.

## Contributing

The SDK is currently closed to external contributions, as it requires tight integration with our proprietary IDA Pro workflows and follows an internal roadmap with specific architectural decisions.

However, feel free to report bugs or suggest features via [Issues](https://github.com/HexRaysSA/ida-sdk/issues).

## Versioning

Git tags use [semver](https://semver.org/)-compatible syntax to track both IDA product releases and independent SDK updates:

| Tag pattern | Meaning |
|---|---|
| `vX.Y.Z-release` | SDK snapshot shipped with an IDA release |
| `vX.Y.Z-sdk.N` | SDK-only update between IDA releases (build system, docs, examples, etc.) |

`X.Y.Z` matches the IDA version that the SDK targets. The pre-release suffix distinguishes the type of change:

- **`-release`** marks the exact SDK state shipped with a given IDA version.
- **`-sdk.N`** marks subsequent SDK improvements that still target the same IDA version. `N` increments with each update.

**Sort order.** Semver compares pre-release identifiers lexically, so `-release` sorts before `-sdk.N` (`r` < `s`), which gives the correct chronological order:

```
v9.3.0-release        ← IDA 9.3.0 ships, SDK updated to match
v9.2.0-sdk.2          ← second SDK-only update for IDA 9.2.0
v9.2.0-sdk.1          ← first SDK-only update (e.g., CMake support added)
v9.2.0-release        ← IDA 9.2.0 ships (initial commit)
```

**Note:** In strict semver, a pre-release version (e.g., `v9.3.0-release`) has lower precedence than the corresponding normal version (`v9.3.0`). Since this repository never publishes bare `vX.Y.Z` tags, the ordering among tagged versions is unambiguous and correct.

## Requirements

To build:

- **CMake 3.25 or later**
- **C++ compiler** that fully supports C++17 compatible with your platform:
    - GCC or LLVM/Clang (Linux/macOS)
    - Microsoft Visual C++ (MSVC) 2022 or later (Windows)

To use the SDK:

- **IDA 9.2**

## Repository fundamentals 

- `src/module/` — Processor modules  
- `src/ldr/` — Loader modules  
- `src/include/` — Core IDA SDK headers  
- `src/lib/` — Stub libraries for linking against IDA kernel  
- `src/dbg/` — Debugger server integration  
- `src/bin/` — Build helpers & binaries  
- `src/idalib/` — IDA as a library examples  
- `src/plugins/` — Sample plugin modules (including IDAPython)  

## Getting Started

**CMake is the supported build system for the IDA SDK.**

To install the project on your local machine, refer to the instructions in [src/readme.txt](src/readme.txt).
Additional README files in subdirectories provide more details about:

- Processor module templates
- Loaders
- Other components

### Building

**Basic build:**

Linux/macOS/Windows:
```shell
cd src/
cmake -B build -G Ninja
cmake --build build
```

**Generator choice (use Ninja).** Ninja is the recommended generator on every
platform, including Windows. It is a *single-config* generator: the build type
is fixed at configure time (this SDK defaults `CMAKE_BUILD_TYPE` to `Release`),
and build outputs land directly in `bin/plugins`, `bin/procs`, etc. On Windows,
run the configure/build from a Visual Studio Developer Command Prompt (or any
shell where `cl.exe` is on `PATH`); the SDK also auto-detects MSVC via
`cmake/find_msvc.cmake`.

> **Known issue - the default "Visual Studio" generator.** If you omit `-G` on
> Windows, CMake picks the *multi-config* Visual Studio generator, which behaves
> differently and is **not recommended** for this SDK:
>
> - It ignores `CMAKE_BUILD_TYPE`; you must pass `--config Release` at build
>   time. Without it the build defaults to **Debug**, whose debug-CRT objects
>   (`/MDd`, `_ITERATOR_DEBUG_LEVEL=2`) fail to link against the **Release-only**
>   stub libs shipped in `src/lib/` (`LNK2038` / `LNK1120`,
>   `__imp__CrtDbgReport`).
> - Even with `--config Release`, it nests outputs under a per-config subfolder
>   (`bin/plugins/Release/...`) instead of `bin/plugins/...`, which can confuse
>   tooling and scripts that expect the flat layout.
>
> Both problems disappear with `-G Ninja`.

**Presets (optional):** `src/CMakePresets.json` defines ready-made configurations:

| Preset | Description |
|---|---|
| `native` | Full SDK build (host arch, 64-bit address space) |
| `dbgserver` | Debug server only (host arch, 64-bit address space) |
| `dbgserver-ea32` | Debug server only (32-bit address space) |
| `arm` | Cross-compile to ARM (from x64 Linux/Windows host) |
| `x64` | Cross-compile to x64 (from ARM macOS host) |
| `arm-dbgserver` | Debug server only, ARM target (64-bit address space) |
| `x64-dbgserver` | Debug server only, x64 target (64-bit address space) |
| `x64-dbgserver-ea32` | Debug server only, x64 target (32-bit address space) |

Each preset is only offered when its host condition matches, so unavailable
cross-compile presets are hidden on the current host.

```shell
cd src/
cmake --preset dbgserver
cmake --build --preset dbgserver
```

The cross-compile toolchains live under
[src/cmake/toolchains/](src/cmake/toolchains/). Targeting ARM Linux from an x64
Linux host additionally needs an aarch64 sysroot, for example:

```shell
cd src/
cmake --preset arm -DCMAKE_SYSROOT=/usr/aarch64-linux-gnu
cmake --build --preset arm
```

**Qt samples.** The Qt-based samples (such as `plugins/qwindow`) call
`find_package(Qt6 ...)` and are built only when a matching Qt6 is discoverable
through the usual CMake mechanisms (`CMAKE_PREFIX_PATH`, `Qt6_DIR`, or a system
install). If no Qt6 is found the target is skipped silently - the rest of the
build is unaffected.

Cross-compiling Qt plugins does **not** work out of the box: Qt's build tools
(`moc`, `rcc`, `uic`) must run on the build host, so a target-only Qt in the
sysroot is not enough - you also need a host Qt of the same version, pointed to
with `QT_HOST_PATH`:

```shell
cd src/
cmake --preset arm -DCMAKE_SYSROOT=$HOME/arm64-cr-sysroot \
      -DQT_HOST_PATH=/path/to/host/Qt/6.8.0/<host-arch>
cmake --build --preset arm
```

If you do not need the Qt samples, skip them entirely instead with
`-DIDACMAKE_SKIP_QT=ON`:

```shell
cd src/
cmake --preset arm -DCMAKE_SYSROOT=$HOME/arm64-cr-sysroot -DIDACMAKE_SKIP_QT=ON
cmake --build --preset arm
```

Build options can be passed with `-D`, for example `-DIDA_WARNINGS=all` (one of
`none`, `default`, `all`), or `-DIDA_BUILD_IDA=OFF -DIDA_BUILD_DBGSRV=ON` to
build only the debugger server tree. The CMake package and its options live
under [src/cmake/](src/cmake/) (entry point `src/cmake/idasdkConfig.cmake`).

### Building your own plugin, loader, or processor module

The build API - `ida_add_plugin`, `ida_add_loader`, `ida_add_procmod`,
`ida_add_idalib` - is the same whether you build inside the SDK tree or from a
separate project of your own. Choose whichever fits your workflow.

**1. In-tree (alongside the bundled examples).**

Put your sources in a folder under the matching example tree and add a
`CMakeLists.txt` next to them. For a plugin in `src/plugins/myplugin/`:

```cmake
# src/plugins/myplugin/CMakeLists.txt
ida_add_plugin(myplugin SOURCES myplugin.cpp)
```

Then register that folder by adding one line to the parent listfile,
`src/plugins/CMakeLists.txt`:

```cmake
add_subdirectory(myplugin)
```

Loaders live under `src/ldr/` and processor modules under `src/module/`, each
registered the same way from the respective parent `CMakeLists.txt`. A regular
SDK build then picks the new component up automatically.

**2. Out-of-tree, using the init helper (recommended).**

Keep your component in its own repository/folder and point it at an SDK
checkout. Include `idasdk_init.cmake` *before* `project()` - it resolves the
SDK location, makes `find_package(idasdk)` reachable, and preselects MSVC on
Windows (so no Developer Command Prompt is required):

```cmake
cmake_minimum_required(VERSION 3.25)

include("$ENV{IDASDK}/src/cmake/idasdk_init.cmake")  # before project()

project(myplugin CXX)
find_package(idasdk REQUIRED)

ida_add_plugin(myplugin SOURCES myplugin.cpp)
```

Build it with `IDASDK` pointing at your SDK checkout (the directory that
contains `src/`):

```shell
IDASDK=/path/to/ida-sdk cmake -B build -G Ninja
cmake --build build
```

By default the result is written to `$IDASDK/bin/{plugins,loaders,procs}`. To
direct it elsewhere, set `IDABIN` (environment variable or `-DIDABIN=/your/out`).

**3. Out-of-tree, using `find_package` directly.**

If you would rather not use the init helper, add the package directory to
`CMAKE_PREFIX_PATH` yourself. In this form MSVC must already be configured in
the shell (e.g. a Visual Studio Developer Command Prompt) on Windows:

```cmake
cmake_minimum_required(VERSION 3.25)
project(myplugin CXX)

list(PREPEND CMAKE_PREFIX_PATH "$ENV{IDASDK}/src/cmake")
find_package(idasdk REQUIRED)

ida_add_plugin(myplugin SOURCES myplugin.cpp)
```

### Run

Depending on your build process, some binaries in `src/bin` may run out of the box. Others may need to be moved to your IDA installation directory.

To use custom-built plugins, you must place them in a location recognized by IDA. You can do this in one of the following ways:

- **Copy plugins manually**

    Copy the contents of `src/bin/plugins/` to:

    - `~/.idapro/plugins/` on **Linux/macOS**
    - `%APPDATA%\Hex-Rays\IDA Pro\plugins\` on **Windows**

    Be careful not to overwrite existing plugins.

- **Use the `IDAUSR` environment variable**

    Set or extend the [`IDAUSR`](https://docs.hex-rays.com/user-guide/user-interface/menu-bar/windows/environment-variables) environment variable to include the `src/bin` path.

- **Install directly to the IDA directory**

    Copy the contents of `src/bin/plugins/` to `<your IDA installation>/plugins/`.
    Be cautious about overwriting existing files.

For more details, see the [Getting Started Documentation](https://docs.hex-rays.com/developer-guide/c++-sdk/c++-sdk-getting-started).

## Build Documentation

To build the documentation locally:

### Install Tools

#### macOS
```bash
brew install doxygen graphviz
```

#### Linux (Debian/Ubuntu)
```bash
sudo apt install doxygen graphviz
```

#### Windows
- Download Doxygen installer from [doxygen.nl](https://www.doxygen.nl/download.html).
- Install Graphviz separately and add it to PATH.

---

### Building Documentation

From docs folder:
```bash
doxygen Doxyfile
```

Output will appear in:
- `docs/build/` 

### Online Documentation

The latest documentation is available at: [https://cpp.docs.hex-rays.com/](https://cpp.docs.hex-rays.com/)


## Related Projects

### Python SDK

The following previous IDAPython repositories have now been archived and moved into this project [IDAPython](src/plugins/idapython/README.md):

- ~~https://github.com/idapython/src~~
- ~~https://github.com/HexRaysSA/IDAPython~~

For more information, refer to the [IDAPython documentation](https://docs.hex-rays.com/developer-guide/idapython)

## Support

For commercial support or licensing inquiries, contact: support@hex-rays.com

For community help, visit:
[IDA Users Forum](https://community.hex-rays.com/c/idas/api-sdk/15)


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The SDK CMake support is based on Elias Bachaalany's [allthingsida/ida-cmake](https://github.com/allthingsida/ida-cmake) project (commit
[06e2b64](https://github.com/allthingsida/ida-cmake/tree/06e2b64ddcb2ba6fdf87b4579f298bf054231960)), and maintains compatibility with its interface. Thanks, Elias!
