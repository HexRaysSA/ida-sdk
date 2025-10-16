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

## Requirements

To build:

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

To install the project on your local machine, refer to the instructions in [src/readme.txt](src/readme.txt).
Additional README files in subdirectories provide more details about:

- Processor module templates
- Loaders
- Other components

If all [requirements](#requirements) are met, you can install the project using the following commands:

Linux/macOS:
```shell
cd src/
make
```

Windows:
```cmd
cd src/
bin/mo.bat
```

### Debugger Servers

This SDK does not provide debugger servers for macOS.

Building Debugger Servers on Linux:
```shell
cd src/
BUILD_DBGSRV=1 make
```

Building Debugger Servers on Windows:
```cmd
cd src\
bin\mso.bat   :: will build win64_remote.exe
bin\m32x86so.bat :: will build win32_remote32.exe
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
