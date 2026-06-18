# ARM64 macOS host -> x64 macOS target. Xcode's universal SDK handles
# both architectures; just declare the target arch.

set(CMAKE_OSX_ARCHITECTURES x86_64)
