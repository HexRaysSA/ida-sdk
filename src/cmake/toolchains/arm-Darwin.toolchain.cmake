# x64 macOS host -> ARM64 macOS target. Xcode's universal SDK handles
# both architectures; just declare the target arch.

set(CMAKE_OSX_ARCHITECTURES arm64)
