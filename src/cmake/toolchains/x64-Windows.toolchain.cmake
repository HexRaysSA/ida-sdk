# ARM64 Windows host -> x64 Windows target. Not currently exercised by
# IDA's CI or shipped SDK packaging.

message(FATAL_ERROR
    "x64 Windows target from an ARM64 Windows host is not yet supported. "
    "If you need this, please open an issue.")
