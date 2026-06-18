# ARM64 Linux host -> x64 Linux target. Not currently exercised by IDA's CI
# or shipped SDK packaging; add the inverse of arm-Linux when needed.

message(FATAL_ERROR
    "x64 Linux target from an ARM64 Linux host is not yet supported. "
    "If you need this, please open an issue.")
