@echo off
setlocal
set __NT__=1
set __XPCOMPAT__=1
set __EA64__=1
set USE_STATIC_RUNTIME=1
set NDEBUG=1
make %*
