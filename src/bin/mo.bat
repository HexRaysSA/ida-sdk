@echo off
setlocal
set __NT__=1
set __EA64__=1
set NDEBUG=1
make %*
