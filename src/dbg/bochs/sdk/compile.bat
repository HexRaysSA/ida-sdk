@echo off
"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\cl.exe" -c /Zl /Gd /Tc bxtest.c "/IC:/Program Files (x86)/Windows Kits/8.1/Include/um" "/IC:/Program Files (x86)/Windows Kits/8.1/Include/shared" "/IC:/PROGRA~2/WI3CF2~1/10/Include/10.0.10150.0/ucrt" /I"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\include"
if errorlevel 1 goto end
"C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\bin\link.exe" bxtest.obj bochsys.lib kernel32.lib user32.lib /OUT:bxtest.dll /ENTRY:Entry /def:bxtest.def /DRIVER /SAFESEH:NO /NODEFAULTLIB /SUBSYSTEM:WINDOWS /LIBPATH:"C:\Program Files\Microsoft Visual Studio 14.0\VC\Lib" /LIBPATH:"C:/Program Files (x86)/Windows Kits/8.1/Lib/winv6.3/um/x86"
if errorlevel 1 goto end

if exist bxtest.obj del bxtest.obj
if exist bxtest.exp del bxtest.exp
if exist bxtest.lib del bxtest.lib

:end