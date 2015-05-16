@echo off
"C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\bin\cl.exe" -c /Zl /Gd /Tc bxtest.c /I"C:\Program Files\Microsoft SDKs\Windows\v6.0A\Include" /I"C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\include"
"C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\bin\link.exe" bxtest.obj bochsys.lib kernel32.lib user32.lib /OUT:bxtest.dll /ENTRY:Entry /def:bxtest.def /DRIVER /SAFESEH:NO /NODEFAULTLIB /SUBSYSTEM:WINDOWS /LIBPATH:"C:\Program Files\Microsoft Visual Studio 9.0\VC\Lib" /LIBPATH:"C:\Program Files\Microsoft SDKs\Windows\v6.0A\Lib"

if exist bxtest.obj del bxtest.obj
if exist bxtest.exp del bxtest.exp
if exist bxtest.lib del bxtest.lib