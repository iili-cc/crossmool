@echo off
set "INCLUDE=D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\14.41.34120\include;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\ucrt;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um"
set "LIB=D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\14.41.34120\lib\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\14.41.34120\bin\Hostx64\x64\cl.exe /nologo /O2 D:\workspaces\git\corssmool\crossmool\testcase\output\c_sm3_test.c /Fe:D:\workspaces\git\corssmool\crossmool\testcase\output\c_sm3_test.exe
if %ERRORLEVEL% equ 0 (
    D:\workspaces\git\corssmool\crossmool\testcase\output\c_sm3_test.exe
)
