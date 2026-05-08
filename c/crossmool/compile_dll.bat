@echo off
cd /d g:\workspaces\git\corssmool\crossmool\c\crossmool
call H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat
if errorlevel 1 (
    echo Failed to initialize Visual Studio environment
    exit /b 1
)
echo Compiling crossmool.dll...
cl /EHsc /std:c11 /I include /I GmSSL/include /LD src/sm2.c GmSSL/lib/libgmssl.lib /Fe:build_msvc\Release\crossmool.dll /Fo:build_msvc\Release\
if errorlevel 1 (
    echo Compilation failed
    exit /b 1
)
echo Compilation successful
dir build_msvc\Release\crossmool.dll
