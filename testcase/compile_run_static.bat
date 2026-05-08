@echo off
call "H:\Programs\VisualStudio\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d "G:\workspaces\git\corssmool\crossmool\testcase"
cl.exe /I"G:\workspaces\git\corssmool\crossmool\c\crossmool\include" c_cross_verify_v2.c /Fe:c_cross_verify_v2_static.exe /link "G:\workspaces\git\corssmool\crossmool\c\crossmool\build_msvc\Release\crossmool.lib" advapi32.lib
if %ERRORLEVEL% EQU 0 (
    echo === Running test ===
    c_cross_verify_v2_static.exe
) else (
    echo === Compilation failed ===
)
