@echo off
call "H:\Programs\VisualStudio\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
echo === VC Ready ===
cd /d "G:\workspaces\git\corssmool\crossmool\testcase"
cl.exe /I"G:\workspaces\git\corssmool\crossmool\c\crossmool\include" c_cross_verify_v2.c /Fe:c_cross_verify_v2.exe /link "G:\workspaces\git\corssmool\crossmool\c\crossmool\build\Release\crossmool.lib" 2>&1
echo === Compile done, errorlevel=%errorlevel% ===
if %errorlevel% equ 0 (
    c_cross_verify_v2.exe
    echo === Run done ===
) else (
    echo === Build Failed ===
)
