@echo off
chcp 65001 >nul
cd /d g:\workspaces\git\corssmool\crossmool

echo === Checking VsDevCmd.bat paths ===

set "path1=H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"
set "path2=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat"
set "path3=C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"

if exist "%path1%" (
    echo Found: %path1%
) else (
    echo Not found: %path1%
)

if exist "%path2%" (
    echo Found: %path2%
) else (
    echo Not found: %path2%
)

if exist "%path3%" (
    echo Found: %path3%
) else (
    echo Not found: %path3%
)

echo.
echo === Testing VsDevCmd.bat with -arch=amd64 ===
call "%path1%" -arch=amd64 >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo VsDevCmd.bat -arch=amd64 succeeded
) else (
    echo VsDevCmd.bat -arch=amd64 failed
)

echo.
echo === Checking compiler architecture ===
where cl.exe >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo cl.exe found in PATH
    cl.exe
) else (
    echo cl.exe not found in PATH
)

pause