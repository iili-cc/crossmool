@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo ========================================
echo Compile Java-C SM Interop Test
echo ========================================
echo.

REM 获取脚本所在目录
set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..
set C_SRC_DIR=%ROOT_DIR%\c\crossmool\src
set C_INC_DIR=%ROOT_DIR%\c\crossmool\include
set BUILD_DIR=%ROOT_DIR%\c\crossmool\build\Release
set TESTCASE_DIR=%SCRIPT_DIR%

REM 查找 Visual Studio 开发者命令
set "VSDEVCMDS="
for %%v in (2022 2019 2017) do (
    for %%e in (Enterprise Professional Community BuildTools) do (
        set "vcmd=C:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat"
        if exist "!vcmd!" set "VSDEVCMDS=!vcmd!"
    )
)

REM 也检查 G 盘路径
for %%v in (2022 2019 2017) do (
    for %%e in (Enterprise Professional Community BuildTools) do (
        set "vcmd=G:\Program Files\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat"
        if exist "!vcmd!" set "VSDEVCMDS=!vcmd!"
    )
)

if not defined VSDEVCMDS (
    echo [ERROR] Visual Studio not found
    exit /b 1
)

echo [INFO] Using: %VSDEVCMDS%
call "%VSDEVCMDS%"

REM 查找 GmSSL
set "GMSSL_PATH="
if exist "C:\Program Files\GmSSL" set "GMSSL_PATH=C:\Program Files\GmSSL"
if exist "H:\Programs\GmSSL" set "GMSSL_PATH=H:\Programs\GmSSL"

if not defined GMSSL_PATH (
    echo [ERROR] GmSSL not found
    exit /b 1
)

echo [INFO] Using GmSSL at: %GMSSL_PATH%

REM 编译测试程序
echo [INFO] Compiling test_java_c_interop_sm.c...
cl /nologo /MD /I%C_INC_DIR% /I"%GMSSL_PATH%\include" ^
   %TESTCASE_DIR%\test_java_c_interop_sm.c ^
   %C_SRC_DIR%\sm2.c ^
   %C_SRC_DIR%\sm3.c ^
   %C_SRC_DIR%\sm4.c ^
   %C_SRC_DIR%\util_hex.c ^
   %C_SRC_DIR%\util_base64.c ^
   %C_SRC_DIR%\util_string.c ^
   %C_SRC_DIR%\error.c ^
   /link /LIBPATH:"%BUILD_DIR%" /LIBPATH:"%GMSSL_PATH%\lib" ^
   gmssl.lib ^
   /OUT:%TESTCASE_DIR%\test_java_c_interop_sm.exe

if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo [SUCCESS] Compiled: %TESTCASE_DIR%\test_java_c_interop_sm.exe
echo.
echo ========================================
echo Compilation Complete!
echo ========================================
