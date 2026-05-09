@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo ========================================
echo Compile Java-C SM Interop Test (Simple)
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
        if exist "G:\Programs\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat" (
            set "VSDEVCMDS=G:\Programs\Microsoft Visual Studio\%%v\%%e\VC\Auxiliary\Build\vcvars64.bat"
        )
    )
)

if not defined VSDEVCMDS (
    echo [ERROR] Visual Studio not found
    exit /b 1
)

echo [INFO] Setting up VS environment...
call "%VSDEVCMDS%" >nul 2>&1

REM 查找 GmSSL
set "GMSSL_PATH="
if exist "H:\Programs\GmSSL" set "GMSSL_PATH=H:\Programs\GmSSL"
if not defined GMSSL_PATH if exist "C:\Program Files\GmSSL" set "GMSSL_PATH=C:\Program Files\GmSSL"

if not defined GMSSL_PATH (
    echo [ERROR] GmSSL not found
    exit /b 1
)

echo [INFO] Using GmSSL at: %GMSSL_PATH%
echo [INFO] Using crossmool lib at: %BUILD_DIR%

REM 编译测试程序（使用预编译的 crossmool.lib）
echo [INFO] Compiling test_java_c_interop_sm.c...

cl /nologo /MD /I%C_INC_DIR% /I"%GMSSL_PATH%\include" ^
   /Fo%TESTCASE_DIR%test_java_c_interop_sm.obj ^
   %TESTCASE_DIR%test_java_c_interop_sm.c

if errorlevel 1 (
    echo [ERROR] Compilation failed
    exit /b 1
)

echo [INFO] Linking...

link /nologo /OUT:%TESTCASE_DIR%test_java_c_interop_sm.exe ^
   %TESTCASE_DIR%test_java_c_interop_sm.obj ^
   %BUILD_DIR%\crossmool.lib ^
   %GMSSL_PATH%\lib\gmssl.lib

if errorlevel 1 (
    echo [ERROR] Linking failed
    del %TESTCASE_DIR%test_java_c_interop_sm.obj 2>nul
    exit /b 1
)

echo [SUCCESS] Compiled: %TESTCASE_DIR%test_java_c_interop_sm.exe
echo.

REM 清理
del %TESTCASE_DIR%test_java_c_interop_sm.obj 2>nul

echo ========================================
echo Compilation Complete!
echo ========================================