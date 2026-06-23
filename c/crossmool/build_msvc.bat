@echo off
REM ================================================================
REM  crossmool-c MSVC Build Script
REM  Output: build_msvc\bin\crossmool.dll + crossmool.lib + headers
REM          build_msvc\bin\test_all.exe
REM ================================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set BUILD=%ROOT%build_msvc
set BIN=%BUILD%\bin
set OBJ=%BUILD%\obj
set INCLUDE_DIR=%ROOT%include
set GMSSL_DIR=%ROOT%gmssl_install
set GMSSL_INCLUDE=%GMSSL_DIR%\include
set GMSSL_LIB=%GMSSL_DIR%\lib\gmssl.lib
set GMSSL_DLL=%GMSSL_DIR%\bin\gmssl.dll

echo =============================================
echo  crossmool-c MSVC Build
echo =============================================

REM --- 创建输出目录 ---
if not exist "%BIN%"  mkdir "%BIN%"
if not exist "%OBJ%"  mkdir "%OBJ%"

REM --- MSVC 编译选项 ---
set CFLAGS=/nologo /MD /O2 /W3 /utf-8 /DCROSSMOOL_BUILD_DLL /DDEBUG=0 /D_CRT_SECURE_NO_WARNINGS
set INCLUDES=/I"%INCLUDE_DIR%" /I"%GMSSL_INCLUDE%"

echo.
echo [1/4] Compiling source files...

cl %CFLAGS% %INCLUDES% /Fo"%OBJ%\\" /c ^
    "%ROOT%src\error.c" ^
    "%ROOT%src\util_hex.c" ^
    "%ROOT%src\util_base64.c" ^
    "%ROOT%src\util_string.c" ^
    "%ROOT%src\sm2.c" ^
    "%ROOT%src\sm3.c" ^
    "%ROOT%src\sm4.c"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo   Source compilation OK.

echo.
echo [2/4] Linking crossmool.dll...
link /NOLOGO /DLL /OUT:"%BIN%\crossmool.dll" /IMPLIB:"%BIN%\crossmool.lib" ^
    "%OBJ%\error.obj" ^
    "%OBJ%\util_hex.obj" ^
    "%OBJ%\util_base64.obj" ^
    "%OBJ%\util_string.obj" ^
    "%OBJ%\sm2.obj" ^
    "%OBJ%\sm3.obj" ^
    "%OBJ%\sm4.obj" ^
    "%GMSSL_LIB%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Link failed!
    exit /b 1
)
echo   crossmool.dll + crossmool.lib created.

REM --- 复制 GmSSL DLL ---
copy /Y "%GMSSL_DLL%" "%BIN%\" >nul
echo   gmssl.dll copied to output.

echo.
echo [3/4] Compiling test_all.exe...
cl %CFLAGS% %INCLUDES% ^
    /Fe:"%BIN%\test_all.exe" ^
    "%ROOT%tests\test_all.c" ^
    /link /NOLOGO "%BIN%\crossmool.lib" "%GMSSL_LIB%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Test compilation failed!
    exit /b 1
)
echo   test_all.exe created.

echo.
echo [4/4] Running tests...
echo =============================================
"%BIN%\test_all.exe"
set TESTRESULT=%ERRORLEVEL%
echo =============================================

if %TESTRESULT% equ 0 (
    echo.
    echo =============================================
    echo   BUILD SUCCESS - All tests passed!
    echo =============================================
    echo.
    echo   Deliverables:
    echo     %BIN%\crossmool.dll
    echo     %BIN%\crossmool.lib
    echo     %BIN%\gmssl.dll
    echo     %INCLUDE_DIR%\*.h
    echo.
    echo   Usage: cl /I"%INCLUDE_DIR%" app.c /link "%BIN%\crossmool.lib"
    echo =============================================
    exit /b 0
) else (
    echo.
    echo =============================================
    echo   BUILD FAILED - %TESTRESULT% tests failed!
    echo =============================================
    exit /b 1
)
