@echo off
REM ================================================================
REM  crossmool-cpp MSVC Build Script
REM  Output: build_msvc\bin\crossmool.dll + crossmool.lib + headers
REM          build_msvc\bin\test_all.exe
REM ================================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set BUILD=%ROOT%build_msvc
set BIN=%BUILD%\bin
set OBJ=%BUILD%\obj
set INCLUDE_DIR=%ROOT%include
set UTILS_DIR=%ROOT%utils
set TEST_DIR=%ROOT%tests

REM GmSSL from sibling C project
set GMSSL_DIR=%ROOT%..\..\c\crossmool\gmssl_install
set GMSSL_INCLUDE=%GMSSL_DIR%\include
set GMSSL_LIB=%GMSSL_DIR%\lib\gmssl.lib
set GMSSL_DLL=%GMSSL_DIR%\bin\gmssl.dll

echo =============================================
echo  crossmool-cpp MSVC Build
echo =============================================

REM --- 创建输出目录 ---
if not exist "%BIN%" mkdir "%BIN%"
if not exist "%OBJ%" mkdir "%OBJ%"

REM --- MSVC 编译选项 ---
set CFLAGS=/nologo /MD /O2 /W3 /utf-8 /EHsc /DCROSSMOOL_BUILD_DLL /DUSE_GMSSL /DDEBUG=0 /D_CRT_SECURE_NO_WARNINGS
set INCLUDES=/I"%INCLUDE_DIR%" /I"%UTILS_DIR%" /I"%GMSSL_INCLUDE%"

echo.
echo [1/4] Compiling source files...

cl %CFLAGS% %INCLUDES% /Fo"%OBJ%\\" /c ^
    "%UTILS_DIR%\Base64Util.cpp" ^
    "%UTILS_DIR%\HexUtil.cpp" ^
    "%UTILS_DIR%\StringUtil.cpp" ^
    "%ROOT%src\SM2Util.cpp" ^
    "%ROOT%src\SM3Util.cpp" ^
    "%ROOT%src\SM4Util.cpp"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed!
    exit /b 1
)
echo   Source compilation OK.

echo.
echo [2/4] Linking crossmool.dll...
link /NOLOGO /DLL /OUT:"%BIN%\crossmool.dll" /IMPLIB:"%BIN%\crossmool.lib" ^
    "%OBJ%\Base64Util.obj" ^
    "%OBJ%\HexUtil.obj" ^
    "%OBJ%\StringUtil.obj" ^
    "%OBJ%\SM2Util.obj" ^
    "%OBJ%\SM3Util.obj" ^
    "%OBJ%\SM4Util.obj" ^
    "%GMSSL_LIB%"
if %ERRORLEVEL% neq 0 (
    echo ERROR: Link failed!
    exit /b 1
)
echo   crossmool.dll + crossmool.lib created.

REM --- 复制 GmSSL DLL ---
copy /Y "%GMSSL_DLL%" "%BIN%\" >nul
copy /Y "%GMSSL_DIR%\bin\libgmssl.dll" "%BIN%\" >nul 2>nul
echo   gmssl.dll copied to output.

echo.
echo [3/4] Compiling test_all.exe...
cl %CFLAGS% %INCLUDES% ^
    /Fe:"%BIN%\test_all.exe" ^
    "%TEST_DIR%\test_all.cpp" ^
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
    echo     %UTILS_DIR%\*.h
    echo.
    echo   Usage: cl /EHsc /I"%INCLUDE_DIR%" /I"%UTILS_DIR%" app.cpp /link "%BIN%\crossmool.lib"
    echo =============================================
    exit /b 0
) else (
    echo.
    echo =============================================
    echo   BUILD FAILED - Exit code: %TESTRESULT%
    echo =============================================
    exit /b 1
)
