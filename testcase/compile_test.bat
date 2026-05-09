@echo off
setlocal

set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
call "%VS_PATH%\VC\Auxiliary\Build\vcvars64.bat"

set "SRC_DIR=G:\workspaces\git\corssmool\crossmool"
set "TEST_DIR=%SRC_DIR%\testcase"
set "C_SRC=%SRC_DIR%\c\crossmool\src"
set "C_INC=%SRC_DIR%\c\crossmool\include"
set "GMSSL_DIR=%SRC_DIR%\c\crossmool\GmSSL\build"

cd /d "%TEST_DIR%"

echo Compiling C interop test...
echo Include paths:
echo   - %C_INC%
echo   - %GMSSL_DIR%\include
echo.

cl /MD ^
   /I"%C_INC%" ^
   /I"%GMSSL_DIR%\include" ^
   test_java_c_interop_sm.c ^
   "%C_SRC%\sm2.c" ^
   "%C_SRC%\sm3.c" ^
   "%C_SRC%\sm4.c" ^
   "%C_SRC%\util_hex.c" ^
   "%C_SRC%\util_base64.c" ^
   "%C_SRC%\util_string.c" ^
   "%C_SRC%\error.c" ^
   /link ^
   /LIBPATH:"%GMSSL_DIR%\bin" ^
   libgmssl.dll.a ^
   /OUT:test_java_c_interop_sm.exe

echo.
echo Exit code: %ERRORLEVEL%

endlocal