@echo off
call "H:\Programs\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d G:\workspaces\git\corssmool\crossmool

echo Compiling c_direct_verify.exe...
cl.exe /I c\crossmool\include /I c\crossmool\GmSSL\include testcase\c_direct_verify.c /Fe c_direct_verify.exe /link /LIBPATH:c\crossmool\build_msvc\Release crossmool.lib 2>&1 | findstr /v "C4819"
echo COMPILE_RC=%ERRORLEVEL%

if exist c_direct_verify.exe (
    copy /Y c_direct_verify.exe c\crossmool\build_msvc\Release\ >nul 2>&1
    cd /d G:\workspaces\git\corssmool\crossmool\c\crossmool\build_msvc\Release
    c_direct_verify.exe
    echo RUN_RC=%ERRORLEVEL%
    del c_direct_verify.exe 2>nul
)

echo.
echo Compiling c_gmssl_raw_test.exe...
cl.exe /I c\crossmool\include /I c\crossmool\GmSSL\include testcase\c_gmssl_raw_test.c /Fe c_gmssl_raw_test.exe /link /LIBPATH:c\crossmool\build_msvc\Release crossmool.lib 2>&1 | findstr /v "C4819"
echo COMPILE2_RC=%ERRORLEVEL%

if exist c_gmssl_raw_test.exe (
    copy /Y c_gmssl_raw_test.exe c\crossmool\build_msvc\Release\ >nul 2>&1
    cd /d G:\workspaces\git\corssmool\crossmool\c\crossmool\build_msvc\Release
    c_gmssl_raw_test.exe
    echo RUN2_RC=%ERRORLEVEL%
    del c_gmssl_raw_test.exe 2>nul
)
