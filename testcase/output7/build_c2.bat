@echo off
echo === Starting build ===
call "H:\Programs\Microsoft\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
echo VCVARS done, errorlevel=%errorlevel%
where cl.exe
echo === Compiling ===
cd /d "G:\workspaces\git\corssmool\crossmool\testcase\output7"
cl.exe /nologo /utf-8 /MD /Fe:c_self_test.exe /I"G:\workspaces\git\corssmool\crossmool\c\crossmool\include" /I"G:\workspaces\git\corssmool\crossmool\c\crossmool\gmssl_install\include" c_self_test.c "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\error.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\util_hex.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\util_base64.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\util_string.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\sm2.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\sm3.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\src\sm4.c" "G:\workspaces\git\corssmool\crossmool\c\crossmool\gmssl_install\lib\gmssl.lib" /link /SUBSYSTEM:CONSOLE
echo === Build done, errorlevel=%errorlevel% ===
dir c_self_test.exe 2>&1
