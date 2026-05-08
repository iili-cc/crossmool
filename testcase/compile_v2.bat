@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cd /d "G:\workspaces\git\corssmool\crossmool\testcase"
cl.exe /I"G:\workspaces\git\corssmool\crossmool\c\crossmool\include" c_cross_verify_v2.c /Fe:c_cross_verify_v2.exe /link "G:\workspaces\git\corssmool\crossmool\c\crossmool\build\Release\crossmool.lib"
