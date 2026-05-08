@echo off
copy /Y "G:\workspaces\git\corssmool\crossmool\c\crossmool\build\Release\crossmool.dll" "G:\workspaces\git\corssmool\crossmool\testcase\" >nul
cd /d "G:\workspaces\git\corssmool\crossmool\testcase"
c_cross_verify_v2.exe > v2_result.txt 2>&1
type v2_result.txt
