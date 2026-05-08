@echo off
chcp 65001 >nul
cd /d g:\workspaces\git\corssmool\crossmool
H:\Programs\Python3\python.exe testcase\java_to_c_verify_test.py
echo Exit code: %ERRORLEVEL%
pause