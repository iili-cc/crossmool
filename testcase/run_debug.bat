@echo off
chcp 65001 >nul
cd /d g:\workspaces\git\corssmool\crossmool
echo Running Python script...
H:\Programs\Python3\python.exe testcase\java_to_c_verify_test.py
echo.
echo Exit code: %ERRORLEVEL%
echo.
dir java_interop_test_*.log
pause