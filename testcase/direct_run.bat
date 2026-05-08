@echo off
chcp 65001 >nul
cd /d g:\workspaces\git\corssmool\crossmool

echo === Running Python Test Script ===
echo Current directory: %CD%
echo.

H:\Programs\Python3\python.exe -u testcase\java_to_c_verify_test.py

echo.
echo === Exit Code: %ERRORLEVEL% ===
echo.

echo === Checking Log Files ===
dir /b java_interop_test_*.log 2>nul
if %ERRORLEVEL% neq 0 echo No log files found.

pause