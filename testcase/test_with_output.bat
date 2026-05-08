@echo off
chcp 65001 >nul
cd /d g:\workspaces\git\corssmool\crossmool

echo ========================================
echo Running Java to C Interop Test
echo ========================================
echo.

H:\Programs\Python3\python.exe -u testcase\java_to_c_verify_test.py 2>&1

echo.
echo ========================================
echo Exit Code: %ERRORLEVEL%
echo ========================================
echo.

echo Checking log files:
dir /b java_interop_test_*.log 2>nul
if %ERRORLEVEL% neq 0 (
    echo No log files found in current directory.
)

echo.
echo Checking testcase directory:
dir /b testcase\java_interop_test_*.log 2>nul
if %ERRORLEVEL% neq 0 (
    echo No log files found in testcase directory.
)

pause