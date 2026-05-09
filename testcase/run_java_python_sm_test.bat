@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ==============================================
echo Java-Python SM2/SM3/SM4 Interoperability Test
echo ==============================================
echo.

cd /d "%~dp0"

REM Find Java and Python
set JAVA_EXE=java
set JAVAC_EXE=javac
set PYTHON_EXE=python

REM Check if Java is available
%JAVA_EXE% -version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Java not found in PATH
    exit /b 1
)
echo [INFO] Java found: %JAVA_EXE%

REM Check if Python is available
%PYTHON_EXE% --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH
    exit /b 1
)
echo [INFO] Python found: %PYTHON_EXE%

REM Build classpath
set PROJECT_ROOT=..
set JAVA_SRC=%PROJECT_ROOT%\java\crossmool\src\main\java
set JAVA_TARGET=%PROJECT_ROOT%\java\crossmool\target\classes
set BC_JAR=%PROJECT_ROOT%\java\crossmool\lib\bcprov-jdk18on-1.82.jar
set LOMBOK_JAR=%PROJECT_ROOT%\java\crossmool\lib\lombok-1.18.42.jar
set SLF4J_API_JAR=%PROJECT_ROOT%\java\crossmool\lib\slf4j-api-2.0.17.jar
set LOGBACK_CLASSIC_JAR=%PROJECT_ROOT%\java\crossmool\lib\logback-classic-1.5.22.jar
set LOGBACK_CORE_JAR=%PROJECT_ROOT%\java\crossmool\lib\logback-core-1.5.22.jar

REM Check if target classes exist
if not exist "%JAVA_TARGET%" (
    echo [WARNING] Java target classes not found, compiling...
    mkdir "%JAVA_TARGET%" 2>nul
)

REM Compile Java test class
echo.
echo [STEP 1] Compiling Java test class...
%JAVAC_EXE% -encoding UTF-8 -cp "%JAVA_TARGET%;%BC_JAR%;%LOMBOK_JAR%;%SLF4J_API_JAR%;%LOGBACK_CLASSIC_JAR%;%LOGBACK_CORE_JAR%" -d . JavaPythonSMInteropTest.java

if errorlevel 1 (
    echo [ERROR] Java compilation failed!
    exit /b 1
)
echo [OK] Java compilation successful!

REM Run Java test to generate test data
echo.
echo [STEP 2] Running Java test to generate test data...
%JAVA_EXE% -cp ".;%JAVA_TARGET%;%BC_JAR%;%LOMBOK_JAR%;%SLF4J_API_JAR%;%LOGBACK_CLASSIC_JAR%;%LOGBACK_CORE_JAR%" testcase.JavaPythonSMInteropTest > java_output.txt 2>&1

if errorlevel 1 (
    echo [ERROR] Java test execution failed!
    type java_output.txt
    exit /b 1
)

echo [OK] Java test completed!
echo.
type java_output.txt

REM Extract JSON output from Java output
echo.
echo [STEP 3] Extracting test data JSON...
setlocal enabledelayedexpansion
set in_json=0
set json_file=test_data_java_python.json
echo { > %json_file%

for /f "usebackq delims=" %%a in ("java_output.txt") do (
    set "line=%%a"
    if "!line!"=="[JSON_OUTPUT_START]" (
        set in_json=1
        goto :continue
    )
    if "!line!"=="[JSON_OUTPUT_END]" (
        set in_json=0
        goto :continue
    )
    if !in_json==1 (
        echo !line! >> %json_file%
    )
    :continue
)

echo } >> %json_file%
endlocal

echo [OK] Test data extracted to %json_file%

REM Run Python test
echo.
echo [STEP 4] Running Python verification test...
%PYTHON_EXE% test_java_python_sm_interop.py

if errorlevel 1 (
    echo.
    echo [ERROR] Python test failed!
    exit /b 1
)

echo.
echo ==============================================
echo All tests completed successfully!
echo ==============================================

REM Cleanup
del java_output.txt 2>nul
del JavaPythonSMInteropTest.class 2>nul

exit /b 0