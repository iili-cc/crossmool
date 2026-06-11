@echo off
setlocal

set WORKDIR=g:\workspaces\git\corssmool\crossmool
cd /d %WORKDIR%

set JAVA_HOME=H:\Program\Java\jdk-21.0.1+12
set CP=%WORKDIR%\java\crossmool\target\classes;%WORKDIR%\java\crossmool\target\dependency\bcprov-jdk18on-1.82.jar;%WORKDIR%\java\crossmool\target\dependency\lombok-1.18.42.jar;%WORKDIR%\java\crossmool\target\dependency\slf4j-api-2.0.17.jar;%WORKDIR%\java\crossmool\target\dependency\logback-classic-1.5.22.jar;%WORKDIR%\java\crossmool\target\dependency\logback-core-1.5.22.jar
set LOGFILE=%WORKDIR%\testcase\go_interop_gen.log

echo === Step 1: Compiling === > %LOGFILE%
echo WORKDIR=%WORKDIR% >> %LOGFILE%
echo CP=%CP% >> %LOGFILE%
"%JAVA_HOME%\bin\javac.exe" -encoding UTF-8 -cp "%CP%" %WORKDIR%\testcase\GenerateGoInteropData.java >> %LOGFILE% 2>&1
if %ERRORLEVEL% neq 0 (
    echo COMPILE FAILED >> %LOGFILE%
    exit /b 1
)
echo COMPILE SUCCESS >> %LOGFILE%

echo === Step 2: Running === >> %LOGFILE%
set RUNCP=%WORKDIR%\testcase;%CP%
"%JAVA_HOME%\bin\java.exe" -cp "%RUNCP%" GenerateGoInteropData %WORKDIR%\testcase\java_go_test_data.json >> %LOGFILE% 2>&1
if %ERRORLEVEL% neq 0 (
    echo RUN FAILED >> %LOGFILE%
    exit /b 1
)

echo === Done === >> %LOGFILE%