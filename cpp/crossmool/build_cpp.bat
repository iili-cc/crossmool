@echo off
REM Windows Batch Script to Build crossmool C++ Project

echo Setting up build environment for crossmool...

REM Check for Visual Studio Developer Command Prompt
if "%VCINSTALLDIR%"=="" (
    echo Error: This script must be run from a Visual Studio Developer Command Prompt
    echo Please open 'Developer Command Prompt for VS' or 'x64 Native Tools Command Prompt'
    exit /b 1
)

echo Detected Visual Studio environment: %VCINSTALLDIR%

REM Navigate to project directory (already in the right directory)
cd /d "%~dp0"

echo Configuring project with CMake using Visual Studio generator...
cmake . -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release

if %ERRORLEVEL% NEQ 0 (
    echo CMake configuration failed.
    echo Trying with older Visual Studio version...
    cmake . -G "Visual Studio 15 2017" -A x64 -DCMAKE_BUILD_TYPE=Release
    if %ERRORLEVEL% NEQ 0 (
        echo CMake configuration failed with VS 2017 too.
        exit /b 1
    )
)

echo Building the project...
cmake --build . --config Release

if %ERRORLEVEL% NEQ 0 (
    echo Build failed.
    exit /b 1
)

echo Build completed successfully!

echo Running tests...
ctest -C Release --output-on-failure

echo Build and test completed.
pause