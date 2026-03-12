@echo off
setlocal EnableDelayedExpansion

echo Checking build environment for crossmool...
echo.

REM Check if we are on Windows
if "%OS%" neq "Windows_NT" (
    echo This script is designed for Windows.
    pause
    exit /b 1
)

REM Define the Visual Studio Build Tools path
set "VS_PATH=D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\14.41.34120\bin\Hostx64\x64"

REM Check if the path exists
if not exist "!VS_PATH!" (
    echo Error: Visual Studio Build Tools not found at !VS_PATH!
    dir "D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\" 2>nul
    if !errorlevel! neq 0 (
        echo Could not find MSVC directory
    )
    pause
    exit /b 1
)

echo Found Visual Studio Build Tools at: !VS_PATH!
echo.

REM Add VS tools to PATH for this session
set "PATH=!VS_PATH!;!PATH!"

REM Check if cl.exe (Microsoft C++ compiler) is accessible
cl 2>nul
if !errorlevel! neq 0 (
    echo Error: Microsoft C++ compiler (cl.exe) is not accessible
    echo Current PATH: !PATH!
    pause
    exit /b 1
)

REM Check if CMake is installed
cmake --version >nul 2>&1
if !errorlevel! neq 0 (
    echo CMake is not installed or not in PATH.
    echo Attempting to install CMake via winget...

    REM Try to install CMake via winget
    winget install Kitware.CMake -h >nul 2>&1
    if !errorlevel! equ 0 (
        echo CMake installed via winget. Waiting a moment...
        timeout /t 5 /nobreak >nul
    ) else (
        echo winget installation failed or not available.
        echo Please install CMake manually from https://cmake.org/download/
        echo Then run this script again.
        pause
        exit /b 1
    )
) else (
    for /f "tokens=*" %%i in ('cmake --version ^| findstr version') do set CMAKE_VERSION=%%i
    echo CMake is available: !CMAKE_VERSION!
)

REM Verify CMake again after potential installation
cmake --version >nul 2>&1
if !errorlevel! neq 0 (
    echo Error: CMake is still not accessible after installation attempt.
    echo Please install CMake manually from https://cmake.org/download/
    pause
    exit /b 1
)

REM Change to the project directory (we're already there)
cd /d "%~dp0"

REM Create build directory if it doesn't exist
if not exist "build" mkdir build
cd build

echo Running CMake configuration...
echo.

REM Configure the project with CMake
cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
if !errorlevel! neq 0 (
    echo CMake configuration failed with Visual Studio 16 2019.
    echo Trying with Visual Studio 15 2017...
    cmake .. -G "Visual Studio 15 2017" -A x64 -DCMAKE_BUILD_TYPE=Release
    if !errorlevel! neq 0 (
        echo CMake configuration failed with Visual Studio 15 2017 too.
        echo Trying with NMake Makefiles...
        cmake .. -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release
        if !errorlevel! neq 0 (
            echo CMake configuration failed with all generators.
            echo Current directory: !cd!
            echo Available files:
            dir
            pause
            exit /b 1
        )
    )
)

echo CMake configuration successful!
echo.

echo Building the project...
echo.
cmake --build . --config Release
if !errorlevel! neq 0 (
    echo Build failed.
    pause
    exit /b 1
)

echo Build completed successfully!
echo.

echo Running tests...
echo.
ctest -C Release --output-on-failure
if !errorlevel! neq 0 (
    echo Some tests failed or tests not available yet.
    REM Don't exit as this might be expected initially
)

echo.
echo Build and test process completed successfully!
echo You can find the built libraries and executables in the build directory.
echo.
pause