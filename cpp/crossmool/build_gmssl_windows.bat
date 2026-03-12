@echo off
REM build_gmssl_windows.bat - Script to build GmSSL on Windows

echo Building GmSSL from source on Windows...

REM First check if we have git, cmake, and a compiler
where git >nul 2>nul
if ERRORLEVEL 1 (
    echo Error: git is not installed or not in PATH
    exit /b 1
)

where cmake >nul 2>nul
if ERRORLEVEL 1 (
    echo Error: cmake is not installed or not in PATH
    exit /b 1
)

REM Check for MSVC compiler
where cl >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Found MSVC compiler
    set COMPILER=MSVC
    goto :BUILD
)

REM Check for MinGW compiler (gcc/g++)
where g++ >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo Found g++ compiler
    set COMPILER=MinGW
    goto :BUILD
)

echo Error: No C++ compiler found (MSVC or MinGW/g++)
exit /b 1

:BUILD
echo Compiler: %COMPILER%

REM Clone GmSSL if not already present
if not exist "GmSSL" (
    echo Cloning GmSSL repository...
    git clone https://github.com/guanzhi/GmSSL.git
) else (
    echo GmSSL repository already exists, updating...
    cd GmSSL
    git pull
    cd ..
)

REM Create build directory and compile
cd GmSSL
if not exist "build" mkdir build
cd build

echo Configuring with CMake...
if "%COMPILER%"=="MSVC" (
    REM Using Visual Studio compiler
    cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
    echo Building with MSVC...
    cmake --build . --config Release
) else (
    REM Using MinGW
    cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
    echo Building with MinGW...
    mingw32-make -j4
)

echo GmSSL built successfully in GmSSL/build/

REM Create local install directory
if not exist "..\local_install\lib" mkdir ..\local_install\lib
if not exist "..\local_install\include" mkdir ..\local_install\include

REM Copy headers
xcopy /s /y "..\include\*" "..\local_install\include\"

REM Copy libraries (adjust based on what was built)
if exist "Release\*.lib" (
    xcopy /y "Release\*.lib" "..\local_install\lib\"
) else if exist "*.lib" (
    xcopy /y "*.lib" "..\local_install\lib\"
) else if exist "lib\*.lib" (
    xcopy /y "lib\*.lib" "..\local_install\lib\"
)

REM If DLLs were built, copy them too
if exist "Release\*.dll" (
    xcopy /y "Release\*.dll" "..\local_install\lib\"
) else if exist "*.dll" (
    xcopy /y "*.dll" "..\local_install\lib\"
)

echo GmSSL local installation created at GmSSL/local_install/
echo You can set PKG_CONFIG_PATH or use CMAKE_PREFIX_PATH to point to this directory