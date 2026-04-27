@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo ========================================
echo Crossmool C Library - Windows Build
echo ========================================
echo.

REM 检查是否安装了 vcpkg
if not defined VCPKG_ROOT (
    echo [ERROR] VCPKG_ROOT is not set.
    echo Please install vcpkg from https://github.com/microsoft/vcpkg
    echo Then run: vcpkg integrate install
    exit /b 1
)

echo [INFO] Using vcpkg at: %VCPKG_ROOT%
echo.

REM 安装依赖
echo [INFO] Installing dependencies via vcpkg...
vcpkg install gmssl:x64-windows
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    exit /b 1
)
echo [SUCCESS] Dependencies installed
echo.

REM 创建构建目录
if not exist build (
    echo [INFO] Creating build directory...
    mkdir build
)

REM 配置 CMake
echo [INFO] Configuring CMake...
cd build
cmake ^
    -G "Visual Studio 17 2022" ^
    -A x64 ^
    -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake ^
    -DCMAKE_BUILD_TYPE=Release ^
    ..

if errorlevel 1 (
    echo [ERROR] CMake configuration failed
    cd ..
    exit /b 1
)
echo [SUCCESS] CMake configured
echo.

REM 构建项目
echo [INFO] Building project...
cmake --build . --config Release
if errorlevel 1 (
    echo [ERROR] Build failed
    cd ..
    exit /b 1
)
echo [SUCCESS] Build completed
echo.

REM 运行测试
echo [INFO] Running tests...
ctest -C Release --output-on-failure
if errorlevel 1 (
    echo [WARNING] Some tests failed
) else (
    echo [SUCCESS] All tests passed
)
echo.

REM 安装
echo [INFO] Installing to build/install...
cmake --install . --config Release --prefix install
echo [SUCCESS] Installation completed
echo.

echo ========================================
echo Build Complete!
echo ========================================
echo.
echo Output directory: %CD%\bin\Release
echo Install directory: %CD%\install
echo.

cd ..