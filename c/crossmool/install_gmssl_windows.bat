@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

echo ========================================
echo Installing GmSSL from Source
echo ========================================
echo.

REM 检查必要的工具
where git >nul 2>nul
if ERRORLEVEL 1 (
    echo [ERROR] git is not installed or not in PATH
    exit /b 1
)

where cmake >nul 2>nul
if ERRORLEVEL 1 (
    echo [ERROR] cmake is not installed or not in PATH
    exit /b 1
)

REM 检查编译器
where g++ >nul 2>nul
if ERRORLEVEL 1 (
    echo [ERROR] g++ (MinGW) is not installed or not in PATH
    exit /b 1
)

echo [INFO] All prerequisites found
echo.

REM 设置目录
set GMSSL_DIR=%~dp0GmSSL
set BUILD_DIR=%GMSSL_DIR%\build
set INSTALL_DIR=%~dp0gmssl_install

REM 克隆 GmSSL
if not exist "%GMSSL_DIR%" (
    echo [INFO] Cloning GmSSL repository...
    git clone https://github.com/guanzhi/GmSSL.git "%GMSSL_DIR%"
    if ERRORLEVEL 1 (
        echo [ERROR] Failed to clone GmSSL
        exit /b 1
    )
) else (
    echo [INFO] GmSSL repository already exists
    cd /d "%GMSSL_DIR%"
    git pull
    cd /d "%~dp0"
)

echo [SUCCESS] GmSSL cloned
echo.

REM 创建构建目录
if not exist "%BUILD_DIR%" (
    echo [INFO] Creating build directory...
    mkdir "%BUILD_DIR%"
)

REM 配置 CMake
echo [INFO] Configuring with CMake...
cd /d "%BUILD_DIR%"
cmake .. ^
    -G "MinGW Makefiles" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_INSTALL_PREFIX="%INSTALL_DIR%"

if ERRORLEVEL 1 (
    echo [ERROR] CMake configuration failed
    exit /b 1
)

echo [SUCCESS] CMake configured
echo.

REM 构建
echo [INFO] Building GmSSL...
mingw32-make -j4

if ERRORLEVEL 1 (
    echo [ERROR] Build failed
    exit /b 1
)

echo [SUCCESS] Build completed
echo.

REM 安装
echo [INFO] Installing GmSSL...
mingw32-make install

if ERRORLEVEL 1 (
    echo [ERROR] Installation failed
    exit /b 1
)

echo [SUCCESS] Installation completed
echo.

echo ========================================
echo GmSSL Installation Complete!
echo ========================================
echo.
echo Installation directory: %INSTALL_DIR%
echo.
echo To use GmSSL, set the following environment variables:
echo   set CMAKE_PREFIX_PATH=%INSTALL_DIR%
echo   set PKG_CONFIG_PATH=%INSTALL_DIR%\lib\pkgconfig
echo.

cd /d "%~dp0"