#!/bin/bash

set -e

echo "========================================"
echo "Crossmool C Library - Linux Build"
echo "========================================"
echo ""

# 检查 vcpkg 路径
if [ -z "$VCPKG_ROOT" ]; then
    echo "[ERROR] VCPKG_ROOT is not set."
    echo "Please install vcpkg from https://github.com/microsoft/vcpkg"
    echo "Then run: vcpkg integrate install"
    exit 1
fi

echo "[INFO] Using vcpkg at: $VCPKG_ROOT"
echo ""

# 安装依赖
echo "[INFO] Installing dependencies via vcpkg..."
vcpkg install gmssl:x64-linux
echo "[SUCCESS] Dependencies installed"
echo ""

# 创建构建目录
if [ ! -d "build" ]; then
    echo "[INFO] Creating build directory..."
    mkdir build
fi

# 配置 CMake
echo "[INFO] Configuring CMake..."
cd build
cmake \
    -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -DCMAKE_BUILD_TYPE=Release \
    ..
echo "[SUCCESS] CMake configured"
echo ""

# 构建项目
echo "[INFO] Building project..."
cmake --build .
echo "[SUCCESS] Build completed"
echo ""

# 运行测试
echo "[INFO] Running tests..."
ctest --output-on-failure
echo "[SUCCESS] All tests passed"
echo ""

# 安装
echo "[INFO] Installing to build/install..."
cmake --install . --prefix install
echo "[SUCCESS] Installation completed"
echo ""

echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "Output directory: $(pwd)"
echo "Install directory: $(pwd)/install"
echo ""