# 构建指南

本文档提供 crossmool-c 项目的详细构建步骤。

## 前置要求

### 1. 安装 CMake

下载并安装 CMake 3.20 或更高版本：
- Windows: https://cmake.org/download/
- Linux: `sudo apt-get install cmake` 或 `sudo yum install cmake`
- macOS: `brew install cmake`

### 2. 安装 vcpkg

```bash
# 克隆 vcpkg
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg

# Windows
.\bootstrap-vcpkg.bat

# Linux/macOS
./bootstrap-vcpkg.sh

# 集成到系统
vcpkg integrate install
```

### 3. 安装 GmSSL

```bash
# 使用 vcpkg 安装
vcpkg install gmssl:x64-windows    # Windows
vcpkg install gmssl:x64-linux     # Linux
vcpkg install gmssl:x64-osx       # macOS
```

## 构建步骤

### Windows (Visual Studio 2022)

```powershell
# 设置环境变量
$env:VCPKG_ROOT="C:\vcpkg"

# 运行构建脚本
.\build_windows.bat

# 或者手动构建
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE=$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake `
    -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release
ctest -C Release
```

### Windows (MinGW/MSYS2)

```bash
# 安装 MSYS2 和 MinGW
# https://www.msys2.org/

# 更新系统
pacman -Syu

# 安装构建工具
pacman -S mingw-w64-x86_64-toolchain

# 构建
mkdir build && cd build
cmake -G "MinGW Makefiles" `
    -DCMAKE_TOOLCHAIN_FILE=/c/vcpkg/scripts/buildsystems/vcpkg.cmake `
    -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
ctest
```

### Linux

```bash
# 运行构建脚本
chmod +x build_linux.sh
./build_linux.sh

# 或者手动构建
mkdir build && cd build
cmake -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
    -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
ctest
```

### macOS

```bash
# 安装 Homebrew (如未安装)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 CMake
brew install cmake

# 构建
mkdir build && cd build
cmake -G Ninja `
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" `
    -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
ctest
```

## 安装

```bash
# Windows
cmake --install . --config Release --prefix install

# Linux/macOS
cmake --install . --prefix install
```

安装后的文件结构：
```
install/
├── bin/           # 可执行文件
├── lib/           # 库文件
│   ├── crossmool.lib     # Windows
│   ├── libcrossmool.a    # Linux/macOS
│   └── libcrossmool.so   # Linux (共享库)
├── include/       # 头文件
└── share/         # CMake 配置文件
```

## 验证安装

### 运行测试

```bash
cd build
ctest -C Release --output-on-failure
```

### 运行示例

```bash
# Windows
cd build\bin\Release
sm2_sample.exe
sm3_sample.exe
sm4_sample.exe
interop_sample.exe

# Linux/macOS
cd build
./samples/sm2_sample
./samples/sm3_sample
./samples/sm4_sample
./samples/interop_sample
```

## 常见问题

### 1. CMake 找不到 GmSSL

确保正确设置了 `CMAKE_TOOLCHAIN_FILE`:
```bash
-DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
```

### 2. 链接错误

确保安装时包含了正确的路径：
```bash
cmake --install . --prefix /path/to/install
```

### 3. 运行时错误

确保动态库路径正确设置：
- Windows: 添加 `build\bin\Release` 到 PATH
- Linux: 设置 `LD_LIBRARY_PATH`
- macOS: 设置 `DYLD_LIBRARY_PATH`

## 使用项目

### 作为子模块

```cmake
add_subdirectory(path/to/crossmool-c)
target_link_libraries(your_target PRIVATE crossmool)
```

### 使用 find_package

```cmake
find_package(crossmool REQUIRED)
target_link_libraries(your_target PRIVATE crossmool)
```

### 使用 pkg-config

```bash
gcc your_program.c $(pkg-config --cflags --libs crossmool)
```

## 卸载

```bash
# 使用 CMake 卸载
cmake --build build --target uninstall

# 或者手动删除
rm -rf /path/to/install