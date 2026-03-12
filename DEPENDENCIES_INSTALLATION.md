# Crossmool C++ Dependencies Installation Guide for Windows

To successfully build and run the crossmool C++ library tests, you need to install GmSSL or OpenSSL with SM2/SM3/SM4 support.

## Installing GmSSL on Windows

### Option 1: Pre-built Binaries (Recommended)

1. Visit the GmSSL project page: https://github.com/guanzhi/GmSSL
2. Look for Windows pre-built binaries or build instructions
3. Alternatively, download from a trusted source that provides Windows builds with SM algorithms

### Option 2: Build from Source

1. Install required build tools:
   - Git for Windows: https://git-scm.com/download/win
   - Visual Studio Build Tools (you already have this)

2. Clone GmSSL:
   ```cmd
   git clone https://github.com/guanzhi/GmSSL.git
   cd GmSSL
   ```

3. Build GmSSL:
   ```cmd
   mkdir build
   cd build
   cmake .. -G "Visual Studio 16 2019" -A x64 -DBUILD_SHARED_LIBS=ON
   cmake --build . --config Release
   ```

## Installing OpenSSL with SM Support

If GmSSL is unavailable, you can use OpenSSL with SM algorithms support:

1. Install MSYS2: https://www.msys2.org/
2. Open MSYS2 terminal
3. Install OpenSSL:
   ```bash
   pacman -S mingw-w64-x86_64-openssl
   ```

## Configuring Environment Variables

After installing GmSSL or OpenSSL, you need to set environment variables:

```cmd
set GmSSL_ROOT_DIR=C:\path\to\your\gmssl\installation
set OPENSSL_ROOT_DIR=C:\path\to\your\openssl\installation
```

Or add these permanently to your system environment variables.

## Alternative Solution: Using vcpkg

You can use Microsoft's vcpkg package manager:

1. Install vcpkg:
   ```cmd
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   ```

2. Install dependencies:
   ```cmd
   .\vcpkg install openssl:x64-windows
   # For GmSSL, you might need to create a custom port
   ```

## Running the Build After Installing Dependencies

Once you have installed the required dependencies:

1. Make sure the libraries' bin directories are in your PATH
2. Ensure the header files are accessible
3. Run the build script:
   ```cmd
   cd build_crossmool.bat
   ```

## Troubleshooting

If CMake still cannot find the libraries:

1. Specify the library paths explicitly:
   ```cmd
   cmake .. -DGmSSL_ROOT_DIR="C:\path\to\gmssl" -DCMAKE_BUILD_TYPE=Release
   ```

2. Or set pkg-config path if the library provides pkg-config files:
   ```cmd
   set PKG_CONFIG_PATH=C:\path\to\lib\pkgconfig;%PKG_CONFIG_PATH%
   ```

## Verification

After successful build, you should be able to run:
```cmd
ctest -C Release --output-on-failure
```

This will execute all the tests we created for SM2, SM3, SM4 algorithms and verify the functionality.