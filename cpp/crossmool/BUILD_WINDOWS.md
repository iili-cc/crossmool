# Crossmool C++ Library - Build and Test Guide for Windows

This document explains how to build and run tests for the Crossmool C++ library on Windows with Visual Studio Build Tools.

## Prerequisites

Before building the project, you need to have the following installed:

1. **Visual Studio Build Tools** - You have this installed at:
   ```
   D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\14.41.34120\bin\Hostx64\x64
   ```

2. **CMake** - Required for the build system
   - Download from: https://cmake.org/download/
   - Or install via package manager like Chocolatey: `choco install cmake`

3. **GmSSL or OpenSSL with SM2/SM3/SM4 support** - The cryptographic library that Crossmool wraps
   - GmSSL: https://github.com/guanzhi/GmSSL
   - Or OpenSSL with SM algorithms support

## Building the Project

### Method 1: Using PowerShell Script (Recommended)

Run the provided PowerShell script:

```powershell
.\build_with_vs.ps1
```

This script will:
- Verify your Visual Studio Build Tools installation
- Check for CMake availability
- Create the build directory
- Configure the project with CMake
- Build all targets including tests
- Run the test suite

### Method 2: Using Batch Script

Run the provided batch script:

```cmd
.\build_with_vs.bat
```

This script performs the same steps as the PowerShell script but in a Windows batch environment.

### Method 3: Manual Build

If you prefer to build manually, follow these steps:

1. Open a Visual Studio Developer Command Prompt (or x64 Native Tools Command Prompt)

2. Navigate to the project directory (you are already in it):
   ```cmd
   cd .
   ```

3. Create and enter the build directory:
   ```cmd
   mkdir build
   cd build
   ```

4. Configure the project with CMake:
   ```cmd
   cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
   ```

   Alternative generators if the above doesn't work:
   ```cmd
   cmake .. -G "Visual Studio 15 2017" -A x64 -DCMAKE_BUILD_TYPE=Release
   # Or if you have Ninja installed:
   cmake .. -G "Ninja" -DCMAKE_BUILD_TYPE=Release
   ```

5. Build the project:
   ```cmd
   cmake --build . --config Release
   ```

6. Run the tests:
   ```cmd
   ctest -C Release --output-on-failure
   ```

## Available Tests

The test suite includes:

- `crossmool_test_sm2` - Tests for SM2 encryption/decryption and signing/verification
- `crossmool_test_sm3` - Tests for SM3 hash functions
- `crossmool_test_sm4` - Tests for SM4 encryption/decryption (ECB/CBC modes)
- `crossmool_test_comprehensive` - Integration tests for all algorithms
- `crossmool_test_interop` - Interoperability tests for cross-language compatibility
- `crossmool_test_main` - Main comprehensive test suite

## Interoperability Testing

To test interoperability between C++ and Java implementations:

1. Build and run the C++ interop test:
   ```cmd
   ./crossmool_test_interop
   ```
   This creates test data files (`interop_test_public.der`, `interop_test_private.der`, etc.)

2. Run the Java interop test (requires Java and Maven/Gradle setup):
   ```bash
   cd ../java/crossmool
   mvn test -Dtest=InteropTest
   ```

## Troubleshooting

### CMake Cannot Find GmSSL/OpenSSL
If CMake reports that GmSSL or OpenSSL is not found:

1. Make sure the library is installed
2. If installed in a non-standard location, specify the path:
   ```cmd
   cmake .. -DGmSSL_ROOT_DIR=<path_to_gmssl_installation> -DCMAKE_BUILD_TYPE=Release
   ```

### Visual Studio Generator Issues
If you get generator-related errors, try specifying the exact version or use a different generator:
- Use `-G "Visual Studio 16 2019"` for VS 2019
- Use `-G "Visual Studio 17 2022"` for VS 2022
- Use `-G "NMake Makefiles"` or `-G "Ninja"` for alternative build systems

### Missing Dependencies
If you encounter linking errors:
1. Verify that OpenSSL/GmSSL is built with SM algorithms support
2. Check that the correct version (x64) of the libraries is being linked
3. Make sure header files are accessible

## Test Structure

The test files created are located in the `tests/` directory:

- `test_sm2.cpp` - SM2 algorithm tests
- `test_sm3.cpp` - SM3 algorithm tests
- `test_sm4.cpp` - SM4 algorithm tests
- `test_comprehensive.cpp` - Integration tests
- `test_interop.cpp` - Cross-language validation
- `test_main.cpp` - Master test suite

All tests validate:
- Functionality of encryption, decryption, signing, and verification
- Support for byte arrays and string-based APIs
- HEX and Base64 encoding/decoding
- UTF-8 and other character set handling
- Cross-language compatibility

## Notes

- The library follows the same API patterns as the Java implementation for maximum interoperability
- All tests include proper error handling and validation
- The string-based APIs support both HEX and Base64 encodings as required
- Character set support includes UTF-8 and other encodings as specified