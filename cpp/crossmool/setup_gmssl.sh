#!/bin/bash
# setup_gmssl.sh - Script to set up GmSSL for crossmool project

echo "Setting up GmSSL for Crossmool C++ library..."

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "Error: CMakeLists.txt not found. Please run this script from the crossmool/cpp/crossmool directory."
    exit 1
fi

# Attempt to install GmSSL
echo "Attempting to install GmSSL..."

# For Windows with vcpkg (since it's available based on our earlier check)
if command -v vcpkg &> /dev/null; then
    echo "Using vcpkg to install GmSSL dependencies..."
    # Note: Since GmSSL is not in standard vcpkg repos, we'll compile from source
    echo "Note: GmSSL is not currently available in standard vcpkg repositories."
    echo "Compiling GmSSL from source..."

    if [ ! -d "GmSSL" ]; then
        echo "Cloning GmSSL repository..."
        git clone https://github.com/guanzhi/GmSSL.git
    fi

    cd GmSSL
    mkdir -p build
    cd build

    if command -v cl &> /dev/null; then
        # Using Visual Studio
        cmake .. -G "Visual Studio 16 2019" -A x64 -DCMAKE_BUILD_TYPE=Release
        cmake --build . --config Release
    else
        # Using GCC/MinGW
        cmake .. -DCMAKE_BUILD_TYPE=Release
        make -j$(nproc 2>/dev/null || echo 4)
    fi

    cd ../..
    echo "GmSSL compiled successfully!"
else
    echo "vcpkg not found. You may need to install it first."
    echo "Visit: https://github.com/microsoft/vcpkg"
    exit 1
fi

echo ""
echo "GmSSL setup complete!"
echo ""
echo "To build crossmool with GmSSL support, run:"
echo "  mkdir -p build_gmssl && cd build_gmssl"
echo "  cmake .. -DUSE_SYSTEM_GMSSL=ON -DCMAKE_PREFIX_PATH=../GmSSL/build"  # adjust path as needed
echo "  cmake --build . --config Release"
echo ""
echo "To build with stub implementations (no GmSSL required):"
echo "  mkdir -p build_stub && cd build_stub"
echo "  cmake .. -DUSE_SYSTEM_GMSSL=OFF"
echo "  cmake --build . --config Release"