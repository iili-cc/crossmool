#!/bin/bash
# Build script for crossmool C++ library

echo "Setting up build environment..."

# Check if we have the required tools
if ! command -v cmake &> /dev/null; then
    echo "CMake is required but not found. Please install CMake."
    exit 1
fi

if ! command -v g++ &> /dev/null && ! command -v cl &> /dev/null; then
    echo "A C++ compiler (g++ or MSVC) is required but not found."
    exit 1
fi

# Create build directory if it doesn't exist
mkdir -p build
cd build

echo "Configuring project with CMake..."
# Try different generators based on platform
if command -v cl &> /dev/null; then
    # Windows with Visual Studio
    cmake .. -G "Visual Studio 16 2019" || cmake .. -G "MinGW Makefiles"
else
    # Unix-like with gcc
    cmake .. -G "Unix Makefiles"
fi

if [ $? -ne 0 ]; then
    echo "CMake configuration failed."
    exit 1
fi

echo "Building the project..."
if command -v cl &> /dev/null; then
    # On Windows with Visual Studio
    cmake --build . --config Release
else
    # On Unix-like systems
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
fi

if [ $? -ne 0 ]; then
    echo "Build failed."
    exit 1
fi

echo "Build completed successfully!"
echo "Running tests..."
ctest --output-on-failure

echo "Build and test script completed."