#!/bin/bash
# install_gmssl.sh - Script to install GmSSL dependency

set -e  # Exit on any error

echo "Installing GmSSL dependency..."

# Detect platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')

# For Windows (Git Bash or WSL), we'll handle differently
if [[ "$PLATFORM" =~ .*mingw.* ]] || [[ "$PLATFORM" =~ .*win.* ]]; then
    PLATFORM="windows"
fi

echo "Detected platform: $PLATFORM"

case $PLATFORM in
    linux*)
        # Try to install via package manager first
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y pkg-config libssl-dev
            echo "Attempting to install GmSSL via apt..."
            # Check if GmSSL package exists in repository
            if apt-cache search gmssl &> /dev/null; then
                sudo apt-get install -y libgmssl-dev
            else
                echo "GmSSL not available via apt, compiling from source..."
                INSTALL_FROM_SOURCE=1
            fi
        elif command -v yum &> /dev/null; then
            sudo yum install -y pkgconfig openssl-devel
            echo "Attempting to install GmSSL via yum..."
            if yum search gmssl &> /dev/null; then
                sudo yum install -y gmssl-devel
            else
                echo "GmSSL not available via yum, compiling from source..."
                INSTALL_FROM_SOURCE=1
            fi
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y pkgconfig openssl-devel
            echo "Attempting to install GmSSL via dnf..."
            if dnf search gmssl &> /dev/null; then
                sudo dnf install -y gmssl-devel
            else
                echo "GmSSL not available via dnf, compiling from source..."
                INSTALL_FROM_SOURCE=1
            fi
        else
            INSTALL_FROM_SOURCE=1
        fi
        ;;
    darwin*)  # macOS
        if command -v brew &> /dev/null; then
            echo "Installing dependencies via Homebrew..."
            brew install pkg-config openssl
            # Check if GmSSL formula exists
            if brew search gmssl &> /dev/null || brew search --desc gmssl &> /dev/null; then
                brew install gmssl
            else
                echo "GmSSL not available via Homebrew, compiling from source..."
                INSTALL_FROM_SOURCE=1
            fi
        else
            INSTALL_FROM_SOURCE=1
        fi
        ;;
    windows*)
        echo "Windows detected. Using vcpkg to install GmSSL..."
        if command -v vcpkg &> /dev/null; then
            vcpkg install gmssl
        else
            echo "vcpkg not found. Please install vcpkg first."
            echo "You can install it via: git clone https://github.com/microsoft/vcpkg.git"
            echo "Then: ./vcpkg/bootstrap-vcpkg.sh (Linux/macOS) or vcpkg\\bootstrap-vcpkg.bat (Windows)"
            echo "Finally: vcpkg integrate install"
            echo "For this script to continue, please install vcpkg first."
            exit 1
        fi
        ;;
    *)
        INSTALL_FROM_SOURCE=1
        ;;
esac

# If package managers didn't work, compile from source
if [[ "$INSTALL_FROM_SOURCE" == "1" ]]; then
    echo "Compiling GmSSL from source..."

    # Install prerequisites
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y build-essential cmake git
    elif command -v yum &> /dev/null || command -v dnf &> /dev/null; then
        sudo yum install -y gcc gcc-c++ make cmake git
    elif command -v brew &> /dev/null; then
        brew install cmake git
    fi

    # Clone and build GmSSL
    if [ ! -d "GmSSL" ]; then
        git clone https://github.com/guanzhi/GmSSL.git
    fi

    cd GmSSL
    mkdir -p build
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    sudo make install
    cd ../..

    echo "GmSSL compiled and installed successfully!"
fi

# Verify installation
echo "Verifying GmSSL installation..."
if pkg-config --exists gmssl; then
    echo "GmSSL is properly installed:"
    pkg-config --modversion gmssl
    pkg-config --cflags gmssl
    pkg-config --libs gmssl
else
    echo "Warning: GmSSL not found by pkg-config, but may be installed elsewhere"
    # Check if gmssl command is available
    if command -v gmssl &> /dev/null; then
        gmssl version || echo "GmSSL command available but version check failed"
    else
        echo "GmSSL not found in system. Please ensure it's installed and in your PATH/PKG_CONFIG_PATH."
        exit 1
    fi
fi

echo "GmSSL installation completed!"