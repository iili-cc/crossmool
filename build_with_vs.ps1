# PowerShell script to build crossmool with Visual Studio Build Tools and CMake

Write-Host "Setting up build environment for crossmool with Visual Studio Build Tools..." -ForegroundColor Green

# Check if we're running on Windows
if ($env:OS -ne "Windows_NT") {
    Write-Host "This script is designed for Windows with Visual Studio Build Tools" -ForegroundColor Red
    exit 1
}

# Define the Visual Studio Build Tools path
$vsPath = "D:\Programs\VisualStudio\BuildTools\VC\Tools\MSVC\14.41.34120\bin\Hostx64\x64"

# Check if the path exists
if (-Not (Test-Path $vsPath)) {
    Write-Host "Error: Visual Studio Build Tools not found at $vsPath" -ForegroundColor Red
    Write-Host "Available MSVC versions:" -ForegroundColor Yellow
    $msvcRoot = Split-Path $vsPath -Parent
    if (Test-Path (Split-Path $msvcRoot -Parent)) {
        Get-ChildItem (Split-Path $msvcRoot -Parent) -Directory | ForEach-Object { Write-Host $_.Name }
    }
    exit 1
}

Write-Host "Found Visual Studio Build Tools at: $vsPath" -ForegroundColor Green

# Check if CMake is installed
$cmakeInstalled = Get-Command cmake -ErrorAction SilentlyContinue
if (-Not $cmakeInstalled) {
    Write-Host "CMake is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Installing CMake via Chocolatey or downloading from official site..." -ForegroundColor Yellow

    # Try to install via Chocolatey if available
    $chocoInstalled = Get-Command choco -ErrorAction SilentlyContinue
    if ($chocoInstalled) {
        Write-Host "Installing CMake via Chocolatey..." -ForegroundColor Cyan
        choco install cmake --confirm
    } else {
        Write-Host "Please install CMake manually from https://cmake.org/download/" -ForegroundColor Red
        Write-Host "Then run this script again." -ForegroundColor Yellow
        exit 1
    }
} else {
    Write-Host "CMake is available: $(cmake --version)" -ForegroundColor Green
}

# Change to the project directory
$projectDir = "$PSScriptRoot\..\cpp\crossmool"
if (-Not (Test-Path $projectDir)) {
    Write-Host "Project directory not found: $projectDir" -ForegroundColor Red
    exit 1
}

Write-Host "Changing to project directory: $projectDir" -ForegroundColor Cyan
Set-Location $projectDir

# Create build directory if it doesn't exist
$buildDir = ".\build"
if (-Not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
    Write-Host "Created build directory: $buildDir" -ForegroundColor Green
}

# Change to build directory
Set-Location $buildDir

Write-Host "Running CMake configuration..." -ForegroundColor Cyan

# Set up the environment variables to include Visual Studio tools
$env:PATH = "$vsPath;$env:PATH"

# Verify compiler availability
Write-Host "Verifying compiler availability..." -ForegroundColor Cyan
if (Get-Command cl -ErrorAction SilentlyContinue) {
    Write-Host "Microsoft C/C++ Compiler (cl.exe) found: $(cl 2>&1 | Select-Object -First 1)" -ForegroundColor Green
} else {
    Write-Host "Microsoft C/C++ Compiler (cl.exe) not accessible" -ForegroundColor Red
    Write-Host "Full PATH: $env:PATH" -ForegroundColor Yellow
    exit 1
}

# Configure the project with CMake using the Visual Studio generator
$cmakeCmd = "cmake .. -G `"Visual Studio 16 2019`" -A x64 -DCMAKE_BUILD_TYPE=Release"
Write-Host "Executing: $cmakeCmd" -ForegroundColor Cyan
try {
    Invoke-Expression $cmakeCmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "CMake configuration failed with exit code $LASTEXITCODE" -ForegroundColor Red

        # Try with different generator
        Write-Host "Trying with 'Ninja' generator..." -ForegroundColor Yellow
        if (Get-Command ninja -ErrorAction SilentlyContinue) {
            $cmakeCmd2 = "cmake .. -G `"Ninja`" -DCMAKE_BUILD_TYPE=Release"
            Write-Host "Executing: $cmakeCmd2" -ForegroundColor Cyan
            Invoke-Expression $cmakeCmd2
            if ($LASTEXITCODE -ne 0) {
                throw "CMake configuration failed with Ninja generator too"
            }
        } else {
            throw "Neither Visual Studio nor Ninja generators worked, and Ninja is not installed"
        }
    }
} catch {
    Write-Host "CMake configuration failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "CMake configuration successful!" -ForegroundColor Green

# Build the project
Write-Host "Building the project..." -ForegroundColor Cyan
try {
    $buildCmd = "cmake --build . --config Release"
    Write-Host "Executing: $buildCmd" -ForegroundColor Cyan
    Invoke-Expression $buildCmd
    if ($LASTEXITCODE -ne 0) {
        throw "Build failed with exit code $LASTEXITCODE"
    }
} catch {
    Write-Host "Build failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully!" -ForegroundColor Green

# Run the tests if they were built
Write-Host "Running tests..." -ForegroundColor Cyan
try {
    $ctestCmd = "ctest -C Release --output-on-failure"
    Write-Host "Executing: $ctestCmd" -ForegroundColor Cyan
    Invoke-Expression $ctestCmd
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Some tests failed with exit code $LASTEXITCODE" -ForegroundColor Yellow
    } else {
        Write-Host "All tests passed!" -ForegroundColor Green
    }
} catch {
    Write-Host "Test execution failed: $_" -ForegroundColor Red
    # Continue, as this might be expected if tests weren't built properly
}

Write-Host "Build and test process completed." -ForegroundColor Green
Write-Host "You can find the built libraries and executables in the build directory." -ForegroundColor Cyan