# Build script for creating MSI installer
# This script builds the Rust executable and creates the MSI installer

Write-Host "=== Building Ebantis MSI Installer ===" -ForegroundColor Cyan

# Check if Rust is installed
$rustInstalled = Get-Command cargo -ErrorAction SilentlyContinue
if (-not $rustInstalled) {
    Write-Host "ERROR: Rust/Cargo is not installed!" -ForegroundColor Red
    Write-Host "Please install Rust from https://rustup.rs/" -ForegroundColor Yellow
    exit 1
}

# Check if cargo-wix is installed
$cargoWixInstalled = cargo wix --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installing cargo-wix..." -ForegroundColor Yellow
    cargo install cargo-wix
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install cargo-wix!" -ForegroundColor Red
        exit 1
    }
}

# Build the Rust project
Write-Host "`nBuilding Rust project..." -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Rust build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build successful!" -ForegroundColor Green

# Copy installer.ps1 to target directory for inclusion in MSI
Write-Host "`nPreparing files..." -ForegroundColor Cyan
$installerPs1 = "..\installer.ps1"
if (Test-Path $installerPs1) {
    $targetDir = "target\release"
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    Copy-Item $installerPs1 "$targetDir\installer.ps1" -Force
    Write-Host "Copied installer.ps1 to target directory" -ForegroundColor Green
} else {
    Write-Host "WARNING: installer.ps1 not found at $installerPs1" -ForegroundColor Yellow
}

# Build MSI using cargo-wix
Write-Host "`nBuilding MSI installer..." -ForegroundColor Cyan
cargo wix
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: MSI build failed!" -ForegroundColor Red
    Write-Host "Make sure WiX Toolset is installed from https://wixtoolset.org/" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n=== Build Complete ===" -ForegroundColor Green
Write-Host "MSI installer should be in: target\wix\" -ForegroundColor Cyan

