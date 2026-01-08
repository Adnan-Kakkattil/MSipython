# Build script for Ebantis MSI Installer
# This script builds the Rust executable and creates the MSI package

$ErrorActionPreference = "Stop"

Write-Host "=== Building Ebantis MSI Installer ===" -ForegroundColor Cyan

# Check if Rust is installed
Write-Host "`n[1/5] Checking Rust installation..." -ForegroundColor Yellow
try {
    $rustVersion = rustc --version 2>&1
    Write-Host "  ✓ Rust found: $rustVersion" -ForegroundColor Green
} catch {
    Write-Host "  ✗ Rust not found. Please install Rust from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# Check if cargo-wix is installed
Write-Host "`n[2/5] Checking cargo-wix installation..." -ForegroundColor Yellow
try {
    $wixVersion = cargo wix --version 2>&1
    Write-Host "  ✓ cargo-wix found" -ForegroundColor Green
} catch {
    Write-Host "  ✗ cargo-wix not found. Installing..." -ForegroundColor Yellow
    cargo install cargo-wix
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ✗ Failed to install cargo-wix" -ForegroundColor Red
        exit 1
    }
    Write-Host "  ✓ cargo-wix installed successfully" -ForegroundColor Green
}

# Ensure installer.ps1 exists
Write-Host "`n[3/5] Checking installer.ps1..." -ForegroundColor Yellow
if (-not (Test-Path "installer.ps1")) {
    if (Test-Path "..\installer.ps1") {
        Copy-Item "..\installer.ps1" -Destination "." -Force
        Write-Host "  ✓ Copied installer.ps1 from parent directory" -ForegroundColor Green
    } else {
        Write-Host "  ✗ installer.ps1 not found!" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "  ✓ installer.ps1 found" -ForegroundColor Green
}

# Build Rust executable
Write-Host "`n[4/5] Building Rust executable..." -ForegroundColor Yellow
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ✗ Build failed" -ForegroundColor Red
    exit 1
}
Write-Host "  ✓ Build successful" -ForegroundColor Green

# Create MSI using cargo-wix
Write-Host "`n[5/5] Creating MSI package..." -ForegroundColor Yellow

# Check if wix directory exists, create if not
if (-not (Test-Path "wix")) {
    New-Item -ItemType Directory -Path "wix" | Out-Null
}

# Run cargo wix
cargo wix --nocapture
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ✗ MSI creation failed" -ForegroundColor Red
    Write-Host "  Note: Make sure WiX Toolset is installed from https://wixtoolset.org/" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n=== Build Complete ===" -ForegroundColor Green
Write-Host "MSI file created in target/wix/ directory" -ForegroundColor Cyan
Write-Host "`nTo use with a branch ID, rename the MSI to: EbantisTrack_{branch_id}.msi" -ForegroundColor Yellow


