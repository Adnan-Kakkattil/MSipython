# Quick Start Guide - Ebantis MSI Installer

## Overview

This MSI installer extracts the branch ID from the MSI filename (`EbantisTrack_{branch_id}.msi`) and executes the PowerShell installation script.

## Quick Build

```powershell
cd msi_installer
.\build.ps1
```

This will:
1. Check Rust installation
2. Install cargo-wix if needed
3. Copy installer.ps1 if missing
4. Build the Rust executable
5. Create the MSI package

## Output

The MSI will be created at:
```
target\wix\ebantis-msi-installer-4.0.0-x86_64.msi
```

## Usage

1. **Rename the MSI with branch ID:**
   ```powershell
   Rename-Item "target\wix\ebantis-msi-installer-4.0.0-x86_64.msi" "EbantisTrack_{your_branch_id}.msi"
   ```

2. **Distribute the MSI** to end users

3. **Users double-click the MSI** to install

## How It Works

```
EbantisTrack_{branch_id}.msi
    ↓
MSI extracts files to C:\Program Files\EbantisV4\
    ↓
MSI runs ebantis-msi-installer.exe
    ↓
Rust executable extracts branch ID from MSI filename
    ↓
Sets EBANTIS_BRANCH_ID environment variable
    ↓
Executes installer.ps1
    ↓
PowerShell script performs full installation
```

## Requirements

- Rust (https://rustup.rs/)
- WiX Toolset (https://wixtoolset.org/)
- cargo-wix (`cargo install cargo-wix`)

## Troubleshooting

See `BUILD_INSTRUCTIONS.md` for detailed troubleshooting.


