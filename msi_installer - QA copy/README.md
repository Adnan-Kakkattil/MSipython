# Ebantis V4 MSI Installer

This Rust-based MSI installer extracts the branch ID from the MSI filename and executes the PowerShell installation script.

## Requirements

1. **Rust** (latest stable version)
2. **cargo-wix** - Install with: `cargo install cargo-wix`
3. **WiX Toolset** - Download from https://wixtoolset.org/
4. **Visual Studio Build Tools** (for Windows MSVC toolchain)

## Building the MSI

1. **Install dependencies:**
   ```powershell
   cargo install cargo-wix
   ```

2. **Build the Rust executable:**
   ```powershell
   cargo build --release
   ```

3. **Create the MSI:**
   ```powershell
   cargo wix
   ```

4. **Rename the MSI with branch ID:**
   The MSI should be named: `EbantisTrack_{branch_id}.msi`
   
   Example: `EbantisTrack_abc123def456.msi`

## How It Works

1. The MSI installer extracts the branch ID from its filename (format: `EbantisTrack_{branch_id}.msi`)
2. Sets the `EBANTIS_BRANCH_ID` environment variable
3. Executes the embedded `installer.ps1` script
4. The PowerShell script reads the branch ID from the environment variable and proceeds with installation

## File Structure

```
msi_installer/
├── Cargo.toml          # Rust project configuration
├── src/
│   └── main.rs        # Main installer executable
├── wix/
│   └── main.wxs       # WiX installer configuration
├── installer.ps1      # PowerShell installation script (copied here)
└── README.md          # This file
```

## Installation Flow

1. User double-clicks `EbantisTrack_{branch_id}.msi`
2. MSI extracts files to `C:\Program Files\EbantisV4\`
3. MSI runs `ebantis-msi-installer.exe` which:
   - Extracts branch ID from MSI filename
   - Sets `EBANTIS_BRANCH_ID` environment variable
   - Executes `installer.ps1` with admin privileges
4. PowerShell script performs full installation

## Notes

- The MSI requires administrator privileges
- The PowerShell script will request elevation if not running as admin
- The branch ID must be in the MSI filename for the installer to work
