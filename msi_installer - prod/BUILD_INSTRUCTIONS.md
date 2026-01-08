# Building Ebantis MSI Installer

## Prerequisites

1. **Rust** (latest stable) - https://rustup.rs/
2. **WiX Toolset v3.11+** - https://wixtoolset.org/releases/
3. **cargo-wix** - Install with: `cargo install cargo-wix`
4. **Visual Studio Build Tools** (for Windows MSVC toolchain)

## Step-by-Step Build Process

### 1. Install Prerequisites

```powershell
# Install Rust (if not already installed)
# Download and run rustup-init.exe from https://rustup.rs/

# Install cargo-wix
cargo install cargo-wix

# Install WiX Toolset
# Download from https://wixtoolset.org/releases/
# Add WiX bin directory to PATH
```

### 2. Prepare Files

Ensure `installer.ps1` is in the `msi_installer` directory:
```powershell
cd msi_installer
if (-not (Test-Path installer.ps1)) {
    Copy-Item ..\installer.ps1 .
}
```

### 3. Build the MSI

**Option A: Using the build script (Recommended)**
```powershell
.\build.ps1
```

**Option B: Manual build**
```powershell
# Build Rust executable
cargo build --release

# Create MSI
cargo wix
```

### 4. Locate the MSI

The MSI will be created in: `target\wix\ebantis-msi-installer-4.0.0-x86_64.msi`

### 5. Rename with Branch ID

Rename the MSI to include the branch ID:
```powershell
Rename-Item "target\wix\ebantis-msi-installer-4.0.0-x86_64.msi" "EbantisTrack_{branch_id}.msi"
```

Example:
```powershell
Rename-Item "target\wix\ebantis-msi-installer-4.0.0-x86_64.msi" "EbantisTrack_abc123def456.msi"
```

## How It Works

1. **MSI Installation:**
   - User runs `EbantisTrack_{branch_id}.msi`
   - MSI extracts files to `C:\Program Files\EbantisV4\`
   - MSI runs `ebantis-msi-installer.exe` as a custom action

2. **Rust Executable:**
   - Extracts branch ID from MSI filename (via `OriginalDatabase` property)
   - Sets `EBANTIS_BRANCH_ID` environment variable
   - Executes `installer.ps1` with the branch ID

3. **PowerShell Script:**
   - Reads branch ID from `$env:EBANTIS_BRANCH_ID`
   - Performs full installation (download, extract, configure, etc.)

## Troubleshooting

### Error: "cargo-wix not found"
```powershell
cargo install cargo-wix
```

### Error: "WiX Toolset not found"
- Download and install WiX from https://wixtoolset.org/
- Add `C:\Program Files (x86)\WiX Toolset v3.11\bin` to PATH
- Restart PowerShell

### Error: "Failed to extract branch ID"
- Ensure MSI filename follows format: `EbantisTrack_{branch_id}.msi`
- Check that `OriginalDatabase` property is available during installation

### Error: "installer.ps1 not found"
- Ensure `installer.ps1` is in the `msi_installer` directory
- The script will be embedded in the MSI

## Testing

1. Build the MSI with a test branch ID:
   ```powershell
   Rename-Item "target\wix\ebantis-msi-installer-4.0.0-x86_64.msi" "EbantisTrack_test123.msi"
   ```

2. Run the MSI:
   ```powershell
   .\EbantisTrack_test123.msi
   ```

3. Verify:
   - Branch ID is extracted correctly
   - PowerShell script executes
   - Installation completes successfully


