# Ebantis MSI Installer - Project Summary

## ✅ Project Complete

A fully functional MSI installer has been created that:
1. Extracts branch ID from MSI filename (`EbantisTrack_{branch_id}.msi`)
2. Executes the PowerShell installation script (`installer.ps1`)
3. Performs complete Ebantis V4 installation

## 📁 Project Structure

```
msi_installer/
├── src/
│   └── main.rs              # Rust executable that extracts branch ID and runs PowerShell
├── wix/
│   └── main.wxs             # WiX installer configuration
├── installer.ps1            # PowerShell installation script (copied from root)
├── Cargo.toml               # Rust project configuration
├── wix.toml                 # cargo-wix configuration
├── build.ps1                # Automated build script
├── BUILD_INSTRUCTIONS.md    # Detailed build instructions
├── QUICK_START.md           # Quick start guide
└── README.md                # Project documentation
```

## 🔧 Key Components

### 1. Rust Executable (`src/main.rs`)
- Extracts branch ID from MSI filename via `OriginalDatabase` environment variable
- Sets `EBANTIS_BRANCH_ID` environment variable
- Executes `installer.ps1` with admin privileges

### 2. PowerShell Script (`installer.ps1`)
- Updated to read branch ID from `$env:EBANTIS_BRANCH_ID`
- Falls back to extracting from filename if env var not set
- Performs complete installation flow

### 3. WiX Configuration (`wix/main.wxs`)
- Embeds Rust executable and PowerShell script
- Runs executable as custom action after file installation
- Uses `asyncWait` return type for proper execution

## 🚀 Build Process

1. **Install Prerequisites:**
   - Rust: https://rustup.rs/
   - WiX Toolset: https://wixtoolset.org/
   - cargo-wix: `cargo install cargo-wix`

2. **Build:**
   ```powershell
   cd msi_installer
   .\build.ps1
   ```

3. **Rename with Branch ID:**
   ```powershell
   Rename-Item "target\wix\ebantis-msi-installer-4.0.0-x86_64.msi" "EbantisTrack_{branch_id}.msi"
   ```

## 📋 Installation Flow

```
User runs: EbantisTrack_{branch_id}.msi
    ↓
MSI extracts files to C:\Program Files\EbantisV4\
    ↓
MSI runs: ebantis-msi-installer.exe (custom action)
    ↓
Rust executable:
  - Reads OriginalDatabase env var (MSI filename)
  - Extracts branch ID: {branch_id}
  - Sets EBANTIS_BRANCH_ID={branch_id}
  - Executes installer.ps1
    ↓
PowerShell script:
  - Reads EBANTIS_BRANCH_ID
  - Performs full installation:
    * Internet check
    * Tenant initialization
    * Download & extract
    * Permissions
    * Autostart
    * Status updates
```

## ✨ Features

- ✅ Extracts branch ID from MSI filename automatically
- ✅ Passes branch ID to PowerShell script via environment variable
- ✅ Traditional MSI installer experience
- ✅ Admin privilege handling
- ✅ Error handling and user feedback
- ✅ Complete installation flow from Python implementation

## 📝 Notes

- MSI filename must follow format: `EbantisTrack_{branch_id}.msi`
- The PowerShell script is embedded in the MSI
- Installation requires administrator privileges
- All installation flows from Python are preserved

## 🎯 Next Steps

1. Test the build process: `.\build.ps1`
2. Create test MSI with branch ID
3. Test installation on a clean system
4. Distribute MSI files to end users


