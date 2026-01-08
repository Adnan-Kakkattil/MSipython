# Ebantis Setup - Complete Installation Flow Documentation

## Overview
Ebantis_setup is a comprehensive Windows installation system for the Ebantis V4 agent. It handles installation, uninstallation, autostart configuration, credential management, and integration with Wazuh security agent.

---

## Architecture Components

### 1. **Entry Point: `installation_run.py`**
   - Checks for admin privileges
   - Elevates to admin if needed
   - Imports and executes main installation logic

### 2. **Core Modules (Cython-compiled)**
   - `installation.pyx` - Main installation logic
   - `uninstallation.pyx` - Uninstallation logic
   - `autostart.pyx` - Startup configuration
   - `utils/service.pyx` - API service connections

### 3. **Supporting Files**
   - `encryption.py` - AES decryption for API credentials
   - `utils/config.py` - Configuration and paths
   - `update/AutoUpdaterService.py` - Windows service for updates

---

## COMPLETE INSTALLATION FLOW (Step-by-Step)

### **PHASE 1: Initialization & Prerequisites**

#### Step 1.1: Admin Privilege Check
- **File**: `installation_run.py`
- **Action**: 
  - Checks if running with admin privileges using `ctypes.windll.shell32.IsUserAnAdmin()`
  - If not admin, relaunches EXE with `ShellExecuteW` using "runas" verb
  - Waits for elevation before proceeding

#### Step 1.2: Logger Initialization
- **File**: `utils/config.py`
- **Action**:
  - Creates log file: `Ebantis_setup_YYYY-MM-DD.log` in current directory
  - Configures loguru logger with rotation at midnight
  - Logs all installation activities

#### Step 1.3: Directory Structure Creation
- **File**: `utils/config.py`
- **Directories Created**:
  ```
  C:\Program Files\EbantisV4\
  C:\Program Files\EbantisV4\data\
  C:\Program Files\EbantisV4\data\EbantisV4\
  C:\Program Files\EbantisV4\data\EbantisV4\utils\
  C:\Program Files\EbantisV4\data\EbantisV4\update\
  C:\ProgramData\EbantisV4\
  C:\ProgramData\EbantisV4\Logs\
  C:\ProgramData\EbantisV4\tenant_info\
  C:\ProgramData\EbantisV4\user_collection\
  C:\ProgramData\EbantisV4\user_collection\{username}\
  ```

#### Step 1.4: System Information Gathering
- **File**: `utils/config.py`
- **Data Collected**:
  - **Machine ID**: UUID from `wmic csproduct get uuid` (fallback to MAC-based hash)
  - **Hostname**: `socket.gethostname()`
  - **Username**: `os.getlogin()`
  - **Display Name**: From `whoami /user` (extracts domain\username)
  - **UPN**: From `whoami /upn` (User Principal Name)
  - **Email**: From Win32API `GetUserNameEx(8)` or PowerShell `whoami /upn`

---

### **PHASE 2: Tenant Information Initialization**

#### Step 2.1: Extract Branch ID from Executable Name
- **File**: `installation.pyx` → `extract_branch_id_from_filename()`
- **Action**:
  - Parses executable name: `EbantisTracker_{branch_id}.exe`
  - Extracts branch_id from filename
  - Logs extracted branch_id

#### Step 2.2: Fetch Tenant Information from API
- **File**: `installation.pyx` → `get_tenant_info_by_branch_id()`
- **API Call**:
  - URL: `https://qaebantisv4service.thekosmoz.com/api/v1/branches/branch/{branch_id}`
  - Method: GET
  - Headers: `Authorization: Bearer {auth_token}`
- **Response Parsing**:
  - Extracts `tenantUniqueId`
  - Extracts `companyUniqueId`
  - Uses provided `branchId`
- **Global Variables Set**:
  - `GLOBAL_TENANT_ID`
  - `GLOBAL_COMPANY_ID`
  - `GLOBAL_BRANCH_ID`

#### Step 2.3: Save Tenant Info to JSON
- **File**: `installation.pyx` → `save_tenant_name_to_json()`
- **Location**: `C:\ProgramData\EbantisV4\tenant_info\tenant_details.json`
- **Content**:
  ```json
  {
    "tenant_id": "...",
    "company_id": "...",
    "branch_id": "..."
  }
  ```

#### Step 2.4: Authentication Token Retrieval
- **File**: `installation.pyx` → `get_auth_token()`
- **API Call**:
  - URL: `https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login`
  - Method: POST
  - Payload: `{"userName": "internalmanager@mail.com", "password": "#@Admin&eu1"}`
- **Response**: Extracts `accessToken` for subsequent API calls

---

### **PHASE 3: Installation Validation**

#### Step 3.1: Check Installation Allowed
- **File**: `installation.pyx` → `check_installation_allowed()`
- **API Call**:
  - URL: `https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}`
  - Method: GET
  - Headers: `Authorization: Bearer {auth_token}`
- **Validation**:
  - Compares `installedDeviceCount` vs `allowedInstallationCount`
  - Blocks installation if limit reached
  - Shows error message if blocked

#### Step 3.2: Internet Connection Check
- **File**: `installation.pyx` → `is_connected()`
- **Action**:
  - Attempts socket connection to `1.1.1.1:53`
  - Timeout: 5 seconds
  - Aborts if no connection

---

### **PHASE 4: UI Initialization**

#### Step 4.1: PyQt6 GUI Launch
- **File**: `installation.pyx` → `InstallerUI.__init__()`
- **Components**:
  - Progress bar (0-100%)
  - Progress label (status text)
  - Exit button (disabled until completion)
- **Auto-start**: Installation begins 500ms after UI shows

---

### **PHASE 5: Installation Worker Thread**

#### Step 5.1: Clear Previous Installation
- **File**: `installation.pyx` → `InstallWorker.run()` → `End_task()`
- **Actions**:
  - Identifies all `.exe` files in:
    - `C:\Program Files\EbantisV4\data\EbantisV4\utils\`
    - `C:\Program Files\EbantisV4\data\EbantisV4\update\`
    - `C:\Program Files\EbantisV4\data\EbantisV4\`
  - Kills running processes by name using `psutil`
  - Waits up to 10 seconds for processes to terminate
  - Removes directories in parallel threads:
    - `utils\`
    - `update\`
    - `EbantisV4\`
  - Removes old startup shortcuts (`.bat` files)

#### Step 5.2: Initial Installation Status Update
- **File**: `installation.pyx` → `upsert_installation_data()`
- **API Call**:
  - URL: `https://qaebantisv4service.thekosmoz.com/api/v1/app-installations`
  - Method: POST
  - Payload:
    ```json
    {
      "branchUniqueId": "...",
      "tenantUniqueId": "...",
      "hostName": "...",
      "installedOn": "ISO datetime",
      "isDownloaded": false,
      "isInstalled": false,
      "versionId": "...",
      "status": "inprogress",
      "userName": "...",
      "userExternalId": 0,
      "email": "..."
    }
    ```
- **Version ID**: Fetched from `update_version_details()` API

---

### **PHASE 6: Application Package Download**

#### Step 6.1: Download Main Package
- **File**: `installation.pyx` → `cloud_dwnld()`
- **API Call**:
  - URL: `https://qaebantisapiv4.thekosmoz.com/DownloadLatestversion?branch_id={branch_id}`
  - Method: POST
  - Headers: `IsInternalCall: true`, `ClientId: EbantisTrack`
- **Download Strategy**:
  - **Multi-threaded** (if file > 5MB):
    - 4 parallel threads
    - Range-based downloads (byte ranges)
    - Writes to: `C:\ProgramData\EbantisV4\Ebantisv4.zip`
  - **Single-threaded** (if file ≤ 5MB):
    - Streams download in 8KB chunks
- **Validation**:
  - Checks file exists and size > 0
  - Validates ZIP file format using `zipfile.is_zipfile()`

#### Step 6.2: Extract Main Package
- **File**: `installation.pyx` → `_robust_extract_zip()`
- **Extraction**:
  - Destination: `C:\Program Files\EbantisV4\data\`
  - Handles nested root directories (strips unnecessary top-level folder)
  - Extracts all files and folders
- **Cleanup**: Removes ZIP file after successful extraction

#### Step 6.3: Update Download Status
- **File**: `installation.pyx` → `upsert_installation_data()`
- **Status Update**: `isDownloaded: true`, `status: "inprogress"`

---

### **PHASE 7: Parallel Operations**

#### Step 7.1: Folder Permission Updates (Parallel)
- **File**: `installation.pyx` → `update_permission()`
- **Folders Modified**:
  - `C:\ProgramData\EbantisV4\user_collection\`
  - `C:\Program Files\EbantisV4\data\downloaded_version\`
  - `C:\Program Files\EbantisV4\data\EbantisV4\`
- **PowerShell Command**:
  ```powershell
  $acl = Get-Acl $folderPath
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users",
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [InheritanceFlags]::ContainerInherit -bor [InheritanceFlags]::ObjectInherit,
    [PropagationFlags]::None,
    [AccessControlType]::Allow
  )
  $acl.AddAccessRule($rule)
  Set-Acl -Path $folderPath -AclObject $acl
  ```

#### Step 7.2: Wazuh Agent Installation (Parallel)
- **File**: `installation.pyx` → `install_wazuh()`
- **Sub-steps**:

  **7.2.1: Download Wazuh MSI**
  - URL: `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi`
  - Destination: `%TEMP%\wazuh-agent.msi`
  - Method: PowerShell `Invoke-WebRequest`

  **7.2.2: Silent MSI Installation**
  - Command: `msiexec.exe /i wazuh-agent.msi /qn WAZUH_MANAGER=135.235.18.31 WAZUH_AGENT_GROUP=default,Windows WAZUH_AGENT_NAME={hostname}`
  - Flags: `/qn` (quiet, no UI)
  - Accepts exit codes: 0, 3010 (reboot required), 1641

  **7.2.3: Start Wazuh Service**
  - Command: `NET START WazuhSvc`
  - Waits 5 seconds
  - Verifies service is running using `psutil.win_service_get()`

  **7.2.4: Verify Agent Connection**
  - Checks state file: `C:\Program Files\ossec-agent\wazuh-agent.state` (or `Program Files (x86)`)
  - Waits up to 120 seconds for "connected" status
  - Polls every 5 seconds
  - Shows warning if still "pending" after timeout

  **7.2.5: Autostart Configuration**
  - **File**: `autostart.pyx` → `Autostart()`
  - **Actions**:
    - Terminates existing `EbantisV4.exe` and `AutoUpdationService.exe` processes
    - Waits 2 seconds
    - Starts `EbantisV4.exe` from `C:\Program Files\EbantisV4\data\EbantisV4\`
    - Starts `AutoUpdationService.exe` from same location
    - Creates startup shortcuts:
      - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\EbantisV4.lnk`
      - `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\AutoUpdationService.lnk`
    - Sets working directory for shortcuts

---

### **PHASE 8: Finalization**

#### Step 8.1: Final Installation Status Update
- **File**: `installation.pyx` → `upsert_installation_data()`
- **Status**: `isDownloaded: true`, `isInstalled: true`, `status: "installed"`

#### Step 8.2: Update Installed Device Count
- **File**: `installation.pyx` → `update_installed_device_count()`
- **API Call**:
  - URL: `https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}/installed-count`
  - Method: PUT
  - Payload: `{"tenantUniqueId": "...", "installedDeviceCount": 1}`
  - Increments device count by 1

#### Step 8.3: Start Additional Executables
- **File**: `installation.pyx` → `exe_run()`
- **Action**:
  - Scans `utils\` and `update\` folders for `.exe` files
  - Launches each executable using `os.startfile()`
  - Logs each started process

#### Step 8.4: UI Completion
- **File**: `installation.pyx` → `on_installation_complete()`
- **Actions**:
  - Shows success/failure message box
  - Enables Exit button
  - Closes UI and exits application

---

## UNINSTALLATION FLOW

### **Step U1: User Confirmation**
- **File**: `uninstallation.pyx` → `run_uninstallation()`
- **Action**: Shows confirmation dialog: "Are you sure you want to uninstall Ebantis?"

### **Step U2: Terminate Processes**
- **File**: `uninstallation.pyx` → `End_task()`
- **Action**:
  - Kills all `.exe` processes in `utils\` and `update\` folders
  - Uses threading for parallel termination

### **Step U3: Remove Startup Shortcuts**
- **File**: `uninstallation.pyx` → `remove_startup_file()`
- **Action**:
  - Scans startup folder for `.lnk` files matching executable names
  - Removes shortcuts in parallel threads

### **Step U4: Uninstall Wazuh**
- **File**: `uninstallation.pyx` → `uninstall_wazuh()`
- **Action**:
  - Finds Wazuh product code from registry: `{45F86F88-FE8F-4F39-90B6-BA91CFC9FADC}`
  - Runs: `msiexec.exe /x {product_code} /qn /norestart`
  - Stops service: `NET STOP WazuhSvc`

### **Step U5: Update MongoDB Status**
- **File**: `uninstallation.pyx` → `uninstall_record()`
- **Action**:
  - Retrieves credentials from SQLite database
  - Decrypts credentials using `decrypt_response()`
  - Connects to MongoDB using connection string
  - Updates `installed_users` collection: `{"status": "Uninstalled"}`

### **Step U6: Remove Files and Folders**
- **File**: `uninstallation.pyx` → `remove()`
- **Removes**:
  - `C:\Program Files\EbantisV4\` (entire directory)
  - `C:\ProgramData\EbantisV4\` (entire directory)

### **Step U7: Completion Message**
- Shows success/failure alert based on step completion count (6 total steps)

---

## CREDENTIAL MANAGEMENT

### **Encryption/Decryption Flow**

#### Encryption (Server-side, not in this codebase)
1. Data encrypted with AES-256-CBC
2. IV = Key (same as secret key)
3. Obfuscation applied:
   - Character shift (+5)
   - XOR with key: `"PZH83QL"`
   - Base64 encoding

#### Decryption (Client-side)
- **File**: `encryption.py` → `decrypt_response()`
- **Steps**:
  1. Base64 decode
  2. Reverse XOR with key `"PZH83QL"`
  3. Reverse character shift (-5)
  4. AES decrypt with key: `"NlN57G7OEBZRvSaL"`
  5. Unpad PKCS7 padding
  6. Parse JSON

### **Credential Storage**
- **Location**: SQLite database at `C:\ProgramData\EbantisV4\user_collection\{username}\tracking_system.db`
- **Table**: `api_data`
- **Schema**: `id TEXT PRIMARY KEY, data TEXT`
- **Content**: Raw JSON response from API (with `obfuscatedEncryptedData` field)

### **Credential Retrieval**
- **File**: `utils/service.pyx` → `connect_service()`
- **API Call**:
  - URL: `https://ebantistrackapi.metlone.com/api/v1/Connection/GetAllConnections?tenant={tenant_name}`
  - Headers: `IsInternalCall: true`, `ClientId: EbantisTrack`
- **Storage**: Stores raw JSON response in SQLite
- **Decryption**: Decrypts `obfuscatedEncryptedData` field when needed

---

## API ENDPOINTS USED

1. **Authentication**: `POST https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login`
2. **Branch Info**: `GET https://qaebantisv4service.thekosmoz.com/api/v1/branches/branch/{branch_id}`
3. **Installation Check**: `GET https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}`
4. **Version Details**: `GET https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}`
5. **Save Installation**: `POST https://qaebantisv4service.thekosmoz.com/api/v1/app-installations`
6. **Update Device Count**: `PUT https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/{branch_id}/installed-count`
7. **Download Package**: `POST https://ebantisapiv4.thekosmoz.com/DownloadLatestversion?branch_id={branch_id}`
8. **Get Credentials**: `GET https://ebantistrackapi.metlone.com/api/v1/Connection/GetAllConnections?tenant={tenant_name}`
9. **Register Agent**: `POST https://ebantisapiv4.thekosmoz.com/register-agent`
10. **User Onboarding**: `POST https://ebantisapiv4.thekosmoz.com/user_onboard/`

---

## KEY FILES AND THEIR ROLES

| File | Purpose |
|------|---------|
| `installation_run.py` | Entry point, admin check, launcher |
| `installation.pyx` | Main installation logic (1463 lines) |
| `uninstallation.pyx` | Complete uninstallation process |
| `autostart.pyx` | Startup shortcut creation and process management |
| `encryption.py` | AES decryption for API credentials |
| `utils/config.py` | Paths, constants, system info gathering |
| `utils/service.pyx` | API connections, credential retrieval |
| `update/AutoUpdaterService.py` | Windows service for automatic updates |
| `setup.py` | Cython build configuration |
| `installation_run.spec` | PyInstaller spec for EXE creation |
| `install.ps1` | PowerShell alternative installer (1159 lines) |

---

## ERROR HANDLING

- All operations wrapped in try-except blocks
- Errors logged to daily log files
- User-facing error messages via PyQt6 message boxes
- Installation status tracked in API (inprogress/failed/installed)
- Graceful degradation: continues installation even if some steps fail (with warnings)

---

## SECURITY CONSIDERATIONS

1. **Admin Privileges**: Required for installation
2. **Encrypted Credentials**: AES-256-CBC with obfuscation
3. **API Authentication**: Bearer tokens for protected endpoints
4. **File Permissions**: Modified to allow Users group access
5. **Service Account**: Hardcoded credentials for internal API access
6. **Network Security**: HTTPS endpoints (with `verify=False` in some cases)

---

## DEPENDENCIES

- **Core**: Python 3.10, Cython 3.0.11
- **GUI**: PyQt6 6.8.0
- **Networking**: requests 2.32.3, pymongo 4.11.3
- **Cryptography**: pycryptodome 3.21.0
- **System**: pywin32 308, psutil 7.1.0
- **Build**: pyinstaller 6.12.0
- **Other**: loguru, sqlite3, dns.resolver, pyautogui

---

## NOTES

- Installation is **automated** - no user interaction required after launch
- Branch ID is extracted from **executable filename**
- All operations are **logged** to daily log files
- **Parallel execution** used for downloads and installations
- **MongoDB** connection verified via DNS SRV record check (in some flows)
- **Wazuh agent** configured with specific manager IP and groups
- **Startup shortcuts** ensure persistence across reboots

