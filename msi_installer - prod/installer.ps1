<#
.SYNOPSIS
    Ebantis V4 Installer - PowerShell Version
    Complete installation flow converted from Python/Cython implementation

.DESCRIPTION
    Handles the complete installation of the Ebantis Agent, including:
    - Prerequisite checks (Admin, Internet)
    - Tenant Information Initialization
    - Installation Validation
    - Application Package Download & Extraction
    - Folder Permission Updates
    - Autostart Configuration
    - Status Updates to API

.NOTES
    Version: 4.0
    Based on: installation.pyx flow
    Excludes: Uninstaller, Wazuh installation
#>

# -------------------------------------------------------------------------
# STEP 1: ADMIN PRIVILEGE CHECK & INITIALIZATION
# -------------------------------------------------------------------------

function Test-IsAdmin {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [System.Security.Principal.WindowsPrincipal]$Identity
    return $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    Write-Host "Requesting administrative privileges..." -ForegroundColor Yellow
    # Pass environment variable to elevated process
    $envArgs = if ($env:EBANTIS_BRANCH_ID) { "-Command `"`$env:EBANTIS_BRANCH_ID='$env:EBANTIS_BRANCH_ID'; & '$PSCommandPath'`"" } else { "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" }
    Start-Process powershell -ArgumentList $envArgs -Verb RunAs
    Exit
}

# Configuration Constants
$AppName = "EbantisV4"
$ProgramFilesPath = [System.IO.Path]::Combine($env:ProgramFiles, $AppName)
$ProgramDataPath = [System.IO.Path]::Combine($env:ProgramData, $AppName)
$LogFolder = [System.IO.Path]::Combine($ProgramDataPath, "Logs")
$LogFile = [System.IO.Path]::Combine($LogFolder, "Ebantis_setup_$(Get-Date -Format 'yyyy-MM-dd').log")

# Create Directories
$DirsToCreate = @(
    $ProgramFilesPath,
    $ProgramDataPath,
    $LogFolder,
    [System.IO.Path]::Combine($ProgramFilesPath, "data"),
    [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName, "utils"),
    [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName, "update"),
    [System.IO.Path]::Combine($ProgramFilesPath, "data", "downloaded_version"),
    [System.IO.Path]::Combine($ProgramDataPath, "tenant_info"),
    [System.IO.Path]::Combine($ProgramDataPath, "user_collection"),
    [System.IO.Path]::Combine($ProgramDataPath, "user_collection", $env:USERNAME)
)

foreach ($Dir in $DirsToCreate) {
    if (-not (Test-Path -Path $Dir)) {
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
    }
}

# Logging Function
function Write-Log {
    param(
        [Parameter(Mandatory=$true)] [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR")] [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "$Timestamp | $Level | $Message"
    $Color = "Cyan"
    if ($Level -eq "ERROR") { $Color = "Red" }
    elseif ($Level -eq "WARNING") { $Color = "Yellow" }
   
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
}

Write-Log "Starting Ebantis V4 Installer..." "INFO"
Write-Log "Running with administrative privileges." "INFO"

# -------------------------------------------------------------------------
# STEP 2: SYSTEM INFORMATION GATHERING
# -------------------------------------------------------------------------

function Get-MachineID {
    # Try getting UUID from WMIC (matches Python: wmic csproduct get uuid)
    try {
        $UUID = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
        if ($UUID -and $UUID -ne "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") {
            Write-Log "Machine ID retrieved from WMI: $UUID" "INFO"
            return $UUID
        }
    } catch {
        Write-Log "Failed to get UUID via WMI: $_" "WARNING"
    }
   
    # Fallback to Machine GUID from registry
    try {
        $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction Stop
        Write-Log "Machine ID retrieved from registry: $($reg.MachineGuid)" "INFO"
        return $reg.MachineGuid
    } catch {
        Write-Log "Failed to get Machine GUID from registry: $_" "WARNING"
        $fallbackId = [guid]::NewGuid().ToString()
        Write-Log "Using fallback Machine ID: $fallbackId" "WARNING"
        return $fallbackId
    }
}

function Get-DisplayName {
    # Matches Python: whoami /user extraction
    try {
        $result = whoami /user /fo csv | ConvertFrom-Csv
        $userInfo = $result.UserName
        if ($userInfo -match "\\") {
            # Extract username from domain\username format
            $displayName = $userInfo.Split('\')[-1]
            Write-Log "Display Name: $displayName" "INFO"
            return $displayName
        }
        return $userInfo
    } catch {
        Write-Log "Failed to get display name: $_" "WARNING"
        return $env:USERNAME
    }
}

function Get-Upn {
    # Matches Python: whoami /upn
    try {
        $upn = whoami /upn 2>$null
        if ($LASTEXITCODE -eq 0 -and $upn -and $upn -match "@") {
            Write-Log "UPN: $upn" "INFO"
            return $upn.Trim()
        }
    } catch {
        Write-Log "Failed to get UPN: $_" "WARNING"
    }
    return ""
}

function Get-UserEmail {
    # Matches Python: Win32API GetUserNameEx(8) or whoami /upn fallback
    try {
        # Try to get UPN first (for domain users)
        $upn = Get-Upn
        if ($upn -and $upn -match "@") {
            return $upn
        }
        
        # If not a domain user, construct email as username@hostname.internal
        $username = $env:USERNAME
        $hostname = $env:COMPUTERNAME
        $email = "${username}@${hostname}.internal"
        Write-Log "Constructed email: $email" "INFO"
        return $email
    } catch {
        Write-Log "Failed to get user email: $_" "WARNING"
        return "${env:USERNAME}@${env:COMPUTERNAME}.internal"
    }
}

function Test-InternetConnection {
    # Matches Python: socket.create_connection(("1.1.1.1", 53), timeout=5)
    # Improved version with multiple fallback methods
    Write-Log "Testing internet connection..." "INFO"
    
    # Method 1: Try socket connection to 1.1.1.1:53 (DNS port) - matches Python exactly
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect = $tcpClient.BeginConnect("1.1.1.1", 53, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne(5000, $false)  # 5 second timeout
        
        if ($wait) {
            try {
                $tcpClient.EndConnect($connect)
                $tcpClient.Close()
                Write-Log "Internet connection verified via socket connection to 1.1.1.1:53" "INFO"
                return $true
            } catch {
                $tcpClient.Close()
            }
        } else {
            $tcpClient.Close()
        }
    } catch {
        Write-Log "Socket connection test failed: $_" "WARNING"
    }
    
    # Method 2: Try Test-Connection (Ping) to 1.1.1.1
    try {
        $result = Test-Connection -ComputerName "1.1.1.1" -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($result) {
            Write-Log "Internet connection verified via ping to 1.1.1.1" "INFO"
            return $true
        }
    } catch {
        Write-Log "Ping test failed: $_" "WARNING"
    }
    
    # Method 3: Try Test-Connection to 8.8.8.8 (Google DNS) as fallback
    try {
        $result = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
        if ($result) {
            Write-Log "Internet connection verified via ping to 8.8.8.8" "INFO"
            return $true
        }
    } catch {
        Write-Log "Ping test to 8.8.8.8 failed: $_" "WARNING"
    }
    
    # Method 4: Try HTTP request to a reliable endpoint
    try {
        $response = Invoke-WebRequest -Uri "https://www.google.com" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) {
            Write-Log "Internet connection verified via HTTP request" "INFO"
            return $true
        }
    } catch {
        Write-Log "HTTP test failed: $_" "WARNING"
    }
    
    # All methods failed
    Write-Log "All internet connection tests failed. No internet connection detected." "ERROR"
    return $false
}

# Gather system information
$MachineID = Get-MachineID
$Hostname = $env:COMPUTERNAME
$Username = $env:USERNAME
$DisplayName = Get-DisplayName
$Email = Get-UserEmail
$Upn = Get-Upn

Write-Log "System Information:" "INFO"
Write-Log "  Machine ID: $MachineID" "INFO"
Write-Log "  Hostname: $Hostname" "INFO"
Write-Log "  Username: $Username" "INFO"
Write-Log "  Display Name: $DisplayName" "INFO"
Write-Log "  Email: $Email" "INFO"
Write-Log "  UPN: $Upn" "INFO"

# -------------------------------------------------------------------------
# STEP 3: ENCRYPTION/DECRYPTION MODULE
# -------------------------------------------------------------------------

$SecretKey = "NlN57G7OEBZRvSaL"
$XorKey = "PZH83QL"
$Shift = 5

function Deobfuscate-String {
    param([string]$InputString)
   
    try {
        # Step 1: Base64 Decode
        $Bytes = [Convert]::FromBase64String($InputString)
        $Decoded = [System.Text.Encoding]::UTF8.GetString($Bytes)
       
        # Step 2: XOR Reverse
        $Xored = ""
        for ($i = 0; $i -lt $Decoded.Length; $i++) {
            $Char = [int][char]$Decoded[$i]
            $KeyChar = [int][char]$XorKey[$i % $XorKey.Length]
            $Xored += [char]($Char -bxor $KeyChar)
        }
       
        # Step 3: Shift Reverse
        $Result = ""
        for ($i = 0; $i -lt $Xored.Length; $i++) {
            $Char = [int][char]$Xored[$i]
            $Val = ($Char - $Shift) % 256
            if ($Val -lt 0) { $Val += 256 }
            $Result += [char]$Val
        }
       
        return $Result
    } catch {
        Write-Log "Deobfuscation failed: $_" "ERROR"
        return $null
    }
}

function Decrypt-AES {
    param([string]$InputString)
   
    try {
        $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
        $IvBytes = $KeyBytes # IV = Key (matches Python)
       
        $Aes = [System.Security.Cryptography.Aes]::Create()
        $Aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $Aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $Aes.Key = $KeyBytes
        $Aes.IV = $IvBytes
       
        $Decryptor = $Aes.CreateDecryptor()
        $InputBytes = [Convert]::FromBase64String($InputString)
       
        $OutputBytes = $Decryptor.TransformFinalBlock($InputBytes, 0, $InputBytes.Length)
        return [System.Text.Encoding]::UTF8.GetString($OutputBytes)
    } catch {
        Write-Log "AES Decryption failed: $_" "ERROR"
        return $null
    }
}

function Decrypt-Response {
    param([string]$ObfuscatedEncryptedData)
   
    try {
        # Step 1: Deobfuscate
        $Step1 = Deobfuscate-String -InputString $ObfuscatedEncryptedData
        if (-not $Step1) { 
            Write-Log "Deobfuscation returned null/empty" "ERROR"
            return $null 
        }
        
        # Step 2: AES Decrypt
        $Step2 = Decrypt-AES -InputString $Step1
        if (-not $Step2) { 
            Write-Log "AES decryption returned null/empty" "ERROR"
            return $null 
        }
        
        # Step 3: Parse JSON
        $parsed = $Step2 | ConvertFrom-Json
        if ($parsed) {
            Write-Log "Credentials decrypted successfully." "INFO"
        } else {
            Write-Log "JSON parsing returned null" "ERROR"
        }
        
        return $parsed
    } catch {
        Write-Log "Decrypt-Response exception: $_" "ERROR"
        return $null
    }
}

# -------------------------------------------------------------------------
# STEP 4: TENANT INFORMATION INITIALIZATION
# -------------------------------------------------------------------------

function Get-AuthToken {
    # Matches Python: get_auth_token()
    try {
        $authApiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/users/auth/login"
        $payload = @{
            userName = "internalmanager@mail.com"
            password = "#@Admin&eu1"
        } | ConvertTo-Json
        
        Write-Log "Authenticating to get access token..." "INFO"
        
        $response = Invoke-RestMethod -Uri $authApiUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 30
        
        if ($response.accessToken) {
            Write-Log "Access token obtained successfully." "INFO"
            return $response.accessToken
        } else {
            Write-Log "No access token found in authentication response." "WARNING"
            return $null
        }
    } catch {
        Write-Log "Authentication API request failed: $_" "ERROR"
        return $null
    }
}

function Get-BranchIdFromExecutable {
    # Matches Python: extract_branch_id_from_filename()
    # Also supports branch ID from environment variable (for MSI installer)
    try {
        # First, check if branch ID is provided via environment variable (from MSI)
        if ($env:EBANTIS_BRANCH_ID) {
            $branchId = $env:EBANTIS_BRANCH_ID
            Write-Log "Branch ID retrieved from environment variable: $branchId" "INFO"
            return $branchId
        }
        
        # Try to extract from executable filename
        $exeName = Split-Path -Leaf $PSCommandPath
        Write-Log "Executable name: $exeName" "INFO"
        
        # Try to extract branch_id from format: EbantisTrack_{branch_id}.exe or .msi
        if ($exeName -match "EbantisTrack_(.+)\.(exe|msi)") {
            $branchId = $matches[1]
            Write-Log "Extracted branch_id from filename: $branchId" "INFO"
            return $branchId
        }
        
        Write-Log "Could not extract branch_id from filename: $exeName" "WARNING"
        return $null
    } catch {
        Write-Log "Error extracting branch_id from filename: $_" "ERROR"
        return $null
    }
}

function Get-TenantInfoByBranchId {
    param([string]$BranchId)
    
    # Matches Python: get_tenant_info_by_branch_id()
    try {
        $authToken = Get-AuthToken
        if (-not $authToken) {
            Write-Log "Failed to obtain authentication token for branch lookup." "ERROR"
            return $null
        }
        
        $apiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/branches/branch/$BranchId"
        $headers = @{
            "Authorization" = "Bearer $authToken"
        }
        
        Write-Log "Fetching tenant info from API for branch_id: $BranchId" "INFO"
        
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -TimeoutSec 30
        
        if ($response) {
            $tenantId = $response.tenantUniqueId
            $companyId = $response.companyUniqueId
            
            Write-Log "Retrieved tenant info - tenant_id: $tenantId, company_id: $companyId, branch_id: $BranchId" "INFO"
            
            return @{
                tenantId = $tenantId
                companyId = $companyId
                branchId = $BranchId
            }
        }
        
        Write-Log "No data found for branch_id: $BranchId" "WARNING"
        return $null
    } catch {
        Write-Log "API request error while fetching tenant info for branch_id $BranchId : $_" "ERROR"
        return $null
    }
}

function Save-TenantInfoToJson {
    param(
        [string]$TenantId,
        [string]$CompanyId,
        [string]$BranchId
    )
    
    # Matches Python: save_tenant_name_to_json()
    try {
        $tenantInfoPath = [System.IO.Path]::Combine($ProgramDataPath, "tenant_info")
        $jsonFilePath = [System.IO.Path]::Combine($tenantInfoPath, "tenant_details.json")
        
        # Ensure directory exists
        if (-not (Test-Path $tenantInfoPath)) {
            New-Item -ItemType Directory -Path $tenantInfoPath -Force | Out-Null
        }
        
        $tenantData = @{
            tenant_id = $TenantId
            company_id = $CompanyId
            branch_id = $BranchId
        } | ConvertTo-Json
        
        $tenantData | Out-File -FilePath $jsonFilePath -Encoding UTF8 -Force
        Write-Log "Tenant info saved successfully to JSON file: $jsonFilePath" "INFO"
        return $true
    } catch {
        Write-Log "Error writing tenant info to JSON file: $_" "ERROR"
        return $false
    }
}

function Initialize-TenantInfo {
    # Matches Python: initialize_tenant_info()
    try {
        # Extract branch_id from executable filename
        $branchId = Get-BranchIdFromExecutable
        
        if (-not $branchId) {
            Write-Log "Failed to extract branch_id from executable filename." "ERROR"
            return $null
        }
        
        # Fetch tenant info from API using branch_id
        $tenantInfo = Get-TenantInfoByBranchId -BranchId $branchId
        
        if (-not $tenantInfo) {
            Write-Log "Failed to fetch tenant information from API." "ERROR"
            return $null
        }
        
        # Save tenant info to JSON file
        if (-not (Save-TenantInfoToJson -TenantId $tenantInfo.tenantId -CompanyId $tenantInfo.companyId -BranchId $tenantInfo.branchId)) {
            Write-Log "Failed to save tenant info to JSON file." "WARNING"
        }
        
        Write-Log "Tenant info initialized - tenant_id: $($tenantInfo.tenantId), company_id: $($tenantInfo.companyId), branch_id: $($tenantInfo.branchId)" "INFO"
        return $tenantInfo
    } catch {
        Write-Log "Failed to initialize tenant info: $_" "ERROR"
        return $null
    }
}

# -------------------------------------------------------------------------
# STEP 5: INSTALLATION VALIDATION
# -------------------------------------------------------------------------

function Get-VersionDetails {
    param([string]$BranchId)
    
    # Matches Python: update_version_details()
    try {
        $authToken = Get-AuthToken
        if (-not $authToken) {
            Write-Log "Failed to obtain authentication token for version details." "ERROR"
            return $null
        }
        
        $apiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$BranchId"
        $headers = @{
            "Authorization" = "Bearer $authToken"
        }
        
        Write-Log "Fetching version details from API: $apiUrl" "INFO"
        
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -TimeoutSec 30
        
        if ($response -and $response.versionId) {
            $versionId = $response.versionId
            Write-Log "Latest Version_Id retrieved from API: $versionId" "INFO"
            return $versionId
        }
        
        Write-Log "No version_id found in API response for branch_id: $BranchId" "WARNING"
        return $null
    } catch {
        Write-Log "API request error while fetching version details for branch $BranchId : $_" "ERROR"
        return $null
    }
}

function Test-InstallationAllowed {
    param([string]$BranchId)
    
    # Matches Python: check_installation_allowed()
    try {
        $authToken = Get-AuthToken
        if (-not $authToken) {
            $msg = "Failed to obtain authentication token for installation check."
            Write-Log $msg "ERROR"
            return $false, $msg
        }
        
        $apiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$BranchId"
        $headers = @{
            "Authorization" = "Bearer $authToken"
        }
        
        Write-Log "Fetching app version details from API: $apiUrl" "INFO"
        
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -TimeoutSec 30
        
        if ($response) {
            $allowedCount = $response.allowedInstallationCount
            $installedCount = $response.installedDeviceCount
            
            if ($installedCount -lt $allowedCount) {
                $msg = "Installation allowed for branch $BranchId ($installedCount/$allowedCount)"
                Write-Log $msg "INFO"
                return $true, $msg
            } else {
                $msg = "Installation not allowed for branch $BranchId : Maximum installations reached ($installedCount/$allowedCount)"
                Write-Log $msg "WARNING"
                return $false, $msg
            }
        } else {
            $msg = "No data found for branch_id: $BranchId"
            Write-Log $msg "WARNING"
            return $false, $msg
        }
    } catch {
        $msg = "API request error while checking installation for branch $BranchId : $_"
        Write-Log $msg "ERROR"
        return $false, $msg
    }
}

# -------------------------------------------------------------------------
# STEP 6: API STATUS UPDATE FUNCTIONS
# -------------------------------------------------------------------------

function Update-InstallationData {
    param(
        [string]$TenantId,
        [string]$BranchId,
        [bool]$StatusFlag,
        [bool]$InstallationFlag,
        [string]$Status
    )
    
    # Matches Python: upsert_installation_data()
    try {
        $versionId = Get-VersionDetails -BranchId $BranchId
        if (-not $versionId) {
            Write-Log "Failed to get version ID, continuing without it." "WARNING"
        }
        
        # Match Python: datetime.now().isoformat() format
        $installedDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        
        # Match Python: user_name_value = display_name if display_name else user_name
        $userNameValue = if ($DisplayName) { $DisplayName } else { $Username }
        $emailValue = if ($Email) { $Email } else { "" }
        
        $payload = @{
            branchUniqueId = $BranchId
            tenantUniqueId = $TenantId
            hostName = $Hostname
            installedOn = $installedDate
            isDownloaded = $StatusFlag
            isInstalled = $InstallationFlag
            versionId = if ($versionId) { $versionId } else { "" }
            status = $Status
            userName = $userNameValue
            userExternalId = 0
            email = $emailValue
        } | ConvertTo-Json -Depth 10
        
        $authToken = Get-AuthToken
        if (-not $authToken) {
            Write-Log "Failed to obtain authentication token for saving installation data." "ERROR"
            return $false
        }
        
        $apiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/app-installations"
        $headers = @{
            "Authorization" = "Bearer $authToken"
        }
        
        Write-Log "Saving installation data to API for host: $Hostname" "INFO"
        Write-Log "Payload: $payload" "INFO"
        
        $response = Invoke-RestMethod -Uri $apiUrl -Method Post -Body $payload -ContentType "application/json" -Headers $headers -TimeoutSec 30
        
        Write-Log "Installation data saved successfully for host: $Hostname" "INFO"
        return $true
    } catch {
        Write-Log "API request failed while saving installation data for host $Hostname : $_" "ERROR"
        return $false
    }
}

function Update-InstalledDeviceCount {
    param(
        [string]$BranchId,
        [string]$TenantId
    )
    
    # Matches Python: update_installed_device_count()
    # Note: This is a non-critical operation - installation can succeed even if this fails
    try {
        $authToken = Get-AuthToken
        if (-not $authToken) {
            $msg = "Failed to obtain authentication token for device count update (non-critical)."
            Write-Log $msg "WARNING"
            return $false, $msg
        }
        
        # Try the branch-based endpoint first
        $apiUrl = "https://ebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$BranchId/installed-count"
        $headers = @{
            "Authorization" = "Bearer $authToken"
            "Content-Type" = "application/json"
        }
        
        $payload = @{
            tenantUniqueId = $TenantId
            installedDeviceCount = 1
        } | ConvertTo-Json
        
        Write-Log "Updating installed device count for branch_id: $BranchId" "INFO"
        Write-Log "Payload: $payload" "INFO"
        
        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Method Put -Body $payload -ContentType "application/json" -Headers $headers -TimeoutSec 30
            
            $msg = "Installed device count updated successfully for branch_id: $BranchId"
            Write-Log $msg "INFO"
            return $true, $msg
        } catch {
            # If branch-based endpoint fails, try tenant-based endpoint (some APIs might use tenant_id)
            $httpError = $_.Exception.Response.StatusCode.value__
            if ($httpError -eq 404) {
                Write-Log "Branch-based endpoint returned 404, trying tenant-based endpoint..." "INFO"
                
                # Try alternative endpoint using tenant_id
                $apiUrlAlt = "https://ebantisv4service.thekosmoz.com/api/v1/app-versions/tenants/$TenantId/installed-count"
                try {
                    $response = Invoke-RestMethod -Uri $apiUrlAlt -Method Put -Body $payload -ContentType "application/json" -Headers $headers -TimeoutSec 30
                    $msg = "Installed device count updated successfully using tenant-based endpoint for tenant_id: $TenantId"
                    Write-Log $msg "INFO"
                    return $true, $msg
                } catch {
                    $msg = "Device count update failed on both endpoints (non-critical operation). Installation will continue. Error: $_"
                    Write-Log $msg "WARNING"
                    return $false, $msg
                }
            } else {
                throw  # Re-throw if it's not a 404
            }
        }
    } catch {
        $msg = "Device count update failed (non-critical operation). Installation completed successfully. Error: $_"
        Write-Log $msg "WARNING"
        return $false, $msg
    }
}

# -------------------------------------------------------------------------
# STEP 7: APPLICATION PACKAGE DOWNLOAD & EXTRACTION
# -------------------------------------------------------------------------

function Stop-EbantisProcesses {
    # Matches Python: End_task() - kills existing processes
    try {
        $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName)
        $UtilsFolder = [System.IO.Path]::Combine($MainFolder, "utils")
        $UpdateFolder = [System.IO.Path]::Combine($MainFolder, "update")
        
        $ProcessesToKill = @()
        
        # Check main folder for executables
        if (Test-Path $MainFolder) {
            $Exes = Get-ChildItem -Path $MainFolder -Filter "*.exe" -ErrorAction SilentlyContinue
            foreach ($Exe in $Exes) {
                $ProcessesToKill += $Exe.BaseName
            }
        }
        
        # Check utils folder
        if (Test-Path $UtilsFolder) {
            $Exes = Get-ChildItem -Path $UtilsFolder -Filter "*.exe" -ErrorAction SilentlyContinue
            foreach ($Exe in $Exes) {
                $ProcessesToKill += $Exe.BaseName
            }
        }
        
        # Check update folder
        if (Test-Path $UpdateFolder) {
            $Exes = Get-ChildItem -Path $UpdateFolder -Filter "*.exe" -ErrorAction SilentlyContinue
            foreach ($Exe in $Exes) {
                $ProcessesToKill += $Exe.BaseName
            }
        }
        
        # Kill all found processes
        $ProcessesToKill = $ProcessesToKill | Select-Object -Unique
        foreach ($ProcName in $ProcessesToKill) {
            $Procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
            if ($Procs) {
                Write-Log "Stopping process: $ProcName" "INFO"
                Stop-Process -Name $ProcName -Force -ErrorAction SilentlyContinue
            }
        }
        
        # Wait for processes to fully terminate
        if ($ProcessesToKill.Count -gt 0) {
            Write-Log "Waiting for processes to terminate..." "INFO"
            Start-Sleep -Seconds 3
        }
        
        return $true
    } catch {
        Write-Log "Error stopping processes: $_" "ERROR"
        return $false
    }
}

function Remove-ExistingInstallation {
    # Matches Python: remove() for existing directories
    try {
        $ExeDirectory = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName)
        $UpdateDirectory = [System.IO.Path]::Combine($ProgramFilesPath, "data")
        
        if (Test-Path $ExeDirectory) {
            Write-Log "Removing existing installation directory: $ExeDirectory" "INFO"
            Remove-Item -Path $ExeDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Remove the entire data directory to clean up
        if (Test-Path $UpdateDirectory) {
            Write-Log "Removing existing data directory: $UpdateDirectory" "INFO"
            Remove-Item -Path $UpdateDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Write-Log "Previous version removed successfully." "INFO"
        return $true
    } catch {
        Write-Log "Error removing existing installation: $_" "ERROR"
        return $false
    }
}

function Remove-StartupFile {
    # Matches Python: remove_startup_file() - removes old .bat files from startup
    try {
        $StartupFolder = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\StartUp")
        $BatchFilenames = @("ebantis")
        
        foreach ($filename in $BatchFilenames) {
            $BatchLocation = [System.IO.Path]::Combine($StartupFolder, "$filename.bat")
            if (Test-Path $BatchLocation) {
                Write-Log "Removing startup file: $BatchLocation" "INFO"
                Remove-Item -Path $BatchLocation -Force -ErrorAction SilentlyContinue
                Write-Log "Startup file removed successfully: $BatchLocation" "INFO"
            } else {
                # This is expected - old .bat files may not exist, which is fine
                Write-Log "Startup file not found (expected if clean install): $BatchLocation" "INFO"
            }
        }
        return $true
    } catch {
        Write-Log "Startup file removal error: $_" "ERROR"
        return $false
    }
}

function Download-AppPackage {
    param([string]$BranchId)
    
    # Matches Python: cloud_dwnld()
    try {
        # Correct path: DATA_FILE_PATH = C:\ProgramData\EbantisV4\Ebantisv4.zip
        $DownloadPath = [System.IO.Path]::Combine($ProgramDataPath, "Ebantisv4.zip")
        $ExtractPath = [System.IO.Path]::Combine($ProgramFilesPath, "data")
        
        # Ensure directory exists
        $DownloadDir = [System.IO.Path]::GetDirectoryName($DownloadPath)
        if (-not (Test-Path $DownloadDir)) {
            New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
        }
        if (-not (Test-Path $ExtractPath)) {
            New-Item -ItemType Directory -Path $ExtractPath -Force | Out-Null
        }
        
        $ApiUrl = "https://ebantisapiv4.thekosmoz.com/DownloadLatestversion?branch_id=$BranchId"
        $Headers = @{
            "IsInternalCall" = "true"
            "ClientId" = "EbantisTrack"
        }
        
        Write-Log "Starting main package download from API: $ApiUrl" "INFO"
        
        # Get file size first (for multi-threaded download if >5MB)
        # Note: API may not support HEAD method, so we skip it and download directly
        # Python code also catches exception for HEAD request
        $fileSize = 0
        try {
            # Try HEAD request, but don't fail if it doesn't work (API may not support it)
            $headResponse = Invoke-WebRequest -Uri $ApiUrl -Method Head -Headers $Headers -TimeoutSec 10 -ErrorAction Stop
            if ($headResponse.Headers['Content-Length']) {
                $fileSize = [long]$headResponse.Headers['Content-Length']
                Write-Log "File size from API: $fileSize bytes" "INFO"
            }
        } catch {
            # API doesn't support HEAD method (405) - this is expected and normal, continue with download
            if ($_.Exception.Response.StatusCode.value__ -eq 405) {
                Write-Log "API doesn't support HEAD method (expected) - proceeding with POST download" "INFO"
            } else {
                Write-Log "Could not get file size from API: $_" "INFO"
            }
            $fileSize = 0
        }
        
        # Download the file (single-threaded for now - multi-threaded requires complex file locking)
        # Note: PowerShell jobs have limitations with file streams, so using single-threaded download
        # which is still efficient for most use cases
        try {
            Write-Log "Downloading package (streaming download)..." "INFO"
            Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $Headers -OutFile $DownloadPath -TimeoutSec 600
            
            if (-not (Test-Path $DownloadPath) -or (Get-Item $DownloadPath).Length -eq 0) {
                Write-Log "Download failed: File not found or empty." "ERROR"
                return $false
            }
            
            Write-Log "Downloaded main package successfully. File size: $((Get-Item $DownloadPath).Length) bytes" "INFO"
        } catch {
            Write-Log "Download failed: $_" "ERROR"
            return $false
        }
        
        # Validate ZIP file
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($DownloadPath)
            $zip.Dispose()
            Write-Log "ZIP file validation successful." "INFO"
        } catch {
            Write-Log "Downloaded file is not a valid ZIP: $_" "ERROR"
            Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue
            return $false
        }
        
        # Extract the ZIP file with robust extraction (handles nested root directories)
        # Matches Python: _robust_extract_zip() function
        Write-Log "Extracting main package from $DownloadPath to $ExtractPath..." "INFO"
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($DownloadPath)
            
            # Get all entries (members)
            $entries = $zip.Entries
            $members = $entries | ForEach-Object { $_.FullName } | Where-Object { $_ -and -not ($_.TrimEnd('\', '/').EndsWith('/') -or $_.TrimEnd('\', '/').EndsWith('\')) }
            
            if ($members.Count -eq 0) {
                Write-Log "ZIP file appears to be empty" "ERROR"
                $zip.Dispose()
                return $false
            }
            
            # Find common root directory (matches Python: os.path.commonpath)
            # Normalize all paths to use forward slashes for comparison
            $normalizedMembers = $members | ForEach-Object { $_.Replace('\', '/') }
            
            # Find the common path prefix
            $rootDir = ""
            if ($normalizedMembers.Count -gt 0) {
                # Sort to get a consistent comparison
                $sortedMembers = $normalizedMembers | Sort-Object
                $firstPath = $sortedMembers[0]
                
                # Check if there's a common prefix
                $commonParts = $firstPath.Split('/')
                $rootDir = ""
                
                for ($i = 0; $i -lt $commonParts.Length; $i++) {
                    $testPath = ($commonParts[0..$i] -join '/')
                    if ($testPath) { $testPath += '/' }
                    
                    $allMatch = $true
                    foreach ($member in $sortedMembers) {
                        if (-not $member.StartsWith($testPath)) {
                            $allMatch = $false
                            break
                        }
                    }
                    
                    if ($allMatch) {
                        $rootDir = $testPath
                    } else {
                        break
                    }
                }
            }
            
            # Check if rootDir exists as a directory entry in the ZIP
            $rootDirNormalized = $rootDir.Replace('/', '\')
            $rootDirIsMember = $false
            if ($rootDir) {
                $rootDirCheck = $rootDir.TrimEnd('/')
                $rootDirIsMember = $members | Where-Object { 
                    $normalized = $_.Replace('\', '/')
                    $normalized -eq $rootDirCheck -or $normalized -eq "$rootDirCheck/" 
                } | Measure-Object | Select-Object -ExpandProperty Count
                $rootDirIsMember = $rootDirIsMember -gt 0
            }
            
            Write-Log "Detected root directory in ZIP: '$rootDir' (is member: $rootDirIsMember)" "INFO"
            
            # Extract all files with progress tracking
            $extractedCount = 0
            $totalFiles = ($entries | Where-Object { -not ($_.FullName.EndsWith('/') -or $_.FullName.EndsWith('\')) }).Count
            
            foreach ($entry in $entries) {
                # Skip directory-only entries
                if ($entry.FullName.EndsWith('/') -or $entry.FullName.EndsWith('\')) {
                    continue
                }
                
                # Determine target path
                $entryPath = $entry.FullName.Replace('/', '\')
                if ($rootDir -and $rootDirIsMember -and $entryPath.StartsWith($rootDirNormalized)) {
                    # Strip the root directory
                    $relativePath = $entryPath.Substring($rootDirNormalized.Length).TrimStart('\', '/')
                    $targetPath = [System.IO.Path]::Combine($ExtractPath, $relativePath)
                } else {
                    # Extract directly (no root directory to strip)
                    $targetPath = [System.IO.Path]::Combine($ExtractPath, $entryPath)
                }
                
                # Ensure target directory exists
                $targetDir = [System.IO.Path]::GetDirectoryName($targetPath)
                if ($targetDir -and -not (Test-Path $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }
                
                # Extract the file
                try {
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $targetPath, $true)
                    $extractedCount++
                    
                    # Log progress every 10%
                    if ($totalFiles -gt 0 -and ($extractedCount % ([Math]::Max(1, [Math]::Floor($totalFiles / 10))) -eq 0)) {
                        $progress = [Math]::Floor(($extractedCount / $totalFiles) * 100)
                        Write-Log "Extraction progress: $extractedCount/$totalFiles files ($progress%)" "INFO"
                    }
                } catch {
                    Write-Log "Warning: Failed to extract $($entry.FullName): $_" "WARNING"
                }
            }
            
            $zip.Dispose()
            Write-Log "Main package extracted successfully. Extracted $extractedCount files to: $ExtractPath" "INFO"
            
            # Verify extraction and handle multiple root directories (EbantisV4, EbantisV4prod)
            $topLevelDirs = Get-ChildItem -Path $ExtractPath -Directory -ErrorAction SilentlyContinue | Select-Object Name, FullName
            Write-Log "Top-level directories in extraction path:" "INFO"
            foreach ($dir in $topLevelDirs) {
                Write-Log "  - $($dir.Name)" "INFO"
            }
            
            # Handle case where ZIP contains multiple directories (e.g., EbantisV4 and EbantisV4prod)
            # Priority: Use EbantisV4prod if it exists and has executables, otherwise use EbantisV4
            $targetDir = [System.IO.Path]::Combine($ExtractPath, "EbantisV4")
            $ebantisProdDir = [System.IO.Path]::Combine($ExtractPath, "EbantisV4prod")
            
            $hasEbantisV4 = Test-Path $targetDir
            $hasEbantisProd = Test-Path $ebantisProdDir
            
            if ($hasEbantisProd) {
                Write-Log "Found EbantisV4prod directory" "INFO"
                # Check which directory has the executables
                $prodExe = [System.IO.Path]::Combine($ebantisProdDir, "EbantisV4.exe")
                $prodAutoUpdate = [System.IO.Path]::Combine($ebantisProdDir, "AutoUpdationService.exe")
                $prodAutoUpdatePy = [System.IO.Path]::Combine($ebantisProdDir, "AutoUpdationService.py")
                
                $hasExeInProd = (Test-Path $prodExe) -or (Test-Path $prodAutoUpdate) -or (Test-Path $prodAutoUpdatePy)
                
                if ($hasExeInProd) {
                    Write-Log "Executables found in EbantisV4prod, using as primary" "INFO"
                    # Merge EbantisV4 into EbantisV4prod, then rename EbantisV4prod to EbantisV4
                    if ($hasEbantisV4) {
                        Write-Log "Merging EbantisV4 into EbantisV4prod" "INFO"
                        Get-ChildItem -Path $targetDir -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                            $relativePath = $_.FullName.Substring($targetDir.Length).TrimStart('\', '/')
                            if ($relativePath) {
                                $targetPath = [System.IO.Path]::Combine($ebantisProdDir, $relativePath)
                                $targetParent = [System.IO.Path]::GetDirectoryName($targetPath)
                                
                                if (-not (Test-Path $targetParent)) {
                                    New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
                                }
                                
                                if (-not $_.PSIsContainer) {
                                    Copy-Item -Path $_.FullName -Destination $targetPath -Force -ErrorAction SilentlyContinue
                                }
                            }
                        }
                        Remove-Item -Path $targetDir -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    # Rename EbantisV4prod to EbantisV4
                    Rename-Item -Path $ebantisProdDir -NewName "EbantisV4" -Force -ErrorAction SilentlyContinue
                    Write-Log "Renamed EbantisV4prod to EbantisV4" "INFO"
                } else {
                    # Executables are in EbantisV4, merge EbantisV4prod into EbantisV4
                    Write-Log "Merging EbantisV4prod into EbantisV4" "INFO"
                    if (-not $hasEbantisV4) {
                        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                    }
                    
                    Get-ChildItem -Path $ebantisProdDir -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        $relativePath = $_.FullName.Substring($ebantisProdDir.Length).TrimStart('\', '/')
                        if ($relativePath) {
                            $targetPath = [System.IO.Path]::Combine($targetDir, $relativePath)
                            $targetParent = [System.IO.Path]::GetDirectoryName($targetPath)
                            
                            if (-not (Test-Path $targetParent)) {
                                New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
                            }
                            
                            if (-not $_.PSIsContainer) {
                                Copy-Item -Path $_.FullName -Destination $targetPath -Force -ErrorAction SilentlyContinue
                            }
                        }
                    }
                    
                    Remove-Item -Path $ebantisProdDir -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Log "Merged EbantisV4prod into EbantisV4" "INFO"
                }
            }
            
            # Verify executables at expected path
            $expectedExePath = [System.IO.Path]::Combine($ExtractPath, "EbantisV4", "EbantisV4.exe")
            $expectedAutoUpdateExe = [System.IO.Path]::Combine($ExtractPath, "EbantisV4", "AutoUpdationService.exe")
            $expectedAutoUpdatePy = [System.IO.Path]::Combine($ExtractPath, "EbantisV4", "AutoUpdationService.py")
            
            if (Test-Path $expectedExePath) {
                Write-Log "Verified: EbantisV4.exe found at $expectedExePath" "INFO"
            } else {
                Write-Log "Warning: EbantisV4.exe not found at expected path: $expectedExePath" "WARNING"
                # Search recursively for the executable
                $foundExe = Get-ChildItem -Path $ExtractPath -Filter "EbantisV4.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($foundExe) {
                    Write-Log "Found EbantisV4.exe at alternative location: $($foundExe.FullName)" "INFO"
                }
            }
            
            if (Test-Path $expectedAutoUpdateExe) {
                Write-Log "Verified: AutoUpdationService.exe found at $expectedAutoUpdateExe" "INFO"
            } elseif (Test-Path $expectedAutoUpdatePy) {
                Write-Log "Verified: AutoUpdationService.py found at $expectedAutoUpdatePy (will use .py version)" "INFO"
            } else {
                Write-Log "Warning: AutoUpdationService.exe/.py not found at expected paths" "WARNING"
                # Search recursively for the updater
                $foundUpdater = Get-ChildItem -Path $ExtractPath -Filter "AutoUpdationService.*" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($foundUpdater) {
                    Write-Log "Found AutoUpdationService at alternative location: $($foundUpdater.FullName)" "INFO"
                }
            }
        } catch {
            Write-Log "Extraction failed: $_" "ERROR"
            Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
            return $false
        }
        
        # Cleanup ZIP file
        try {
            Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue
            Write-Log "Cleanup successful: ZIP file removed." "INFO"
        } catch {
            Write-Log "Warning: Could not remove ZIP file: $_" "WARNING"
        }
        
        return $true
    } catch {
        Write-Log "Main package download/extraction failed: $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 8: FOLDER PERMISSION UPDATES
# -------------------------------------------------------------------------

function Update-FolderPermissions {
    param([string]$FolderPath)
    
    # Matches Python: update_permission() - PowerShell command
    try {
        if (-not (Test-Path $FolderPath)) {
            Write-Host "Folder does not exist: $FolderPath. Creating it." -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $FolderPath -Force | Out-Null
        }
        
        $acl = Get-Acl $FolderPath
        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Users",
            [System.Security.AccessControl.FileSystemRights]::Modify,
            $inheritanceFlags,
            $propagationFlags,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
        
        $acl.AddAccessRule($rule)
        Set-Acl -Path $FolderPath -AclObject $acl
        Write-Log "Permissions successfully updated for $FolderPath" "INFO"
        return $true
    } catch {
        Write-Log "Error updating permissions for $FolderPath : $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 9: AUTOSTART CONFIGURATION
# -------------------------------------------------------------------------

function Start-EbantisProcesses {
    # Matches Python: exe_run() - starts executables from utils and update folders
    try {
        $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName)
        $UtilsFolder = [System.IO.Path]::Combine($MainFolder, "utils")
        $UpdateFolder = [System.IO.Path]::Combine($MainFolder, "update")
        
        $pathsToCheck = @($UtilsFolder, $UpdateFolder)
        
        foreach ($path in $pathsToCheck) {
            if (Test-Path $path) {
                $executables = Get-ChildItem -Path $path -Filter "*.exe" -ErrorAction SilentlyContinue
                
                foreach ($exe in $executables) {
                    try {
                        $exePath = $exe.FullName
                        Start-Process -FilePath $exePath -WorkingDirectory $path
                        Write-Log "Started executable: $exePath" "INFO"
                    } catch {
                        Write-Log "Exception occurred while running $($exe.Name): $_" "ERROR"
                    }
                }
            } else {
                Write-Log "Path does not exist: $path" "WARNING"
            }
        }
        
        return $true
    } catch {
        Write-Log "Error occurred in running executables: $_" "ERROR"
        return $false
    }
}

function Add-StartupShortcuts {
    # Matches Python: autostart.pyx -> Autostart() - terminates processes FIRST, then starts, then creates shortcuts
    try {
        $StartupFolder = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\StartUp")
        $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName)
        $TargetExe = [System.IO.Path]::Combine($MainFolder, "EbantisV4.exe")
        # Check for both .exe and .py versions of AutoUpdationService
        $AutoUpdateExe = [System.IO.Path]::Combine($MainFolder, "AutoUpdationService.exe")
        $AutoUpdatePy = [System.IO.Path]::Combine($MainFolder, "AutoUpdationService.py")
        $updaterMainFolder = $MainFolder
        # Use .exe if available, otherwise .py
        if (-not (Test-Path $AutoUpdateExe) -and (Test-Path $AutoUpdatePy)) {
            $AutoUpdateExe = $AutoUpdatePy
            Write-Log "Using AutoUpdationService.py (AutoUpdationService.exe not found)" "INFO"
        }
        
        Write-Log "=== Autostart Process Started ===" "INFO"
        
        # Step 1: Kill existing processes (matches autostart.pyx terminate_process)
        Write-Log "Terminating existing processes..." "INFO"
        $processesToKill = @("EbantisV4", "AutoUpdationService")
        foreach ($procName in $processesToKill) {
            $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
            if ($procs) {
                Write-Log "Terminating process: $procName" "INFO"
                Stop-Process -Name $procName -Force -ErrorAction SilentlyContinue
            } else {
                Write-Log "No running instance found for: $procName" "INFO"
            }
        }
        
        # Wait 2 seconds (matches Python: time.sleep(2))
        Start-Sleep -Seconds 2
        
        # Step 2: Start processes (with comprehensive search if not at expected path)
        $ebantisStarted = $false
        $updaterStarted = $false
        
        # Comprehensive search for EbantisV4.exe
        if (-not (Test-Path $TargetExe)) {
            Write-Log "EbantisV4.exe not at expected path, searching recursively..." "INFO"
            $searchPath = [System.IO.Path]::Combine($ProgramFilesPath, "data")
            
            # Search in multiple locations
            $searchPaths = @(
                $searchPath,
                $MainFolder,
                [System.IO.Path]::Combine($searchPath, "EbantisV4"),
                [System.IO.Path]::Combine($searchPath, "EbantisV4prod")
            )
            
            $foundExe = $null
            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    $foundExe = Get-ChildItem -Path $path -Filter "EbantisV4.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($foundExe) {
                        break
                    }
                }
            }
            
            if ($foundExe) {
                $TargetExe = $foundExe.FullName
                $MainFolder = $foundExe.DirectoryName
                Write-Log "Found EbantisV4.exe at: $TargetExe" "INFO"
            } else {
                Write-Log "Could not find EbantisV4.exe in any location" "ERROR"
            }
        }
        
        if (Test-Path $TargetExe) {
            try {
                $process = Start-Process -FilePath $TargetExe -WorkingDirectory $MainFolder -PassThru
                Start-Sleep -Seconds 2  # Wait longer to ensure process starts
                
                # Verify process is running
                try {
                    $verifyProcess = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
                    if ($verifyProcess -and -not $verifyProcess.HasExited) {
                        Write-Log "Started: $TargetExe (PID: $($process.Id))" "INFO"
                        Write-Log "EbantisV4.exe is running successfully (PID: $($process.Id))" "INFO"
                        $ebantisStarted = $true
                    } else {
                        # Check if process is running by name (might have spawned child process)
                        $runningProcesses = Get-Process -Name "EbantisV4" -ErrorAction SilentlyContinue
                        if ($runningProcesses) {
                            Write-Log "EbantisV4.exe is running successfully (PID: $($runningProcesses[0].Id))" "INFO"
                            $ebantisStarted = $true
                        } else {
                            Write-Log "Warning: EbantisV4.exe process started but could not be verified as running" "WARNING"
                            $ebantisStarted = $true  # Consider it started for autostart configuration
                        }
                    }
                } catch {
                    # Try checking by process name
                    $runningProcesses = Get-Process -Name "EbantisV4" -ErrorAction SilentlyContinue
                    if ($runningProcesses) {
                        Write-Log "EbantisV4.exe is running successfully (PID: $($runningProcesses[0].Id))" "INFO"
                        $ebantisStarted = $true
                    } else {
                        Write-Log "Warning: Could not verify EbantisV4.exe process status: $_" "WARNING"
                        $ebantisStarted = $true  # Consider it started for autostart configuration
                    }
                }
            } catch {
                Write-Log "Error starting $TargetExe : $_" "ERROR"
            }
        } else {
            Write-Log "Executable not found: $TargetExe" "ERROR"
        }
        
        # Comprehensive search for AutoUpdationService (check both .exe and .py)
        $updaterFound = $false
        if (-not (Test-Path $AutoUpdateExe) -and -not (Test-Path $AutoUpdatePy)) {
            Write-Log "AutoUpdationService not at expected path, searching recursively..." "INFO"
            $searchPath = [System.IO.Path]::Combine($ProgramFilesPath, "data")
            
            # Search in multiple locations
            $searchPaths = @(
                $searchPath,
                $MainFolder,
                [System.IO.Path]::Combine($searchPath, "EbantisV4"),
                [System.IO.Path]::Combine($searchPath, "EbantisV4prod")
            )
            
            $foundAutoUpdate = $null
            foreach ($path in $searchPaths) {
                if (Test-Path $path) {
                    # Try .exe first
                    $foundAutoUpdate = Get-ChildItem -Path $path -Filter "AutoUpdationService.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($foundAutoUpdate) {
                        break
                    }
                    # Then try .py
                    $foundAutoUpdate = Get-ChildItem -Path $path -Filter "AutoUpdationService.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($foundAutoUpdate) {
                        break
                    }
                }
            }
            
            if ($foundAutoUpdate) {
                if ($foundAutoUpdate.Extension -eq ".exe") {
                    $AutoUpdateExe = $foundAutoUpdate.FullName
                    $AutoUpdatePy = $null
                } else {
                    $AutoUpdatePy = $foundAutoUpdate.FullName
                    $AutoUpdateExe = $AutoUpdatePy
                }
                $updaterMainFolder = $foundAutoUpdate.DirectoryName
                Write-Log "Found AutoUpdationService at: $($foundAutoUpdate.FullName)" "INFO"
                $updaterFound = $true
            } else {
                Write-Log "Could not find AutoUpdationService in any location" "ERROR"
            }
        } else {
            $updaterFound = $true
            if (Test-Path $AutoUpdateExe) {
                $updaterMainFolder = $MainFolder
            } elseif (Test-Path $AutoUpdatePy) {
                $updaterMainFolder = (Get-Item $AutoUpdatePy).DirectoryName
            }
        }
        
        if ($updaterFound -and (Test-Path $AutoUpdateExe)) {
            try {
                $process = $null
                if ($AutoUpdateExe.EndsWith(".py")) {
                    # If it's a Python file, we need to run it with Python
                    $pythonPath = Get-Command python -ErrorAction SilentlyContinue
                    if ($pythonPath) {
                        $process = Start-Process -FilePath $pythonPath.Path -ArgumentList "`"$AutoUpdateExe`"" -WorkingDirectory $updaterMainFolder -PassThru
                    } else {
                        Write-Log "Python not found to run AutoUpdationService.py" "WARNING"
                        $updaterStarted = $false
                    }
                } else {
                    $process = Start-Process -FilePath $AutoUpdateExe -WorkingDirectory $updaterMainFolder -PassThru
                }
                
                if ($process) {
                    Start-Sleep -Seconds 2  # Wait longer to ensure process starts
                    
                    # Verify process is running
                    try {
                        $verifyProcess = Get-Process -Id $process.Id -ErrorAction SilentlyContinue
                        if ($verifyProcess -and -not $verifyProcess.HasExited) {
                            Write-Log "Started: $AutoUpdateExe (PID: $($process.Id))" "INFO"
                            Write-Log "AutoUpdationService is running successfully (PID: $($process.Id))" "INFO"
                            $updaterStarted = $true
                        } else {
                            # Check if process is running by name (might have spawned child process or different name)
                            $updaterProcessNames = @("AutoUpdationService", "python")
                            $foundRunning = $false
                            foreach ($procName in $updaterProcessNames) {
                                $runningProcesses = Get-Process -Name $procName -ErrorAction SilentlyContinue
                                if ($runningProcesses) {
                                    # Check if any of these processes have a path matching AutoUpdationService
                                    foreach ($proc in $runningProcesses) {
                                        try {
                                            $procPath = $proc.Path
                                            if ($procPath -like "*AutoUpdationService*") {
                                                Write-Log "AutoUpdationService is running successfully (PID: $($proc.Id))" "INFO"
                                                $foundRunning = $true
                                                break
                                            }
                                        } catch {
                                            # Path might not be accessible, check if we have python processes and assume one might be ours
                                            if ($procName -eq "python" -and $runningProcesses.Count -gt 0) {
                                                Write-Log "AutoUpdationService (via Python) may be running (PID: $($proc.Id))" "INFO"
                                                $foundRunning = $true
                                                break
                                            }
                                        }
                                    }
                                    if ($foundRunning) { break }
                                }
                            }
                            
                            if ($foundRunning) {
                                $updaterStarted = $true
                            } else {
                                Write-Log "Warning: AutoUpdationService process started but could not be verified as running" "WARNING"
                                $updaterStarted = $true  # Consider it started for autostart configuration
                            }
                        }
                    } catch {
                        # Try checking by process name
                        $runningProcesses = Get-Process -Name "AutoUpdationService" -ErrorAction SilentlyContinue
                        if ($runningProcesses) {
                            Write-Log "AutoUpdationService is running successfully (PID: $($runningProcesses[0].Id))" "INFO"
                            $updaterStarted = $true
                        } else {
                            Write-Log "Warning: Could not verify AutoUpdationService process status: $_" "WARNING"
                            $updaterStarted = $true  # Consider it started for autostart configuration
                        }
                    }
                }
            } catch {
                Write-Log "Error starting $AutoUpdateExe : $_" "ERROR"
            }
        } elseif (-not $updaterFound) {
            Write-Log "Executable not found: AutoUpdationService" "ERROR"
        }
        
        # Step 3: Add to startup if both started successfully (matches autostart.pyx add_to_startup)
        if ($ebantisStarted -and $updaterStarted) {
            # Final verification: Check that processes are actually running
            Write-Log "Verifying processes are running..." "INFO"
            Start-Sleep -Seconds 2  # Give processes more time to fully start
            
            $ebantisRunning = Get-Process -Name "EbantisV4" -ErrorAction SilentlyContinue
            $updaterRunning = $null
            
            # Check for AutoUpdationService (could be .exe or python process)
            $updaterRunning = Get-Process -Name "AutoUpdationService" -ErrorAction SilentlyContinue
            if (-not $updaterRunning) {
                # Might be running as python process with AutoUpdationService.py
                $pythonProcs = Get-Process -Name "python" -ErrorAction SilentlyContinue
                if ($pythonProcs) {
                    # Check if any python process has AutoUpdationService in its path
                    foreach ($proc in $pythonProcs) {
                        try {
                            $procPath = $proc.Path
                            if ($procPath -like "*AutoUpdationService*") {
                                $updaterRunning = $proc
                                break
                            }
                        } catch {
                            # If we can't check path, and we have python processes, one might be ours
                            # Use the first python process as potential match
                            if (-not $updaterRunning) {
                                $updaterRunning = $proc
                            }
                        }
                    }
                }
            }
            
            if ($ebantisRunning) {
                Write-Log "✓ EbantisV4.exe is confirmed running (PID: $($ebantisRunning[0].Id))" "INFO"
            } else {
                Write-Log "⚠ EbantisV4.exe process verification failed, but startup will be configured" "WARNING"
            }
            
            if ($updaterRunning) {
                Write-Log "✓ AutoUpdationService is confirmed running (PID: $($updaterRunning[0].Id))" "INFO"
            } else {
                Write-Log "⚠ AutoUpdationService process verification failed, but startup will be configured" "WARNING"
            }
            
            $shell = New-Object -ComObject WScript.Shell
            
            # Remove existing shortcuts
            $shortcutsToRemove = @("EbantisV4.lnk", "AutoUpdationService.lnk")
            foreach ($shortcutName in $shortcutsToRemove) {
                $fullPath = [System.IO.Path]::Combine($StartupFolder, $shortcutName)
                if (Test-Path $fullPath) {
                    try {
                        Remove-Item -Path $fullPath -Force
                        Write-Log "Removed old startup shortcut: $shortcutName" "INFO"
                    } catch {
                        Write-Log "Could not remove $shortcutName : $_" "WARNING"
                    }
                }
            }
            
            # Create EbantisV4 shortcut
            $ebantisShortcutPath = [System.IO.Path]::Combine($StartupFolder, "EbantisV4.lnk")
            $ebantisShortcut = $shell.CreateShortcut($ebantisShortcutPath)
            $ebantisShortcut.TargetPath = $TargetExe
            $ebantisShortcut.WorkingDirectory = $MainFolder
            $ebantisShortcut.Save()
            
            # Verify shortcut was created
            if (Test-Path $ebantisShortcutPath) {
                Write-Log "✓ Created startup shortcut for EbantisV4.exe: $ebantisShortcutPath" "INFO"
                Write-Log "  Target: $TargetExe" "INFO"
                Write-Log "  Working Directory: $MainFolder" "INFO"
            } else {
                Write-Log "⚠ Warning: EbantisV4 shortcut may not have been created successfully" "WARNING"
            }
            
            # Create AutoUpdationService shortcut
            $autoupdateShortcutPath = [System.IO.Path]::Combine($StartupFolder, "AutoUpdationService.lnk")
            $autoupdateShortcut = $shell.CreateShortcut($autoupdateShortcutPath)
            
            # Handle .py files - need to run with Python
            if ($AutoUpdateExe.EndsWith(".py")) {
                $pythonPath = Get-Command python -ErrorAction SilentlyContinue
                if ($pythonPath) {
                    $autoupdateShortcut.TargetPath = $pythonPath.Path
                    $autoupdateShortcut.Arguments = "`"$AutoUpdateExe`""
                    Write-Log "AutoUpdationService is a Python file, using Python to execute it" "INFO"
                } else {
                    # Fallback: try to use py launcher
                    $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
                    if ($pyLauncher) {
                        $autoupdateShortcut.TargetPath = $pyLauncher.Path
                        $autoupdateShortcut.Arguments = "`"$AutoUpdateExe`""
                        Write-Log "AutoUpdationService is a Python file, using py launcher to execute it" "INFO"
                    } else {
                        Write-Log "ERROR: Python not found to run AutoUpdationService.py. Shortcut may not work." "ERROR"
                        $autoupdateShortcut.TargetPath = $AutoUpdateExe  # Set it anyway, but it may not work
                    }
                }
            } else {
                $autoupdateShortcut.TargetPath = $AutoUpdateExe
            }
            
            $autoupdateShortcut.WorkingDirectory = $MainFolder
            $autoupdateShortcut.Save()
            
            # Verify shortcut was created
            if (Test-Path $autoupdateShortcutPath) {
                Write-Log "✓ Created startup shortcut for AutoUpdationService: $autoupdateShortcutPath" "INFO"
                if ($AutoUpdateExe.EndsWith(".py")) {
                    Write-Log "  Target: Python -> $AutoUpdateExe" "INFO"
                } else {
                    Write-Log "  Target: $AutoUpdateExe" "INFO"
                }
                Write-Log "  Working Directory: $MainFolder" "INFO"
            } else {
                Write-Log "⚠ Warning: AutoUpdationService shortcut may not have been created successfully" "WARNING"
            }
            
            # Final verification: List all shortcuts in startup folder
            Write-Log "Verifying startup shortcuts in: $StartupFolder" "INFO"
            $createdShortcuts = Get-ChildItem -Path $StartupFolder -Filter "*.lnk" -ErrorAction SilentlyContinue | Where-Object { 
                $_.Name -eq "EbantisV4.lnk" -or $_.Name -eq "AutoUpdationService.lnk" 
            }
            
            if ($createdShortcuts) {
                Write-Log "✓ Confirmed startup shortcuts exist:" "INFO"
                foreach ($sc in $createdShortcuts) {
                    Write-Log "  - $($sc.Name)" "INFO"
                }
            } else {
                Write-Log "⚠ Warning: Could not verify startup shortcuts exist" "WARNING"
            }
            
            Write-Log "✓ Autostart feature configured successfully!" "INFO"
            Write-Log "  Both EbantisV4.exe and AutoUpdationService will start automatically on system reboot" "INFO"
            Write-Log "EbantisV4 and AutoUpdation successfully configured for autostart." "INFO"
            Write-Log "=== Autostart Process Finished ===" "INFO"
            return $true
        } else {
            Write-Log "Failed to start one or both processes. Autostart configuration skipped." "WARNING"
            Write-Log "=== Autostart Process Finished ===" "INFO"
            return $false
        }
    } catch {
        Write-Log "Autostart error: $_" "ERROR"
        Write-Log "=== Autostart Process Finished ===" "INFO"
        return $false
    }
}

# -------------------------------------------------------------------------
# STEP 10: MAIN INSTALLATION FLOW
# -------------------------------------------------------------------------

try {
    Write-Log "=== Starting Installation Process ===" "INFO"
    
    # Step 1: Internet Connection Check
    Write-Log "Checking Internet Connection..." "INFO"
    if (-not (Test-InternetConnection)) {
        Write-Log "No Internet Connection. Installation Aborted." "ERROR"
        Exit 1
    }
    
    # Step 2: Initialize Tenant Information
    Write-Log "Initializing tenant information..." "INFO"
    $tenantInfo = Initialize-TenantInfo
    if (-not $tenantInfo) {
        Write-Log "Failed to initialize tenant information. Installation Aborted." "ERROR"
        Exit 1
    }
    
    $TenantId = $tenantInfo.tenantId
    $CompanyId = $tenantInfo.companyId
    $BranchId = $tenantInfo.branchId
    
    # Step 3: Check Installation Allowed
    Write-Log "Checking if installation is allowed..." "INFO"
    $isAllowed, $message = Test-InstallationAllowed -BranchId $BranchId
    if (-not $isAllowed) {
        Write-Log $message "ERROR"
        Write-Host $message -ForegroundColor Red
        Read-Host "Press Enter to exit..."
        Exit 1
    }
    
    # Step 4: Initial Status Update (inprogress)
    Write-Log "Recording installation start..." "INFO"
    Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $false -InstallationFlag $false -Status "inprogress"
    
    # Step 5: Stop existing processes and remove old installation
    Write-Log "Clearing previous version (if installed)..." "INFO"
    Stop-EbantisProcesses
    Remove-ExistingInstallation
    Remove-StartupFile  # Remove old .bat files from startup
    Start-Sleep -Seconds 2
    
    # Ensure utils and update folders exist (they may have been removed during cleanup)
    $UtilsFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName, "utils")
    $UpdateFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName, "update")
    if (-not (Test-Path $UtilsFolder)) {
        New-Item -ItemType Directory -Path $UtilsFolder -Force | Out-Null
        Write-Log "Created utils folder: $UtilsFolder" "INFO"
    }
    if (-not (Test-Path $UpdateFolder)) {
        New-Item -ItemType Directory -Path $UpdateFolder -Force | Out-Null
        Write-Log "Created update folder: $UpdateFolder" "INFO"
    }
    
    # Step 6: Download and extract application package
    Write-Log "Downloading application package..." "INFO"
    $downloadSuccess = Download-AppPackage -BranchId $BranchId
    
    if (-not $downloadSuccess) {
        Write-Log "Application download failed. Aborting installation..." "ERROR"
        Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $false -InstallationFlag $false -Status "failed"
        Exit 1
    }
    
    # Step 7: Update download status
    Write-Log "Updating installation status - download complete..." "INFO"
    Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $true -InstallationFlag $false -Status "inprogress"
    
    # Step 8: Update folder permissions
    Write-Log "Updating folder permissions..." "INFO"
    $UsersFolder = [System.IO.Path]::Combine($ProgramDataPath, "user_collection")
    $DownloadZipPath = [System.IO.Path]::Combine($ProgramFilesPath, "data", "downloaded_version")
    $ExeDirectory = [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName)
    
    # Ensure DownloadZipPath directory exists (even if empty)
    if (-not (Test-Path $DownloadZipPath)) {
        New-Item -ItemType Directory -Path $DownloadZipPath -Force | Out-Null
    }
    
    $foldersToModify = @($UsersFolder, $DownloadZipPath, $ExeDirectory)
    $permissionResults = @()
    
    foreach ($folder in $foldersToModify) {
        $result = Update-FolderPermissions -FolderPath $folder
        $permissionResults += $result
    }
    
    if (-not ($permissionResults -contains $false)) {
        Write-Log "All folder permissions updated successfully." "INFO"
    } else {
        Write-Log "Some folder permission updates failed, but continuing..." "WARNING"
    }
    
    # Step 9: Configure autostart and start processes
    Write-Log "Setting up autostart..." "INFO"
    $autostartSuccess = Add-StartupShortcuts
    
    # Step 10: Start additional executables from utils and update folders
    Write-Log "Starting additional executables..." "INFO"
    Start-EbantisProcesses
    
    # Step 11: Final status update
    if ($autostartSuccess) {
        Write-Log "Installation completed successfully!" "INFO"
        Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $true -InstallationFlag $true -Status "installed"
        
        # Update installed device count (non-critical operation)
        $countModifyFlag, $countMessage = Update-InstalledDeviceCount -BranchId $BranchId -TenantId $TenantId
        if ($countModifyFlag) {
            Write-Log "Installed device count updated successfully" "INFO"
        } else {
            Write-Log "Device count update skipped or failed (non-critical): $countMessage" "WARNING"
        }
    } else {
        Write-Log "Installation completed but autostart configuration failed." "WARNING"
        Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $true -InstallationFlag $false -Status "installed"
    }
    
    # Step 12: Final verification - Check that processes are running
    Write-Log "=== Final Installation Verification ===" "INFO"
    Write-Log "Verifying that all services are running..." "INFO"
    Start-Sleep -Seconds 3  # Give processes more time to fully start
    
    $ebantisProcess = Get-Process -Name "EbantisV4" -ErrorAction SilentlyContinue
    $updaterProcess = Get-Process -Name "AutoUpdationService" -ErrorAction SilentlyContinue
    
    # Check for Python-based updater if .exe not found
    if (-not $updaterProcess) {
        $pythonProcs = Get-Process -Name "python" -ErrorAction SilentlyContinue
        if ($pythonProcs) {
            foreach ($proc in $pythonProcs) {
                try {
                    if ($proc.Path -like "*AutoUpdationService*") {
                        $updaterProcess = $proc
                        break
                    }
                } catch {
                    # If we can't check path, skip
                }
            }
        }
    }
    
    $allProcessesRunning = $true
    
    Write-Log "" "INFO"
    if ($ebantisProcess) {
        try {
            $pid = $ebantisProcess[0].Id
            $memoryMB = [math]::Round($ebantisProcess[0].WorkingSet64 / 1MB, 2)
            $startTime = $ebantisProcess[0].StartTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Log "✓ EbantisV4.exe is RUNNING successfully" "INFO"
            Write-Log "  - Process ID: $pid" "INFO"
            Write-Log "  - Memory Usage: $memoryMB MB" "INFO"
            Write-Log "  - Start Time: $startTime" "INFO"
            Write-Log "  - Status: RUNNING ✓" "INFO"
        } catch {
            Write-Log "✓ EbantisV4.exe is RUNNING successfully (PID: $($ebantisProcess[0].Id))" "INFO"
        }
    } else {
        Write-Log "✗ EbantisV4.exe is NOT running" "ERROR"
        Write-Log "  - Status: NOT RUNNING ✗" "ERROR"
        $allProcessesRunning = $false
    }
    
    Write-Log "" "INFO"
    if ($updaterProcess) {
        try {
            $pid = $updaterProcess[0].Id
            $memoryMB = [math]::Round($updaterProcess[0].WorkingSet64 / 1MB, 2)
            $startTime = $updaterProcess[0].StartTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Log "✓ AutoUpdationService is RUNNING successfully" "INFO"
            Write-Log "  - Process ID: $pid" "INFO"
            Write-Log "  - Memory Usage: $memoryMB MB" "INFO"
            Write-Log "  - Start Time: $startTime" "INFO"
            Write-Log "  - Status: RUNNING ✓" "INFO"
        } catch {
            Write-Log "✓ AutoUpdationService is RUNNING successfully (PID: $($updaterProcess[0].Id))" "INFO"
        }
    } else {
        Write-Log "✗ AutoUpdationService is NOT running" "ERROR"
        Write-Log "  - Status: NOT RUNNING ✗" "ERROR"
        $allProcessesRunning = $false
    }
    
    Write-Log "" "INFO"
    if ($allProcessesRunning) {
        Write-Log "=== ✓ All services are running successfully ===" "INFO"
        Write-Log "✓ Installation completed and verified: Both EbantisV4.exe and AutoUpdationService are running" "INFO"
    } else {
        Write-Log "=== ⚠ WARNING: Some services are not running ===" "WARNING"
        Write-Log "⚠ Installation completed, but one or more services failed to start. Please check the logs above." "WARNING"
    }
    Write-Log "" "INFO"
    
    # Step 13: Cleanup installer files (no longer needed after installation)
    Write-Log "Cleaning up installer files..." "INFO"
    $installerExe = [System.IO.Path]::Combine($ProgramFilesPath, "ebantis-msi-installer.exe")
    $installerScript = [System.IO.Path]::Combine($ProgramFilesPath, "installer.ps1")
    
    if (Test-Path $installerExe) {
        try {
            Remove-Item -Path $installerExe -Force -ErrorAction SilentlyContinue
            Write-Log "Removed installer executable: $installerExe" "INFO"
        } catch {
            Write-Log "Warning: Could not remove installer executable: $_" "WARNING"
        }
    }
    
    if (Test-Path $installerScript) {
        try {
            Remove-Item -Path $installerScript -Force -ErrorAction SilentlyContinue
            Write-Log "Removed installer script: $installerScript" "INFO"
        } catch {
            Write-Log "Warning: Could not remove installer script: $_" "WARNING"
        }
    }
    
    Write-Log "=== Installation Process Completed ===" "INFO"
    Write-Log "Installation completed successfully!" "INFO"
    Write-Log "Log file location: $LogFile" "INFO"
    # Silent completion - no popup or Read-Host
    
} catch {
    Write-Log "Fatal error in main execution: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Log "Installation failed. Check the log file for details: $LogFile" "ERROR"
    Exit 1
}

