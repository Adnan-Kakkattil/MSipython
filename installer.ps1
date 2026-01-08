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
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
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
        $authApiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login"
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
        
        # Try to extract branch_id from format: EbantisTracker_{branch_id}.exe or .msi
        if ($exeName -match "EbantisTracker_(.+)\.(exe|msi)") {
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
        
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/branches/branch/$BranchId"
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
        
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$BranchId"
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
        
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$BranchId"
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
        
        $installedDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        
        $payload = @{
            branchUniqueId = $BranchId
            tenantUniqueId = $TenantId
            hostName = $Hostname
            installedOn = $installedDate
            isDownloaded = $StatusFlag
            isInstalled = $InstallationFlag
            versionId = if ($versionId) { $versionId } else { "" }
            status = $Status
            userName = $DisplayName
            userExternalId = 0
            email = $Email
        } | ConvertTo-Json -Depth 10
        
        $authToken = Get-AuthToken
        if (-not $authToken) {
            Write-Log "Failed to obtain authentication token for saving installation data." "ERROR"
            return $false
        }
        
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/app-installations"
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
    # Note: Python function takes branch_id but is called with tenant_id (line 1273)
    # The API URL uses branch_id, but payload uses tenantUniqueId with tenant_id value
    try {
        $authToken = Get-AuthToken
        if (-not $authToken) {
            $msg = "Failed to obtain authentication token for device count update."
            Write-Log $msg "ERROR"
            return $false, $msg
        }
        
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$BranchId/installed-count"
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
        
        $response = Invoke-RestMethod -Uri $apiUrl -Method Put -Body $payload -ContentType "application/json" -Headers $headers -TimeoutSec 30
        
        $msg = "Installed device count updated successfully for branch_id: $BranchId"
        Write-Log $msg "INFO"
        return $true, $msg
    } catch {
        $msg = "API request error while updating device count for branch_id $BranchId : $_"
        Write-Log $msg "ERROR"
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
                Write-Log "Startup file not found: $BatchLocation" "WARNING"
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
        
        $ApiUrl = "https://qaebantisapiv4.thekosmoz.com/DownloadLatestversion?branch_id=$BranchId"
        $Headers = @{
            "IsInternalCall" = "true"
            "ClientId" = "EbantisTrack"
        }
        
        Write-Log "Starting main package download from API: $ApiUrl" "INFO"
        
        # Get file size first (for multi-threaded download if >5MB)
        try {
            $headResponse = Invoke-WebRequest -Uri $ApiUrl -Method Head -Headers $Headers -TimeoutSec 30 -ErrorAction SilentlyContinue
            $fileSize = [long]$headResponse.Headers['Content-Length']
            Write-Log "File size from API: $fileSize bytes" "INFO"
        } catch {
            $fileSize = 0
            Write-Log "Could not get file size from API: $_" "WARNING"
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
        Write-Log "Extracting main package from $DownloadPath to $ExtractPath..." "INFO"
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [System.IO.Compression.ZipFile]::OpenRead($DownloadPath)
            
            # Get all entries
            $entries = $zip.Entries
            $members = $entries | ForEach-Object { $_.FullName }
            
            # Detect if there's an unnecessary root directory
            $commonPath = ""
            if ($members.Count -gt 0) {
                $firstPath = $members[0]
                $pathParts = $firstPath.Split([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
                if ($pathParts.Count -gt 0) {
                    $commonPath = $pathParts[0]
                }
            }
            
            # Extract all files
            foreach ($entry in $entries) {
                $targetPath = if ($commonPath -and $entry.FullName.StartsWith($commonPath)) {
                    # Strip the common root directory
                    $relativePath = $entry.FullName.Substring($commonPath.Length).TrimStart('\', '/')
                    [System.IO.Path]::Combine($ExtractPath, $relativePath)
                } else {
                    [System.IO.Path]::Combine($ExtractPath, $entry.FullName)
                }
                
                $targetDir = [System.IO.Path]::GetDirectoryName($targetPath)
                if (-not (Test-Path $targetDir)) {
                    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
                }
                
                if (-not $entry.FullName.EndsWith('/') -and -not $entry.FullName.EndsWith('\')) {
                    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $targetPath, $true)
                }
            }
            
            $zip.Dispose()
            Write-Log "Main package extracted successfully." "INFO"
        } catch {
            Write-Log "Extraction failed: $_" "ERROR"
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
        $AutoUpdateExe = [System.IO.Path]::Combine($MainFolder, "AutoUpdationService.exe")
        
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
        
        # Step 2: Start processes
        $ebantisStarted = $false
        $updaterStarted = $false
        
        if (Test-Path $TargetExe) {
            try {
                Start-Process -FilePath $TargetExe -WorkingDirectory $MainFolder
                Write-Log "Started: $TargetExe" "INFO"
                $ebantisStarted = $true
            } catch {
                Write-Log "Error starting $TargetExe : $_" "ERROR"
            }
        } else {
            Write-Log "Executable not found: $TargetExe" "ERROR"
        }
        
        if (Test-Path $AutoUpdateExe) {
            try {
                Start-Process -FilePath $AutoUpdateExe -WorkingDirectory $MainFolder
                Write-Log "Started: $AutoUpdateExe" "INFO"
                $updaterStarted = $true
            } catch {
                Write-Log "Error starting $AutoUpdateExe : $_" "ERROR"
            }
        } else {
            Write-Log "Executable not found: $AutoUpdateExe" "ERROR"
        }
        
        # Step 3: Add to startup if both started successfully (matches autostart.pyx add_to_startup)
        if ($ebantisStarted -and $updaterStarted) {
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
            $ebantisShortcut = $shell.CreateShortcut([System.IO.Path]::Combine($StartupFolder, "EbantisV4.lnk"))
            $ebantisShortcut.TargetPath = $TargetExe
            $ebantisShortcut.WorkingDirectory = $MainFolder
            $ebantisShortcut.Save()
            Write-Log "Created startup shortcut for: EbantisV4.exe" "INFO"
            
            # Create AutoUpdationService shortcut
            $autoupdateShortcut = $shell.CreateShortcut([System.IO.Path]::Combine($StartupFolder, "AutoUpdationService.lnk"))
            $autoupdateShortcut.TargetPath = $AutoUpdateExe
            $autoupdateShortcut.WorkingDirectory = $MainFolder
            $autoupdateShortcut.Save()
            Write-Log "Created startup shortcut for: AutoUpdationService.exe" "INFO"
            
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
        Read-Host "Press Enter to exit..."
        Exit 1
    }
    
    # Step 2: Initialize Tenant Information
    Write-Log "Initializing tenant information..." "INFO"
    $tenantInfo = Initialize-TenantInfo
    if (-not $tenantInfo) {
        Write-Log "Failed to initialize tenant information. Installation Aborted." "ERROR"
        Read-Host "Press Enter to exit..."
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
    
    # Step 6: Download and extract application package
    Write-Log "Downloading application package..." "INFO"
    $downloadSuccess = Download-AppPackage -BranchId $BranchId
    
    if (-not $downloadSuccess) {
        Write-Log "Application download failed. Aborting installation..." "ERROR"
        Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $false -InstallationFlag $false -Status "failed"
        Read-Host "Press Enter to exit..."
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
        
        # Update installed device count
        $countModifyFlag, $countMessage = Update-InstalledDeviceCount -BranchId $BranchId -TenantId $TenantId
        Write-Log "Installed device count update: $countModifyFlag, message: $countMessage" "INFO"
    } else {
        Write-Log "Installation completed but autostart configuration failed." "WARNING"
        Update-InstallationData -TenantId $TenantId -BranchId $BranchId -StatusFlag $true -InstallationFlag $false -Status "installed"
    }
    
    Write-Log "=== Installation Process Completed ===" "INFO"
    Write-Host ""
    Write-Host "Installation completed successfully!" -ForegroundColor Green
    Write-Host "Log file location: $LogFile" -ForegroundColor Cyan
    Read-Host "Press Enter to close..."
    
} catch {
    Write-Log "Fatal error in main execution: $_" "ERROR"
    Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
    Write-Host "Installation failed. Check the log file for details: $LogFile" -ForegroundColor Red
    Read-Host "Press Enter to exit..."
    Exit 1
}

