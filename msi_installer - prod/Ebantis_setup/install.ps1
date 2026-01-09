<#
.SYNOPSIS
    Ebantis V4.0.1 Installer / Uninstaller
    Converts the Python/Cython installer to a standalone PowerShell script.

.DESCRIPTION
    Handles the installation of the Ebantis Agent, including:
    - Prerequisite checks (Admin, Internet)
    - API Registration
    - Credential Retrieval & Decryption
    - Wazuh Agent Installation
    - Persistence (Startup Shortcut)
    - Uninstallation Logic

.NOTES
    Version: 4.0.1
    Author: Converted by Google DeepMind Agent
    Date: 2025-11-26
#>

# -------------------------------------------------------------------------
# 1. CORE SETUP & CONFIGURATION
# -------------------------------------------------------------------------

# Ensure Admin Privileges
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

# Hardcoded Tenant Name
$TenantName = "gritstone technologies"

# Database Path
$UserDataDir = [System.IO.Path]::Combine($ProgramDataPath, "user_collection", $env:USERNAME)
$DbPath = [System.IO.Path]::Combine($UserDataDir, "tracking_system.db")

# Create Directories
$DirsToCreate = @(
    $ProgramFilesPath,
    $ProgramDataPath,
    $LogFolder,
    [System.IO.Path]::Combine($ProgramFilesPath, "data"),
    [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName, "utils"),
    [System.IO.Path]::Combine($ProgramFilesPath, "data", $AppName, "update"),
    [System.IO.Path]::Combine($ProgramDataPath, "tenant_info"),
    [System.IO.Path]::Combine($ProgramDataPath, "user_collection"),
    $UserDataDir
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

Write-Log "Starting Ebantis V4.0.1 Installer..." "INFO"
Write-Log "Running with administrative privileges." "INFO"
Write-Log "Tenant Name: $TenantName" "INFO"

# -------------------------------------------------------------------------
# 2. ENCRYPTION MODULE (Ported from encryption.py)
# -------------------------------------------------------------------------

$SecretKey = "NlN57G7OEBZRvSaL"
$XorKey = "PZH83QL"
$Shift = 5

function Deobfuscate-String {
    param([string]$InputString)
   
    try {
        # 1. Base64 Decode
        $Bytes = [Convert]::FromBase64String($InputString)
        $Decoded = [System.Text.Encoding]::UTF8.GetString($Bytes)
       
        # 2. XOR Reverse
        $Xored = ""
        for ($i = 0; $i -lt $Decoded.Length; $i++) {
            $Char = [int][char]$Decoded[$i]
            $KeyChar = [int][char]$XorKey[$i % $XorKey.Length]
            $Xored += [char]($Char -bxor $KeyChar)
        }
       
        # 3. Shift Reverse
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
        $IvBytes = $KeyBytes # IV = Key
       
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
        Write-Log "DEBUG: Decrypt-Response called, input length: $($ObfuscatedEncryptedData.Length)" "INFO"
        Write-Log "DEBUG: Input (first 100 chars): $($ObfuscatedEncryptedData.Substring(0, [Math]::Min(100, $ObfuscatedEncryptedData.Length)))" "INFO"
        
        # Step 1: Deobfuscate
        $Step1 = Deobfuscate-String -InputString $ObfuscatedEncryptedData
        if (-not $Step1) { 
            Write-Log "DEBUG: Deobfuscation returned null/empty" "ERROR"
            return $null 
        }
        
        Write-Log "DEBUG: Deobfuscation successful, length: $($Step1.Length)" "INFO"
        Write-Log "DEBUG: Deobfuscated (first 100 chars): $($Step1.Substring(0, [Math]::Min(100, $Step1.Length)))" "INFO"
        
        # Step 2: AES Decrypt
        $Step2 = Decrypt-AES -InputString $Step1
        if (-not $Step2) { 
            Write-Log "DEBUG: AES decryption returned null/empty" "ERROR"
            return $null 
        }
        
        Write-Log "DEBUG: AES decryption successful, length: $($Step2.Length)" "INFO"
        Write-Log "DEBUG: Decrypted JSON string: $Step2" "INFO"
        
        # Step 3: Parse JSON
        $parsed = $Step2 | ConvertFrom-Json
        if ($parsed) {
            Write-Log "DEBUG: JSON parsing successful" "INFO"
            Write-Log "DEBUG: Parsed object type: $($parsed.GetType().Name)" "INFO"
            if ($parsed.PSObject.Properties) {
                Write-Log "DEBUG: Parsed properties: $($parsed.PSObject.Properties.Name -join ', ')" "INFO"
            }
        } else {
            Write-Log "DEBUG: JSON parsing returned null" "ERROR"
        }
        
        return $parsed
    } catch {
        Write-Log "DEBUG: Decrypt-Response exception: $_" "ERROR"
        Write-Log "DEBUG: Stack trace: $($_.ScriptStackTrace)" "ERROR"
        return $null
    }
}

# -------------------------------------------------------------------------
# 3. SQLITE UTILITIES
# -------------------------------------------------------------------------

# Try to load SQLite DLL if available
function Get-SqliteConnection {
    param($DbPath)
    
    try {
        # Try to load SQLite DLL from script directory
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $sqliteDll = Join-Path $scriptDir "System.Data.SQLite.dll"
        
        if (Test-Path $sqliteDll) {
            Add-Type -Path $sqliteDll -ErrorAction Stop
        } else {
            Write-Log "System.Data.SQLite.dll not found at $sqliteDll. SQLite operations will be skipped." "WARNING"
            return $null
        }
        
        if (-not ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq "System.Data.SQLite" })) {
            Write-Log "System.Data.SQLite.dll is not loaded. Cannot connect to database." "WARNING"
            return $null
        }
        
        $connString = "Data Source=$DbPath;Version=3;"
        $conn = New-Object System.Data.SQLite.SQLiteConnection($connString)
        $conn.Open()
        return $conn
    } catch {
        Write-Log "Failed to connect to SQLite database: $_" "WARNING"
        return $null
    }
}

# -------------------------------------------------------------------------
# 4. UTILITIES
# -------------------------------------------------------------------------

function Set-DirectoryPermissions {
    param([string]$Path)
    
    Write-Log "Attempting to set permissions for directory: $Path" "INFO"
    
    if (Test-Path $Path) {
        try {
            $acl = Get-Acl $Path
            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
            $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "FullControl", $inheritanceFlags, $propagationFlags, "Allow")
            $acl.SetAccessRule($rule)
            Set-Acl -Path $Path -AclObject $acl
            Write-Log "Successfully set FullControl permissions for Users group on: $Path" "INFO"
        } catch {
            Write-Log "Failed to set permissions for ${Path}: $_" "ERROR"
        }
    } else {
        Write-Log "Directory does not exist, skipping permission setting: $Path" "WARNING"
    }
}

function Write-TenantDetailsJson {
    <#
    .SYNOPSIS
    Writes the tenant name to tenant_details.json file.
    
    .DESCRIPTION
    Creates the tenant_details.json file in the tenant_info directory with the tenant name.
    This file is required by the Python application to read the tenant name.
    #>
    param(
        [string]$TenantName,
        [string]$TenantInfoPath
    )
    
    try {
        $TenantInfoDir = [System.IO.Path]::Combine($TenantInfoPath, "tenant_info")
        $TenantDetailsJson = [System.IO.Path]::Combine($TenantInfoDir, "tenant_details.json")
        
        # Ensure directory exists
        if (-not (Test-Path $TenantInfoDir)) {
            New-Item -ItemType Directory -Path $TenantInfoDir -Force | Out-Null
            Write-Log "Created tenant_info directory: $TenantInfoDir" "INFO"
        }
        
        # Create JSON object with tenant name
        $tenantData = @{
            tenant_name = $TenantName
        } | ConvertTo-Json -Compress
        
        # Write to file
        $tenantData | Out-File -FilePath $TenantDetailsJson -Encoding UTF8 -Force
        Write-Log "Successfully wrote tenant name to: $TenantDetailsJson" "INFO"
        Write-Log "Tenant name written: $TenantName" "INFO"
        
        return $true
    } catch {
        Write-Log "Failed to write tenant details JSON: $_" "ERROR"
        return $false
    }
}

function Get-MachineID {
    # Try getting UUID from WMIC
    try {
        $UUID = (Get-WmiObject -Class Win32_ComputerSystemProduct).UUID
        if ($UUID -and $UUID -ne "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") {
            return $UUID
        }
    } catch {
        Write-Log "Failed to get UUID via WMI: $_" "WARNING"
    }
   
    # Fallback to Machine GUID from registry
    try {
        $reg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name "MachineGuid" -ErrorAction Stop
        return $reg.MachineGuid
    } catch {
        Write-Log "Failed to get Machine GUID from registry: $_" "WARNING"
        return [guid]::NewGuid().ToString()
    }
}

function Get-DisplayName {
    try {
        $user = whoami /user /fo csv | ConvertFrom-Csv
        $sid = $user.SID
        # Extract username from whoami output
        $parts = $env:USERNAME
        return $parts
    } catch {
        Write-Log "Failed to get display name: $_" "WARNING"
        return $env:USERNAME
    }
}

function Get-Upn {
    try {
        $upn = whoami /upn 2>$null
        if ($LASTEXITCODE -eq 0 -and $upn -and $upn -match "@") {
            return $upn.Trim()
        }
    } catch {
        Write-Log "Failed to get UPN: $_" "WARNING"
    }
    return ""
}

function Get-UserEmail {
    # Try to get UPN first (for domain users)
    $upn = Get-Upn
    if ($upn -and $upn -match "@") {
        return $upn
    }
    
    # If not a domain user, construct email as username@hostname.internal
    $username = $env:USERNAME
    $hostname = $env:COMPUTERNAME
    return "${username}@${hostname}.internal"
}

# -------------------------------------------------------------------------
# 5. API INTEGRATION
# -------------------------------------------------------------------------

function Register-Agent {
    param(
        [string]$MachineID,
        [string]$Hostname,
        [string]$DisplayName,
        [string]$Email,
        [string]$Upn,
        [string]$Username
    )
   
    $Url = "https://ebantisapiv4.thekosmoz.com/register-agent"
    $Payload = @{
        machine_id   = $MachineID
        hostname     = $Hostname
        display_name = $DisplayName
        email        = $Email
        upn          = $Upn
        username     = $Username
    } | ConvertTo-Json
   
    $Headers = @{
        "Content-Type"   = "application/json"
        "IsInternalCall" = "true"
        "ClientId"       = "EbantisTrack"
    }
   
    try {
        Write-Log "Registering agent at $Url..." "INFO"
        $Response = Invoke-RestMethod -Uri $Url -Method Post -Body $Payload -Headers $Headers -TimeoutSec 300
        Write-Log "Registration successful." "INFO"
        
        # Log the response
        if ($Response) {
            $ResponseJson = $Response | ConvertTo-Json -Depth 10 -Compress
            Write-Log "Registration Response: $ResponseJson" "INFO"
        }
        
        return $Response
    } catch {
        Write-Log "Registration failed: $_" "ERROR"
        return $null
    }
}

function Invoke-UpsertInstallationData {
    <#
    .SYNOPSIS
    Calls the API to upsert installation data for tracking installation progress.
    
    .PARAMETER TenantName
    Name of the tenant
    
    .PARAMETER Hostname
    Hostname of the machine
    
    .PARAMETER StatusFlag
    Download status flag (boolean)
    
    .PARAMETER InstallationFlag
    Installation status flag (boolean)
    
    .PARAMETER Status
    Overall status string (e.g., "inprogress", "installed", "failed")
    #>
    param(
        [string]$TenantName,
        [string]$Hostname,
        [bool]$StatusFlag,
        [bool]$InstallationFlag,
        [string]$Status
    )
   
    # Build URL with query parameters (to match current API implementation)
    $BaseUrl = "https://ebantisapiv4.thekosmoz.com/upsert-installation-data"
    
    # URL encode parameters
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $EncodedTenant = [System.Uri]::EscapeDataString($TenantName)
    $EncodedHostname = [System.Uri]::EscapeDataString($Hostname)
    $EncodedStatus = [System.Uri]::EscapeDataString($Status)
    
    $Url = "${BaseUrl}?tenant_name=${EncodedTenant}&hostname=${EncodedHostname}&status_flag=${StatusFlag}&installation_flag=${InstallationFlag}&status=${EncodedStatus}"
   
    $Headers = @{
        "IsInternalCall" = "true"
        "ClientId"       = "EbantisTrack"
    }
   
    try {
        Write-Log "Upserting installation data for host: $Hostname (Status: $Status)" "INFO"
        $Response = Invoke-RestMethod -Uri $Url -Method Post -Headers $Headers -TimeoutSec 60
        Write-Log "Installation data upserted successfully." "INFO"
        return $Response
    } catch {
        Write-Log "Failed to upsert installation data: $_" "WARNING"
        return $null
    }
}

function Get-DecodedCredentialsFromDB {
    <#
    .SYNOPSIS
    Fetch and decode encrypted API credentials from SQLite database.
    #>
    $conn = $null
    try {
        $conn = Get-SqliteConnection -DbPath $DbPath
        if (-not $conn) {
            Write-Log "Cannot connect to SQLite database. Driver may be missing." "WARNING"
            return $null
        }

        $cmd = $conn.CreateCommand()
        $cmd.CommandText = 'SELECT data FROM api_data WHERE id = ''1'''
        $reader = $cmd.ExecuteReader()
        
        if (-not $reader.Read()) {
            Write-Log "No credential record found in database." "WARNING"
            $reader.Close()
            return $null
        }

        $jsonString = $reader.GetString(0)
        $reader.Close()
        
        Write-Log "DEBUG: Read JSON from DB, length: $($jsonString.Length)" "INFO"
        Write-Log "DEBUG: JSON from DB (first 200 chars): $($jsonString.Substring(0, [Math]::Min(200, $jsonString.Length)))" "INFO"
        
        if ([string]::IsNullOrWhiteSpace($jsonString)) {
            Write-Log "Credential data is empty in database." "WARNING"
            return $null
        }

        # Parse the JSON string to get the stored response object
        $credentialData = $jsonString | ConvertFrom-Json
        
        if (-not $credentialData) {
            Write-Log "Failed to parse JSON from database." "ERROR"
            return $null
        }

        Write-Log "DEBUG: Parsed credential data from DB, type: $($credentialData.GetType().FullName)" "INFO"
        if ($credentialData.PSObject.Properties) {
            Write-Log "DEBUG: Properties in stored data: $($credentialData.PSObject.Properties.Name -join ', ')" "INFO"
        }

        # Extract obfuscatedEncryptedData field
        if (-not ($credentialData.PSObject.Properties.Name -contains "obfuscatedEncryptedData")) {
            Write-Log "obfuscatedEncryptedData field missing from stored credentials." "ERROR"
            Write-Log "Available fields: $($credentialData.PSObject.Properties.Name -join ', ')" "ERROR"
            return $null
        }

        $encryptedData = $credentialData.obfuscatedEncryptedData
        
        if ([string]::IsNullOrWhiteSpace($encryptedData)) {
            Write-Log "obfuscatedEncryptedData is null or empty in stored data." "ERROR"
            return $null
        }

        Write-Log "Extracted encrypted data from database, length: $($encryptedData.Length)" "INFO"
        Write-Log "DEBUG: Encrypted data from DB (first 100 chars): $($encryptedData.Substring(0, [Math]::Min(100, $encryptedData.Length)))" "INFO"

        # Decrypt the credentials
        $decodedData = Decrypt-Response -ObfuscatedEncryptedData $encryptedData
        
        if (-not $decodedData) {
            Write-Log "Failed to decrypt credentials from database." "ERROR"
            return $null
        }

        Write-Log "Credentials successfully decoded from database." "INFO"
        
        # Log the decrypted data
        if ($decodedData.PSObject.Properties) {
            Write-Log "DEBUG: Decrypted properties from DB:" "INFO"
            foreach ($prop in $decodedData.PSObject.Properties) {
                $value = $prop.Value
                if ($value -is [string] -and $value.Length -gt 100) {
                    $value = "$($value.Substring(0, 100))... (truncated)"
                }
                Write-Log "DEBUG:   $($prop.Name) = $value" "INFO"
            }
            
            # Also log as JSON
            try {
                $decryptedJson = $decodedData | ConvertTo-Json -Depth 10 -Compress
                Write-Log "DEBUG: Decrypted JSON from DB: $decryptedJson" "INFO"
            } catch {
                Write-Log "DEBUG: Failed to convert to JSON: $_" "WARNING"
            }
        }
        
        return $decodedData
    } catch {
        Write-Log "Error decoding credentials from database: $_" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        return $null
    } finally {
        if ($conn) {
            $conn.Close()
        }
    }
}

function Get-Credentials {
    param([string]$TenantName)
   
    # URL encode the tenant name
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    if (-not ([System.Web.HttpUtility])) {
        # Fallback if System.Web is not available
        $EncodedTenant = [System.Uri]::EscapeDataString($TenantName)
    } else {
        $EncodedTenant = [System.Web.HttpUtility]::UrlEncode($TenantName)
    }
    
    $Url = "https://ebantistrackapi.metlone.com/api/v1/Connection/GetAllConnections?tenant=$EncodedTenant"
    $Headers = @{
        "IsInternalCall" = "true"
        "ClientId"       = "EbantisTrack"
    }
   
    try {
        Write-Log "Fetching credentials for tenant $TenantName..." "INFO"
        
        # Get raw JSON string first (before deserialization) - this is what we'll store
        $rawJsonResponse = (Invoke-WebRequest -Uri $Url -Headers $Headers -Method Get).Content
        
        if ([string]::IsNullOrWhiteSpace($rawJsonResponse)) {
            Write-Log "Empty response received from API." "ERROR"
            return $null
        }
        
        # Parse the JSON to get the object for processing
        $rawResponse = $rawJsonResponse | ConvertFrom-Json
        
        if (-not $rawResponse) {
            Write-Log "Failed to parse API response as JSON." "ERROR"
            return $null
        }

        # Handle array response (API might return array with single object)
        $dataList = $rawResponse
        $jsonToStore = $rawJsonResponse  # Store the original JSON string
        
        if ($rawResponse -is [System.Array]) {
            if ($rawResponse.Count -eq 0) {
                Write-Log "API returned empty array." "ERROR"
                return $null
            }
            $dataList = $rawResponse[0]
            # If it's an array, we need to extract just the first element as JSON
            $jsonToStore = ($dataList | ConvertTo-Json -Depth 10 -Compress)
            Write-Log "API returned array, using first element." "INFO"
        }
        
        # Extract encrypted data before storing
        if (-not ($dataList.PSObject.Properties.Name -contains "obfuscatedEncryptedData")) {
            Write-Log "ERROR: obfuscatedEncryptedData field MISSING from response" "ERROR"
            return $null
        }
        
        $originalEncryptedData = $dataList.obfuscatedEncryptedData
        $originalEncryptedLength = if ($originalEncryptedData) { $originalEncryptedData.Length } else { 0 }
        
        if ([string]::IsNullOrWhiteSpace($originalEncryptedData)) {
            Write-Log "obfuscatedEncryptedData is null or empty." "ERROR"
            return $null
        }
        
        Write-Log "Extracted encrypted data from response, length: $originalEncryptedLength" "INFO"
        
        # Store RAW response in SQLite FIRST (like Python version does)
        $conn = Get-SqliteConnection -DbPath $DbPath
        if ($conn) {
            try {
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "CREATE TABLE IF NOT EXISTS api_data (id TEXT PRIMARY KEY, data TEXT)"
                $cmd.ExecuteNonQuery()

                $cmd.CommandText = "DELETE FROM api_data"
                $cmd.ExecuteNonQuery()
                
                # Store the RAW JSON response string (matching Python's json.dumps behavior)
                # Use the original JSON string from the API, not a re-serialized version
                
                # Validate that obfuscatedEncryptedData is in the JSON string
                if ($jsonToStore -notmatch "obfuscatedEncryptedData") {
                    Write-Log "WARNING: obfuscatedEncryptedData not found in JSON string!" "WARNING"
                } else {
                    Write-Log "Storing raw JSON response with encrypted data (length: $originalEncryptedLength)" "INFO"
                }
                
                $cmd.CommandText = "INSERT INTO api_data (id, data) VALUES (@id, @data)"
                $cmd.Parameters.Clear()
                $cmd.Parameters.AddWithValue("@id", "1") | Out-Null
                $cmd.Parameters.AddWithValue("@data", $jsonToStore) | Out-Null
                $result = $cmd.ExecuteNonQuery()
                
                if ($result -gt 0) {
                    Write-Log "Raw API response successfully stored in SQLite (JSON length: $($jsonToStore.Length))." "INFO"
                    
                    # Verify the stored data can be read back correctly
                    $verifyCmd = $conn.CreateCommand()
                    $verifyCmd.CommandText = 'SELECT data FROM api_data WHERE id = ''1'''
                    $verifyReader = $verifyCmd.ExecuteReader()
                    if ($verifyReader.Read()) {
                        $storedJson = $verifyReader.GetString(0)
                        $verifyReader.Close()
                        
                        # Verify the stored JSON matches what we stored
                        if ($storedJson -eq $jsonToStore) {
                            Write-Log "Verification passed: Stored JSON matches original." "INFO"
                        } else {
                            Write-Log "WARNING: Stored JSON differs from original!" "WARNING"
                            Write-Log "Original length: $($jsonToStore.Length), Stored length: $($storedJson.Length)" "WARNING"
                        }
                        
                        # Also verify we can parse it and extract the encrypted data
                        $storedData = $storedJson | ConvertFrom-Json
                        if ($storedData.obfuscatedEncryptedData) {
                            $storedEncryptedLength = $storedData.obfuscatedEncryptedData.Length
                            Write-Log "Verification: Stored encrypted data length: $storedEncryptedLength (original: $originalEncryptedLength)" "INFO"
                            if ($storedEncryptedLength -ne $originalEncryptedLength) {
                                Write-Log "WARNING: Stored encrypted data length mismatch! Data may be corrupted." "WARNING"
                            } else {
                                Write-Log "Verification passed: Encrypted data stored correctly." "INFO"
                            }
                        } else {
                            Write-Log "WARNING: Could not find obfuscatedEncryptedData in stored data!" "WARNING"
                        }
                    } else {
                        Write-Log "WARNING: Could not read back stored data for verification!" "WARNING"
                    }
                } else {
                    Write-Log "WARNING: INSERT returned 0 rows affected!" "WARNING"
                }
            } catch {
                Write-Log "SQLite Error while storing raw response: $_" "ERROR"
            } finally {
                $conn.Close()
            }
        } else {
            Write-Log "Skipping SQLite storage (Driver missing)." "WARNING"
        }
        
        # Now decrypt the credentials (we already extracted $originalEncryptedData above)
        Write-Log "Decrypting credentials, encrypted data length: $originalEncryptedLength" "INFO"
        Write-Log "DEBUG: Encrypted data (first 100 chars): $($originalEncryptedData.Substring(0, [Math]::Min(100, $originalEncryptedData.Length)))" "INFO"
        
        # Decrypt the credentials
        $Decrypted = Decrypt-Response -ObfuscatedEncryptedData $originalEncryptedData
        
        if ($Decrypted) {
            Write-Log "Credentials decrypted successfully from API response." "INFO"
            Write-Log "DEBUG: Decrypted response type: $($Decrypted.GetType().FullName)" "INFO"
            
            # Log all decrypted properties
            if ($Decrypted.PSObject.Properties) {
                Write-Log "DEBUG: Decrypted properties count: $($Decrypted.PSObject.Properties.Count)" "INFO"
                foreach ($prop in $Decrypted.PSObject.Properties) {
                    $value = $prop.Value
                    if ($null -eq $value) {
                        $value = "null"
                    } elseif ($value -is [string] -and $value.Length -gt 100) {
                        $value = "$($value.Substring(0, 100))... (truncated, length: $($value.Length))"
                    }
                    Write-Log "DEBUG: Property '$($prop.Name)' = $value" "INFO"
                }
            }
            
            # Also log as JSON
            try {
                $decryptedJson = $Decrypted | ConvertTo-Json -Depth 10 -Compress
                Write-Log "DEBUG: Decrypted JSON string from API: $decryptedJson" "INFO"
            } catch {
                Write-Log "DEBUG: Failed to convert decrypted data to JSON: $_" "WARNING"
            }
            
            # Test reading from database and decrypting
            Write-Log "Testing decryption from database..." "INFO"
            $dbDecrypted = Get-DecodedCredentialsFromDB
            if ($dbDecrypted) {
                Write-Log "SUCCESS: Credentials decrypted from database successfully!" "INFO"
            } else {
                Write-Log "WARNING: Failed to decrypt credentials from database!" "WARNING"
            }
            
            return $Decrypted
        } else {
            Write-Log "Failed to decrypt credentials." "ERROR"
            Write-Log "DEBUG: Decrypt-Response returned null" "ERROR"
            return $null
        }
        
    } catch {
        Write-Log "Failed to fetch credentials: $_" "ERROR"
        return $null
    }
}

# -------------------------------------------------------------------------
# 6. INSTALLATION LOGIC
# -------------------------------------------------------------------------

function Test-InternetConnection {
    try {
        $result = Test-Connection -ComputerName "1.1.1.1" -Count 1 -Quiet
        return $result
    } catch {
        Write-Log "Internet connection check failed: $_" "WARNING"
        return $false
    }
}

function Install-Wazuh {
    # Default Wazuh Product Code
    $ProductCode = "{45F86F88-FE8F-4F39-90B6-BA91CFC9FADC}"
   
    # Check if already installed
    try {
        $Installed = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.IdentifyingNumber -eq $ProductCode }
        if ($Installed) {
            Write-Log "Wazuh agent is already installed." "INFO"
            return $true
        }
    } catch {
        Write-Log "Error checking for existing Wazuh installation: $_" "WARNING"
    }
   
    Write-Log "Downloading Wazuh Agent..." "INFO"
    $MsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.7.2-1.msi"
    $MsiPath = [System.IO.Path]::Combine($env:TEMP, "wazuh-agent.msi")
   
    try {
        Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath -TimeoutSec 300
       
        if (-not (Test-Path $MsiPath)) {
            Write-Log "Wazuh MSI download failed." "ERROR"
            return $false
        }
       
        Write-Log "Installing Wazuh Agent..." "INFO"
        # Silent install
        $ArgsList = @("/i", "`"$MsiPath`"", "/qn", "/norestart")
        $Process = Start-Process -FilePath "msiexec.exe" -ArgumentList $ArgsList -Wait -NoNewWindow -PassThru
       
        if ($Process.ExitCode -eq 0 -or $Process.ExitCode -eq 3010) {
            Write-Log "Wazuh Agent installation completed." "INFO"
            # Cleanup
            Remove-Item -Path $MsiPath -Force -ErrorAction SilentlyContinue
            return $true
        } else {
            Write-Log "Wazuh Agent installation failed with exit code: $($Process.ExitCode)" "ERROR"
            return $false
        }
    } catch {
        Write-Log "Failed to install Wazuh Agent: $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# 7. APPLICATION DOWNLOAD & PERSISTENCE
# -------------------------------------------------------------------------

function Stop-EbantisProcesses {
    <#
    .SYNOPSIS
    Stops all running Ebantis-related processes before installation/update.
    #>
    $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", "EbantisV4")
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
}

function Download-AppPackage {
    $ApiUrl = "https://ebantisapiv4.thekosmoz.com/DownloadLatestversion"
    $DownloadPath = [System.IO.Path]::Combine($ProgramFilesPath, "data", "downloaded_version", "Ebantisv4.zip")
    $ExtractPath = [System.IO.Path]::Combine($ProgramFilesPath, "data")
   
    $Headers = @{
        "Content-Type"   = "application/json"
        "IsInternalCall" = "true"
        "ClientId"       = "EbantisTrack"
    }
   
    try {
        # Stop all running Ebantis processes before extraction
        Write-Log "Stopping any running Ebantis processes..." "INFO"
        Stop-EbantisProcesses
        
        # Ensure directory exists
        $DownloadDir = [System.IO.Path]::GetDirectoryName($DownloadPath)
        if (-not (Test-Path $DownloadDir)) { 
            New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null 
        }
       
        Write-Log "Downloading application package from $ApiUrl..." "INFO"
        Invoke-WebRequest -Uri $ApiUrl -Method Post -Headers $Headers -OutFile $DownloadPath -TimeoutSec 600
       
        if (-not (Test-Path $DownloadPath)) {
            Write-Log "Download failed: File not found." "ERROR"
            return $false
        }
       
        Write-Log "Extracting package to $ExtractPath..." "INFO"
        Expand-Archive -Path $DownloadPath -DestinationPath $ExtractPath -Force
       
        # Cleanup
        Remove-Item -Path $DownloadPath -Force -ErrorAction SilentlyContinue
        Write-Log "Application package installed successfully." "INFO"
        return $true
    } catch {
        Write-Log "Failed to download/install application package: $_" "ERROR"
        return $false
    }
}

function Create-StartupShortcut {
    $StartupFolder = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\StartUp")
    $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", "EbantisV4")
    $TargetExe = [System.IO.Path]::Combine($MainFolder, "EbantisV4.exe")
   
    try {
        $WScriptShell = New-Object -ComObject WScript.Shell
       
        # Check if EbantisV4.exe exists
        if (Test-Path $TargetExe) {
            $ShortcutPath = [System.IO.Path]::Combine($StartupFolder, "EbantisV4.lnk")
           
            # Remove existing
            if (Test-Path $ShortcutPath) { 
                Remove-Item -Path $ShortcutPath -Force 
            }
           
            # Create new shortcut for EbantisV4.exe
            $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
            $Shortcut.TargetPath = $TargetExe
            $Shortcut.WorkingDirectory = $MainFolder
            $Shortcut.Save()
           
            Write-Log "Created startup shortcut for: EbantisV4.exe" "INFO"
           
            # Also start the process now
            Start-Process -FilePath $TargetExe -WorkingDirectory $MainFolder
            Write-Log "Started process: EbantisV4.exe" "INFO"
            return $true
        } else {
            Write-Log "EbantisV4.exe not found at: $TargetExe" "WARNING"
            return $false
        }
    } catch {
        Write-Log "Failed to create startup shortcuts: $_" "ERROR"
        return $false
    }
}

# -------------------------------------------------------------------------
# 8. UNINSTALLATION LOGIC
# -------------------------------------------------------------------------

function Uninstall-Ebantis {
    Write-Log "Starting Uninstallation..." "INFO"
   
    # 1. Kill Processes
    $MainFolder = [System.IO.Path]::Combine($ProgramFilesPath, "data", "EbantisV4")
    $TargetExe = [System.IO.Path]::Combine($MainFolder, "EbantisV4.exe")
   
    if (Test-Path $TargetExe) {
        $Procs = Get-Process -Name "EbantisV4" -ErrorAction SilentlyContinue
        if ($Procs) {
            Write-Log "Stopping process: EbantisV4" "INFO"
            Stop-Process -Name "EbantisV4" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
   
    # Also check utils and update folders for any other processes
    $UtilsPath = [System.IO.Path]::Combine($ProgramFilesPath, "data", "EbantisV4", "utils")
    $UpdatePath = [System.IO.Path]::Combine($ProgramFilesPath, "data", "EbantisV4", "update")
   
    foreach ($Folder in @($UtilsPath, $UpdatePath)) {
        if (Test-Path $Folder) {
            $Exes = Get-ChildItem -Path $Folder -Filter "*.exe" -ErrorAction SilentlyContinue
            foreach ($Exe in $Exes) {
                $ProcName = $Exe.BaseName
                $Procs = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
                if ($Procs) {
                    Write-Log "Stopping process: $ProcName" "INFO"
                    Stop-Process -Name $ProcName -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }
   
    # 2. Remove Startup Shortcuts
    $StartupFolder = [System.IO.Path]::Combine($env:ProgramData, "Microsoft\Windows\Start Menu\Programs\StartUp")
    $Shortcuts = Get-ChildItem -Path $StartupFolder -Filter "*.lnk" -ErrorAction SilentlyContinue
    foreach ($Shortcut in $Shortcuts) {
        try {
            $Shell = New-Object -ComObject WScript.Shell
            $Link = $Shell.CreateShortcut($Shortcut.FullName)
            if ($Link.TargetPath -like "*EbantisV4*" -or $Shortcut.Name -eq "EbantisV4.lnk") {
                Remove-Item -Path $Shortcut.FullName -Force
                Write-Log "Removed shortcut: $($Shortcut.Name)" "INFO"
            }
        } catch {
            # Ignore errors for individual shortcuts
        }
    }
   
    # 3. Uninstall Wazuh
    $ProductCode = "{45F86F88-FE8F-4F39-90B6-BA91CFC9FADC}"
    try {
        $Installed = Get-WmiObject -Class Win32_Product -ErrorAction SilentlyContinue | Where-Object { $_.IdentifyingNumber -eq $ProductCode }
        if ($Installed) {
            Write-Log "Uninstalling Wazuh Agent..." "INFO"
            $Installed.Uninstall() | Out-Null
            Write-Log "Wazuh Agent uninstalled." "INFO"
        }
    } catch {
        Write-Log "Failed to uninstall Wazuh Agent: $_" "WARNING"
    }
   
    # 4. Remove Files
    if (Test-Path $ProgramFilesPath) {
        try {
            Remove-Item -Path $ProgramFilesPath -Recurse -Force
            Write-Log "Removed Program Files directory." "INFO"
        } catch {
            Write-Log "Failed to remove Program Files directory: $_" "WARNING"
        }
    }
   
    Write-Log "Uninstallation completed." "INFO"
}

# -------------------------------------------------------------------------
# MAIN EXECUTION FLOW
# -------------------------------------------------------------------------

# Check for Uninstall Switch
if ($args -contains "-Uninstall") {
    Uninstall-Ebantis
    Exit
}

try {
    # 1. Internet Check
    Write-Log "Checking Internet Connection..." "INFO"
    if (-not (Test-InternetConnection)) {
        Write-Log "No Internet Connection. Installation Aborted." "ERROR"
        Read-Host "Press Enter to exit..."
        Exit
    }
    
    # 1.5 Set Directory Permissions
    Write-Log "Setting Directory Permissions..." "INFO"
    Set-DirectoryPermissions -Path $ProgramFilesPath
    Set-DirectoryPermissions -Path $ProgramDataPath
    
    # 1.6 Write Tenant Details JSON
    Write-Log "Writing tenant details to JSON file..." "INFO"
    $TenantInfoPath = $ProgramDataPath
    Write-TenantDetailsJson -TenantName $TenantName -TenantInfoPath $TenantInfoPath
    
    # 2. Gather Info
    $MachineID = Get-MachineID
    $Hostname = $env:COMPUTERNAME
    $Username = $env:USERNAME
    $DisplayName = Get-DisplayName
    $Email = Get-UserEmail
    $Upn = Get-Upn
    
    Write-Log "Machine ID: $MachineID" "INFO"
    Write-Log "Hostname: $Hostname" "INFO"
    Write-Log "Username: $Username" "INFO"
    
    # 3. Register Agent
    Write-Log "Registering agent..." "INFO"
    $RegResult = Register-Agent -MachineID $MachineID -Hostname $Hostname -DisplayName $DisplayName -Email $Email -Upn $Upn -Username $Username
    
    if (-not $RegResult) {
        Write-Log "Agent registration failed, but continuing installation..." "WARNING"
    }
   
    # 4. Get Credentials
    Write-Log "Fetching credentials..." "INFO"
    $Creds = Get-Credentials -TenantName $TenantName
    if ($Creds) {
        Write-Log "Credentials retrieved and stored successfully." "INFO"
    } else {
        Write-Log "Failed to retrieve credentials, but continuing installation..." "WARNING"
    }
    
    # 4.5 Initial Status - Mark installation as started (BEFORE download)
    Write-Log "Recording installation start..." "INFO"
    Invoke-UpsertInstallationData -TenantName $TenantName -Hostname $Hostname -StatusFlag $false -InstallationFlag $false -Status "inprogress"
   
    # 5. Download Application (BEFORE Wazuh - matching Python logic)
    Write-Log "Downloading application package..." "INFO"
    $AppInstalled = Download-AppPackage
    
    # 5.5 Update Status - Mark download complete
    if ($AppInstalled) {
        Write-Log "Updating installation status - download complete..." "INFO"
        Invoke-UpsertInstallationData -TenantName $TenantName -Hostname $Hostname -StatusFlag $true -InstallationFlag $false -Status "inprogress"
    } else {
        Write-Log "Application download failed. Aborting installation..." "ERROR"
        Invoke-UpsertInstallationData -TenantName $TenantName -Hostname $Hostname -StatusFlag $false -InstallationFlag $false -Status "failed"
        Read-Host "Press Enter to exit..."
        Exit
    }
   
    # 6. Install Wazuh (AFTER download - matching Python logic)
    Write-Log "Installing Wazuh Agent..." "INFO"
    $WazuhInstalled = Install-Wazuh
    if (-not $WazuhInstalled) {
        Write-Log "Wazuh installation failed, but continuing..." "WARNING"
    }
   
    # 7. Persistence & Start
    Write-Log "Setting up autostart..." "INFO"
    $Started = Create-StartupShortcut
    
    # 7.5 Final Status Update
    if ($Started -and $WazuhInstalled) {
        Write-Log "Installation completed successfully!" "INFO"
        Invoke-UpsertInstallationData -TenantName $TenantName -Hostname $Hostname -StatusFlag $true -InstallationFlag $true -Status "installed"
    } elseif ($Started -and -not $WazuhInstalled) {
        Write-Log "Installation completed but Wazuh failed." "WARNING"
        Invoke-UpsertInstallationData -TenantName $TenantName -Hostname $Hostname -StatusFlag $true -InstallationFlag $false -Status "installed"
    } else {
        Write-Log "Installation failed - could not start application." "ERROR"
        Invoke-UpsertInstallationData -TenantName $TenantName -Hostname $Hostname -StatusFlag $true -InstallationFlag $WazuhInstalled -Status "failed"
    }
   
    Write-Log "Installation sequence finished." "INFO"
    Write-Host ""
    Write-Host "Installation completed!" -ForegroundColor Green
    Read-Host "Press Enter to close..."
   
} catch {
    Write-Log "Fatal error in main execution: $_" "ERROR"
    Write-Host "Installation failed. Check the log file for details." -ForegroundColor Red
    Read-Host "Press Enter to exit..."
}

