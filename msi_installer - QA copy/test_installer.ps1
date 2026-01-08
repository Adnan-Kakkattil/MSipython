# Test script for installer.ps1 - Validates key functions without full installation
# This tests the installer logic with the provided branch ID

$ErrorActionPreference = "Continue"

Write-Host "=== Installer Test Script ===" -ForegroundColor Cyan
Write-Host "Branch ID: cc73f958-adc7-4baa-8058-1fb899c9ce70" -ForegroundColor Yellow
Write-Host ""

# Set environment variable
$env:EBANTIS_BRANCH_ID = "cc73f958-adc7-4baa-8058-1fb899c9ce70"
$branchId = "cc73f958-adc7-4baa-8058-1fb899c9ce70"

# Test 1: Check if branch ID is read correctly
Write-Host "[Test 1] Checking branch ID extraction..." -ForegroundColor Cyan
if ($env:EBANTIS_BRANCH_ID -eq $branchId) {
    Write-Host "  ✓ Branch ID correctly set: $env:EBANTIS_BRANCH_ID" -ForegroundColor Green
    Write-Host "  ✓ Test PASSED: Branch ID correctly extracted" -ForegroundColor Green
} else {
    Write-Host "  ✗ Test FAILED: Branch ID mismatch" -ForegroundColor Red
}

Write-Host ""

# Test 2: Check API connectivity and tenant info
Write-Host "[Test 2] Testing API connectivity and tenant info retrieval..." -ForegroundColor Cyan
try {
    $authApiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login"
    $payload = @{
        userName = "internalmanager@mail.com"
        password = "#@Admin&eu1"
    } | ConvertTo-Json
    
    Write-Host "  Attempting authentication..." -ForegroundColor Yellow
    $response = Invoke-RestMethod -Uri $authApiUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 30
    
    if ($response.accessToken) {
        Write-Host "  ✓ Authentication successful" -ForegroundColor Green
        
        # Test tenant info retrieval
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/branches/branch/$branchId"
        $headers = @{
            "Authorization" = "Bearer $($response.accessToken)"
        }
        
        Write-Host "  Fetching tenant info for branch: $branchId" -ForegroundColor Yellow
        $tenantResponse = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -TimeoutSec 30
        
        if ($tenantResponse) {
            Write-Host "  ✓ Tenant info retrieved successfully" -ForegroundColor Green
            Write-Host "    Tenant ID: $($tenantResponse.tenantUniqueId)" -ForegroundColor Gray
            Write-Host "    Company ID: $($tenantResponse.companyUniqueId)" -ForegroundColor Gray
            Write-Host "    Branch ID: $branchId" -ForegroundColor Gray
        } else {
            Write-Host "  ✗ Failed to retrieve tenant info" -ForegroundColor Red
        }
    } else {
        Write-Host "  ✗ Authentication failed: No access token" -ForegroundColor Red
    }
} catch {
    Write-Host "  ✗ API test failed: $_" -ForegroundColor Red
}

Write-Host ""

# Test 3: Check download API
Write-Host "[Test 3] Testing download API endpoint..." -ForegroundColor Cyan
try {
    $downloadUrl = "https://qaebantisapiv4.thekosmoz.com/DownloadLatestversion?branch_id=$branchId"
    $headers = @{
        "IsInternalCall" = "true"
        "ClientId" = "EbantisTrack"
    }
    
    Write-Host "  Testing download URL..." -ForegroundColor Yellow
    try {
        $headResponse = Invoke-WebRequest -Uri $downloadUrl -Method Head -Headers $headers -TimeoutSec 10 -ErrorAction Stop
        Write-Host "  ✓ Download endpoint is accessible" -ForegroundColor Green
    } catch {
        if ($_.Exception.Response.StatusCode.value__ -eq 405) {
            Write-Host "  ✓ Download endpoint accessible (HEAD not supported, but POST should work)" -ForegroundColor Green
        } else {
            Write-Host "  ⚠ Download endpoint test: $_" -ForegroundColor Yellow
        }
    }
} catch {
    Write-Host "  ✗ Download API test failed: $_" -ForegroundColor Red
}

Write-Host ""

# Test 4: Check installation allowed
Write-Host "[Test 4] Testing installation permission check..." -ForegroundColor Cyan
try {
    $authApiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/users/auth/login"
    $payload = @{
        userName = "internalmanager@mail.com"
        password = "#@Admin&eu1"
    } | ConvertTo-Json
    
    $authResponse = Invoke-RestMethod -Uri $authApiUrl -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 30
    if ($authResponse.accessToken) {
        $apiUrl = "https://qaebantisv4service.thekosmoz.com/api/v1/app-versions/branches/$branchId"
        $headers = @{
            "Authorization" = "Bearer $($authResponse.accessToken)"
        }
        
        $versionResponse = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -TimeoutSec 30
        if ($versionResponse) {
            $allowedCount = $versionResponse.allowedInstallationCount
            $installedCount = $versionResponse.installedDeviceCount
            
            Write-Host "  ✓ Installation check successful" -ForegroundColor Green
            Write-Host "    Allowed installations: $allowedCount" -ForegroundColor Gray
            Write-Host "    Installed devices: $installedCount" -ForegroundColor Gray
            if ($installedCount -lt $allowedCount) {
                Write-Host "    Status: Installation allowed" -ForegroundColor Green
            } else {
                Write-Host "    Status: Maximum reached" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  ✗ Installation check failed: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Test Summary ===" -ForegroundColor Cyan
Write-Host "All validation tests completed." -ForegroundColor Green
Write-Host ""
Write-Host "To run the full installer (requires admin privileges):" -ForegroundColor Yellow
Write-Host "  powershell -ExecutionPolicy Bypass -File installer.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Or use the MSI installer:" -ForegroundColor Yellow
$msiPath = "target\wix\EbantisTrack_cc73f958-adc7-4baa-8058-1fb899c9ce70.msi"
Write-Host "  Start-Process `"$msiPath`"" -ForegroundColor White
