# pillar4_threat/check_risky_users.ps1
# ============================================================
# Queries three Entra ID threat signals for MediZuva:
#   1. Identity Protection — risky users (high/medium)
#   2. MFA registration gaps — users not yet MFA registered
#   3. Device compliance gaps — non-compliant managed devices
#
# Exports data/risky_users.json for threat_audit.ps1.
#
# Usage: .\check_risky_users.ps1
# ============================================================

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

# ── Auth ─────────────────────────────────────────────────────
Write-Host "`nObtaining access token..." -ForegroundColor Yellow
try {
    $tokenResponse = Invoke-RestMethod -Method POST `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = "https://graph.microsoft.com/.default"
        }
    $headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }
    Write-Host "  [OK] Token obtained" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host " MediZuva - Threat Signal Check (Pillar 4)"      -ForegroundColor Cyan
Write-Host " Tenant: micrlabs.onmicrosoft.com"               -ForegroundColor Cyan
Write-Host " Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# ── 1. Identity Protection — Risky Users ─────────────────────
Write-Host "`n[1/3] Querying Identity Protection risky users..." -ForegroundColor Yellow
$riskyUsers = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $url = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskLevel eq 'high' or riskLevel eq 'medium'&`$select=id,userDisplayName,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime,isDeleted"
    while ($url) {
        $page = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        foreach ($u in $page.value) {
            if ($u.isDeleted) { continue }
            $colour = if ($u.riskLevel -eq "high") { "Red" } else { "Yellow" }
            Write-Host "  [$($u.riskLevel.ToUpper())] $($u.userDisplayName) — $($u.riskState)" -ForegroundColor $colour
            $riskyUsers.Add([PSCustomObject]@{
                UserId       = $u.id
                DisplayName  = $u.userDisplayName
                UPN          = $u.userPrincipalName
                RiskLevel    = $u.riskLevel
                RiskState    = $u.riskState
                LastUpdated  = $u.riskLastUpdatedDateTime
                Source       = "IdentityProtection"
            })
        }
        $url = $page.'@odata.nextLink'
    }
    Write-Host "  Total risky users: $($riskyUsers.Count)" -ForegroundColor White
} catch {
    Write-Host "  [WARN] Identity Protection query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         (Requires IdentityRiskyUser.Read.All permission)" -ForegroundColor DarkGray
}

# ── 2. MFA Registration Gaps ──────────────────────────────────
Write-Host "`n[2/3] Querying MFA registration status..." -ForegroundColor Yellow
$mfaGaps = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $url = "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails"
    while ($url) {
        $page = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        foreach ($u in $page.value) {
            if (-not $u.isMfaRegistered) {
                $mfaGaps.Add([PSCustomObject]@{
                    UserId      = $u.id
                    DisplayName = $u.userDisplayName
                    UPN         = $u.userPrincipalName
                    MFARegistered = $false
                    AuthMethods   = ($u.authMethods -join ", ")
                })
            }
        }
        $url = $page.'@odata.nextLink'
    }
    Write-Host "  Users without MFA: $($mfaGaps.Count)" -ForegroundColor $(if ($mfaGaps.Count -gt 0) { "Red" } else { "Green" })
    foreach ($u in $mfaGaps | Select-Object -First 5) {
        Write-Host "  [NO MFA] $($u.DisplayName)" -ForegroundColor Red
    }
    if ($mfaGaps.Count -gt 5) {
        Write-Host "  ... and $($mfaGaps.Count - 5) more" -ForegroundColor DarkGray
    }
} catch {
    Write-Host "  [WARN] MFA report query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         (Requires Reports.Read.All permission)" -ForegroundColor DarkGray
}

# ── 3. Device Compliance Gaps ────────────────────────────────
Write-Host "`n[3/3] Querying non-compliant managed devices..." -ForegroundColor Yellow
$deviceGaps = [System.Collections.Generic.List[PSCustomObject]]::new()
try {
    $url = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=complianceState ne 'compliant'&`$select=id,deviceName,userDisplayName,userPrincipalName,complianceState,operatingSystem,lastSyncDateTime"
    while ($url) {
        $page = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
        foreach ($d in $page.value) {
            $deviceGaps.Add([PSCustomObject]@{
                DeviceId        = $d.id
                DeviceName      = $d.deviceName
                UserDisplayName = $d.userDisplayName
                UPN             = $d.userPrincipalName
                ComplianceState = $d.complianceState
                OS              = $d.operatingSystem
                LastSync        = $d.lastSyncDateTime
            })
        }
        $url = $page.'@odata.nextLink'
    }
    Write-Host "  Non-compliant devices: $($deviceGaps.Count)" -ForegroundColor $(if ($deviceGaps.Count -gt 0) { "Yellow" } else { "Green" })
} catch {
    Write-Host "  [WARN] Device query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "         (Requires DeviceManagementManagedDevices.Read.All permission)" -ForegroundColor DarkGray
}

# ── Summary ───────────────────────────────────────────────────
Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "THREAT SIGNAL SUMMARY"                            -ForegroundColor Cyan
Write-Host "  Risky users (IdP):    $($riskyUsers.Count)"   -ForegroundColor $(if ($riskyUsers.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  MFA gaps:             $($mfaGaps.Count)"      -ForegroundColor $(if ($mfaGaps.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Non-compliant devices:$($deviceGaps.Count)"   -ForegroundColor $(if ($deviceGaps.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "=================================================" -ForegroundColor Cyan

# ── Export ────────────────────────────────────────────────────
$export = @{
    CheckDate   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Tenant      = "micrlabs.onmicrosoft.com"
    RiskyUsers  = $riskyUsers
    MFAGaps     = $mfaGaps
    DeviceGaps  = $deviceGaps
}

$exportPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\risky_users.json"
$export | ConvertTo-Json -Depth 5 | Out-File $exportPath -Encoding utf8
Write-Host "Exported: $exportPath" -ForegroundColor Cyan
Write-Host "Next: run osint_exposure_check.py, then threat_audit.ps1`n" -ForegroundColor Cyan
