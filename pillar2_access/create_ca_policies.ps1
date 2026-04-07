# pillar2_access/create_ca_policies.ps1
# ============================================================
# Deploys MediZuva Zero-Trust Conditional Access policies.
# Uses Invoke-RestMethod directly to avoid Graph SDK token cache issues.
# Safe to re-run - skips policies that already exist.
#
# Usage:
#   .\create_ca_policies.ps1
#   .\create_ca_policies.ps1 -PolicyState Enabled
# ============================================================

param(
    [ValidateSet("enabledForReportingButNotEnforced", "enabled", "disabled")]
    [string]$PolicyState = "enabledForReportingButNotEnforced"
)

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

$BreakGlassIds = @(
    "fb49fc3e-ffba-47d4-bd74-5f8397f1f5cf",  # Global.Admin
    "968c5cb1-0421-4694-84fd-3fe2b8fe92d2"   # breakglass
)

# Get a fresh access token
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
    $token = $tokenResponse.access_token
    $headers = @{ Authorization = "Bearer $token" }
    Write-Host "  [OK] Token obtained" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Could not obtain token: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function New-CAPolicy {
    param([string]$Name, [hashtable]$Body)
    try {
        $existing = Invoke-RestMethod -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Headers $headers
        $match = $existing.value | Where-Object { $_.displayName -eq $Name }
        if ($match) {
            Write-Host "  [SKIP] $Name - already exists" -ForegroundColor Yellow
            $results.Add([PSCustomObject]@{ Policy = $Name; Status = "SKIPPED"; Id = $match.id })
            return
        }
        $response = Invoke-RestMethod -Method POST `
            -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
            -Headers $headers `
            -ContentType "application/json" `
            -Body ($Body | ConvertTo-Json -Depth 10)
        Write-Host "  [OK]   $Name" -ForegroundColor Green
        $results.Add([PSCustomObject]@{ Policy = $Name; Status = "CREATED"; Id = $response.id })
    } catch {
        $errBody = ""
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $errBody = $reader.ReadToEnd()
        } catch {}
        Write-Host "  [FAIL] $Name - $errBody" -ForegroundColor Red
        $results.Add([PSCustomObject]@{ Policy = $Name; Status = "FAILED"; Id = "" })
    }
}

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host " MediZuva - Conditional Access Policy Deployment" -ForegroundColor Cyan
Write-Host " Tenant: micrlabs.onmicrosoft.com"               -ForegroundColor Cyan
Write-Host " State:  $PolicyState"                           -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# CA001 - Require MFA for all users
Write-Host "`n[CA001] Require MFA for all users..."
New-CAPolicy -Name "MZV-CA001-RequireMFA-AllUsers" -Body @{
    displayName   = "MZV-CA001-RequireMFA-AllUsers"
    state         = $PolicyState
    conditions    = @{
        users          = @{ includeUsers = @("All"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
}

# CA002 - Block legacy authentication
Write-Host "`n[CA002] Block legacy authentication..."
New-CAPolicy -Name "MZV-CA002-BlockLegacyAuth" -Body @{
    displayName   = "MZV-CA002-BlockLegacyAuth"
    state         = $PolicyState
    conditions    = @{
        users          = @{ includeUsers = @("All"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("exchangeActiveSync", "other")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("block") }
}

# CA003 - Require compliant device for Clinical, Pharmacy, Radiology
Write-Host "`n[CA003] Require compliant device for clinical departments..."
New-CAPolicy -Name "MZV-CA003-RequireCompliantDevice-Clinical" -Body @{
    displayName   = "MZV-CA003-RequireCompliantDevice-Clinical"
    state         = $PolicyState
    conditions    = @{
        users          = @{ includeGroups = @("MZV-Dept-Clinical", "MZV-Dept-Pharmacy", "MZV-Dept-Radiology"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("compliantDevice") }
}

# CA004 - Block high sign-in risk
Write-Host "`n[CA004] Block high-risk sign-ins..."
New-CAPolicy -Name "MZV-CA004-BlockHighRiskSignin" -Body @{
    displayName   = "MZV-CA004-BlockHighRiskSignin"
    state         = $PolicyState
    conditions    = @{
        users            = @{ includeUsers = @("All"); excludeUsers = $BreakGlassIds }
        applications     = @{ includeApplications = @("All") }
        clientAppTypes   = @("all")
        signInRiskLevels = @("high")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("block") }
}

# CA005 - IT admins require MFA AND compliant device
Write-Host "`n[CA005] Require MFA + compliant device for IT admins..."
New-CAPolicy -Name "MZV-CA005-RequireMFAAndDevice-Admins" -Body @{
    displayName   = "MZV-CA005-RequireMFAAndDevice-Admins"
    state         = $PolicyState
    conditions    = @{
        users          = @{ includeGroups = @("MZV-Dept-IT"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    grantControls = @{ operator = "AND"; builtInControls = @("mfa", "compliantDevice") }
}

# CA006 - 8-hour session limit for all users
# NIST SP 800-63B Section 7.2 — reauthentication required after inactivity
Write-Host "`n[CA006] Enforce 8-hour session limit (all users)..."
New-CAPolicy -Name "MZV-CA006-SessionControl-8h" -Body @{
    displayName     = "MZV-CA006-SessionControl-8h"
    state           = $PolicyState
    conditions      = @{
        users          = @{ includeUsers = @("All"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    sessionControls = @{
        signInFrequency   = @{ value = 8; type = "hours"; isEnabled = $true }
        persistentBrowser = @{ mode = "never"; isEnabled = $true }
    }
}

# CA007 - Privileged admin 30-minute session limit
# NIST SP 800-63B AAL2/AAL3 Section 7.2 — re-authentication every 30 min for privileged roles
# NIST SP 800-53 Rev5 AC-11, IA-11 — session lock and re-authentication for privileged accounts
Write-Host "`n[CA007] Enforce 30-minute session limit for privileged admins (NIST SP 800-63B AAL2)..."
New-CAPolicy -Name "MZV-CA007-SessionControl-Admins-30min" -Body @{
    displayName     = "MZV-CA007-SessionControl-Admins-30min"
    state           = $PolicyState
    conditions      = @{
        users          = @{ includeGroups = @("MZV-Dept-IT"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
    }
    sessionControls = @{
        signInFrequency   = @{ value = 30; type = "minutes"; isEnabled = $true }
        persistentBrowser = @{ mode = "never"; isEnabled = $true }
    }
}

# CA008 - Block HIGH user risk (identity-level risk, not just sign-in risk)
# NIST SP 800-207 Section 3.1 Tenet 4 — access determined by dynamic policy including user risk state
# NIST SP 800-53 Rev5 SI-4 — information system monitoring; RA-3 — risk assessment
# Complements CA004 (sign-in risk) — together they cover both risk dimensions
Write-Host "`n[CA008] Block high user risk — NIST SP 800-207 Tenet 4, SP 800-53 SI-4..."
New-CAPolicy -Name "MZV-CA008-BlockHighUserRisk" -Body @{
    displayName   = "MZV-CA008-BlockHighUserRisk"
    state         = $PolicyState
    conditions    = @{
        users           = @{ includeUsers = @("All"); excludeUsers = $BreakGlassIds }
        applications    = @{ includeApplications = @("All") }
        clientAppTypes  = @("all")
        userRiskLevels  = @("high")
    }
    grantControls = @{ operator = "OR"; builtInControls = @("block") }
}

# CA009 - Require password change for medium/high user risk
# NIST SP 800-53 Rev5 IA-5(1) — authenticator management; enforce password change on compromise
# NIST SP 800-63B Section 5.1.1.2 — verifiers SHALL force change when credential compromised
Write-Host "`n[CA009] Require MFA + password change for medium user risk — NIST SP 800-53 IA-5(1)..."
New-CAPolicy -Name "MZV-CA009-PasswordChange-MediumUserRisk" -Body @{
    displayName   = "MZV-CA009-PasswordChange-MediumUserRisk"
    state         = $PolicyState
    conditions    = @{
        users          = @{ includeUsers = @("All"); excludeUsers = $BreakGlassIds }
        applications   = @{ includeApplications = @("All") }
        clientAppTypes = @("all")
        userRiskLevels = @("medium", "high")
    }
    grantControls = @{ operator = "AND"; builtInControls = @("mfa", "passwordChange") }
}

# Summary
$created = ($results | Where-Object Status -eq "CREATED").Count
$skipped = ($results | Where-Object Status -eq "SKIPPED").Count
$failed  = ($results | Where-Object Status -eq "FAILED").Count

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "DEPLOYMENT SUMMARY"                               -ForegroundColor Cyan
Write-Host "  Created : $created"  -ForegroundColor Green
Write-Host "  Skipped : $skipped"  -ForegroundColor Yellow
Write-Host "  Failed  : $failed"   -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "=================================================" -ForegroundColor Cyan

$exportPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\ca_policy_status.json"
$results | ConvertTo-Json | Out-File $exportPath -Encoding utf8
Write-Host "Status exported: $exportPath" -ForegroundColor Cyan
