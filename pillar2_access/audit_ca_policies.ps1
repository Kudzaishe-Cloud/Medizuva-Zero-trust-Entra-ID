# pillar2_access/audit_ca_policies.ps1
# ============================================================
# Audits the current state of MediZuva Conditional Access
# policies in Entra ID. Outputs a console report and exports
# data to JSON for the dashboard.
#
# Usage: .\audit_ca_policies.ps1
# ============================================================

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

$EXPECTED_POLICIES = @(
    "MZV-CA001-RequireMFA-AllUsers",
    "MZV-CA002-BlockLegacyAuth",
    "MZV-CA003-RequireCompliantDevice-Clinical",
    "MZV-CA004-BlockHighRiskSignin",
    "MZV-CA005-RequireMFAAndDevice-Admins",
    "MZV-CA006-SessionControl-8h"
)

# Get fresh token
Write-Host "Obtaining access token..." -ForegroundColor Yellow
$tokenResponse = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
    -Body @{
        grant_type    = "client_credentials"
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
    }
$headers = @{ Authorization = "Bearer $($tokenResponse.access_token)" }

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host " MediZuva - Conditional Access Audit Report"      -ForegroundColor Cyan
Write-Host " Tenant: micrlabs.onmicrosoft.com"               -ForegroundColor Cyan
Write-Host " Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# Fetch all CA policies
$allPolicies = (Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" `
    -Headers $headers).value

# Fetch total user count
try {
    $totalUsers = (Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/users?`$count=true&`$top=1" `
        -Headers ($headers + @{ ConsistencyLevel = "eventual" })).'@odata.count'
} catch {
    $totalUsers = 500
}
Write-Host "`nTotal users: $totalUsers" -ForegroundColor White

# Policy coverage check
Write-Host "`n--- Policy Status ---" -ForegroundColor Cyan
$auditRows = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($expectedName in $EXPECTED_POLICIES) {
    $match = $allPolicies | Where-Object { $_.displayName -eq $expectedName }

    if (-not $match) {
        Write-Host "  [MISSING] $expectedName" -ForegroundColor Red
        $auditRows.Add([PSCustomObject]@{
            PolicyName = $expectedName
            State      = "MISSING"
            Id         = ""
            CreatedAt  = ""
            ModifiedAt = ""
        })
        continue
    }

    $stateLabel = switch ($match.state) {
        "enabled"                           { "ENFORCED"    }
        "enabledForReportingButNotEnforced" { "REPORT-ONLY" }
        "disabled"                          { "DISABLED"    }
        default                             { $match.state  }
    }
    $stateColour = switch ($stateLabel) {
        "ENFORCED"    { "Green"  }
        "REPORT-ONLY" { "Yellow" }
        default       { "Red"    }
    }

    Write-Host "  [$stateLabel] $expectedName" -ForegroundColor $stateColour
    $auditRows.Add([PSCustomObject]@{
        PolicyName = $match.displayName
        State      = $stateLabel
        Id         = $match.id
        CreatedAt  = $match.createdDateTime
        ModifiedAt = $match.modifiedDateTime
    })
}

# Extra policies not managed by MediZuva
$extraPolicies = $allPolicies | Where-Object { $_.displayName -notin $EXPECTED_POLICIES }
if ($extraPolicies) {
    Write-Host "`n--- Additional policies (not MediZuva-managed) ---" -ForegroundColor Yellow
    foreach ($p in $extraPolicies) {
        Write-Host "  [$($p.state)] $($p.displayName)" -ForegroundColor Yellow
    }
}

# Summary
$enforced   = ($auditRows | Where-Object State -eq "ENFORCED").Count
$reportOnly = ($auditRows | Where-Object State -eq "REPORT-ONLY").Count
$disabled   = ($auditRows | Where-Object State -eq "DISABLED").Count
$missing    = ($auditRows | Where-Object State -eq "MISSING").Count
$total      = $EXPECTED_POLICIES.Count
$coverage   = if ($total -gt 0) { [math]::Round(($enforced / $total) * 100, 1) } else { 0 }

$posture = if ($missing -eq 0 -and $disabled -eq 0 -and $enforced -gt 0) { "COMPLIANT" }
           elseif ($missing -gt 0 -or $disabled -gt 2) { "AT RISK" }
           else { "PARTIAL" }

$postureColour = switch ($posture) { "COMPLIANT" { "Green" } "AT RISK" { "Red" } default { "Yellow" } }

Write-Host "`n--- Coverage Summary ---" -ForegroundColor Cyan
Write-Host "  Enforced    : $enforced / $total ($coverage% enforcement)" -ForegroundColor Green
Write-Host "  Report-only : $([int]$reportOnly)" -ForegroundColor Yellow
Write-Host "  Disabled    : $([int]$disabled)"   -ForegroundColor Red
Write-Host "  Missing     : $([int]$missing)"    -ForegroundColor Red
Write-Host "`n  Zero-Trust Posture: $posture" -ForegroundColor $postureColour
Write-Host "=================================================" -ForegroundColor Cyan

# Export for dashboard
$exportData = @{
    AuditDate  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Tenant     = "micrlabs.onmicrosoft.com"
    TotalUsers = $totalUsers
    Policies   = $auditRows
    Summary    = @{
        Enforced   = $enforced
        ReportOnly = $reportOnly
        Disabled   = $disabled
        Missing    = $missing
        Total      = $total
        Coverage   = $coverage
        Posture    = $posture
    }
}

$exportPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\ca_audit.json"
$exportData | ConvertTo-Json -Depth 5 | Out-File $exportPath -Encoding utf8
Write-Host "Audit exported: $exportPath" -ForegroundColor Cyan
Write-Host "Run generate_dashboard.py to render the HTML report.`n" -ForegroundColor Cyan
