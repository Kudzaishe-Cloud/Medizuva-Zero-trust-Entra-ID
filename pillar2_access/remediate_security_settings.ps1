# pillar2_access/remediate_security_settings.ps1
# ============================================================
# Remediates Entra ID Secure Score recommendations not covered
# by Conditional Access policies:
#
#   1. App consent policy  — block user consent to unreliable apps
#   2. SSPR                — enable self-service password reset
#   3. Admin role audit    — least-privilege check (report only)
#   4. MFA registration    — report users who cannot complete MFA
#
# Usage:
#   .\remediate_security_settings.ps1           # report-only (safe)
#   .\remediate_security_settings.ps1 -Apply    # apply fixes 1 & 2
# ============================================================

param(
    [switch]$Apply   # apply changes; default is report-only
)

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host " MediZuva — Security Settings Remediation"        -ForegroundColor Cyan
Write-Host " Tenant : micrlabs.onmicrosoft.com"               -ForegroundColor Cyan
Write-Host " Mode   : $(if ($Apply) { 'APPLY' } else { 'REPORT-ONLY' })" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# ── Auth ──────────────────────────────────────────────────────
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
    $token   = $tokenResponse.access_token
    $headers = @{
        Authorization  = "Bearer $token"
        "Content-Type" = "application/json"
    }
    Write-Host "  [OK] Token obtained" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] Could not obtain token: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$report = [System.Collections.Generic.List[PSCustomObject]]::new()

# ── 1. App Consent Policy ─────────────────────────────────────
# Secure Score: "Do not allow users to grant consent to unreliable applications"
# Fix: restrict to low-risk verified-publisher apps only
Write-Host "`n[1/4] Checking app consent policy..."
try {
    $authPolicy = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
        -Headers $headers

    $consentPolicies = $authPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned
    Write-Host "  Current consent policies: $($consentPolicies -join ', ')"

    $isCompliant = ($consentPolicies -eq $null) -or
                   ($consentPolicies.Count -eq 0) -or
                   ($consentPolicies -contains "managePermissionGrantsForSelf.microsoft-user-default-low")

    if ($isCompliant) {
        Write-Host "  [OK] App consent is already restricted." -ForegroundColor Green
        $report.Add([PSCustomObject]@{ Check = "AppConsent"; Status = "OK"; Action = "None" })
    } else {
        Write-Host "  [WARN] Users can consent to unreliable apps." -ForegroundColor Yellow
        if ($Apply) {
            # Allow consent only to low-risk apps from verified publishers (MS recommended)
            $patchBody = @{
                defaultUserRolePermissions = @{
                    permissionGrantPoliciesAssigned = @("managePermissionGrantsForSelf.microsoft-user-default-low")
                }
            } | ConvertTo-Json -Depth 5
            Invoke-RestMethod -Method PATCH `
                -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" `
                -Headers $headers `
                -Body $patchBody | Out-Null
            Write-Host "  [FIXED] Consent restricted to verified low-risk apps." -ForegroundColor Green
            $report.Add([PSCustomObject]@{ Check = "AppConsent"; Status = "FIXED"; Action = "Set to microsoft-user-default-low" })
        } else {
            Write-Host "  [ACTION] Run with -Apply to restrict app consent." -ForegroundColor Cyan
            $report.Add([PSCustomObject]@{ Check = "AppConsent"; Status = "NEEDS_FIX"; Action = "Set permissionGrantPoliciesAssigned to microsoft-user-default-low" })
        }
    }
} catch {
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $report.Add([PSCustomObject]@{ Check = "AppConsent"; Status = "ERROR"; Action = $_.Exception.Message })
}

# ── 2. Self-Service Password Reset ────────────────────────────
# Secure Score: "Enable self-service password reset"
# Requires Entra ID P1 or higher. Checks SSPR registration via credentialUserRegistrationDetails.
Write-Host "`n[2/4] Checking SSPR registration coverage..."
try {
    $mfaRegs = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" `
        -Headers $headers
    $total    = $mfaRegs.value.Count
    $sspr     = ($mfaRegs.value | Where-Object { $_.isSsprRegistered }).Count
    $pct      = if ($total -gt 0) { [math]::Round($sspr / $total * 100, 1) } else { 0 }
    Write-Host "  SSPR registered: $sspr / $total users ($pct%)"

    if ($pct -ge 90) {
        Write-Host "  [OK] SSPR registration is healthy." -ForegroundColor Green
        $report.Add([PSCustomObject]@{ Check = "SSPR"; Status = "OK"; Action = "None" })
    } else {
        Write-Host "  [WARN] Low SSPR registration ($pct%). Enable SSPR in Entra admin center:" -ForegroundColor Yellow
        Write-Host "         Entra Admin Center → Password reset → Properties → Enable for All" -ForegroundColor Yellow
        $report.Add([PSCustomObject]@{ Check = "SSPR"; Status = "NEEDS_FIX"; Action = "Enable SSPR for All in Entra admin center > Password reset > Properties" })
    }
} catch {
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $report.Add([PSCustomObject]@{ Check = "SSPR"; Status = "ERROR"; Action = $_.Exception.Message })
}

# ── 3. Admin Role Least Privilege Audit ──────────────────────
# Secure Score: "Use least privileged administrative roles"
# Lists permanent (non-PIM) global admin assignments and flags excess.
Write-Host "`n[3/4] Auditing permanent admin role assignments..."
try {
    # Global Administrator role template ID
    $globalAdminRoleId = "62e90394-69f5-4237-9190-012177145e10"
    $roleAssignments = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId%20eq%20'$globalAdminRoleId'&`$expand=principal" `
        -Headers $headers

    $globalAdmins = $roleAssignments.value | Where-Object { $_.directoryScopeId -eq "/" }
    Write-Host "  Permanent Global Admins: $($globalAdmins.Count)"

    foreach ($a in $globalAdmins) {
        $name = $a.principal.displayName
        $upn  = $a.principal.userPrincipalName
        Write-Host "    - $name ($upn)"
    }

    if ($globalAdmins.Count -gt 2) {
        Write-Host "  [WARN] More than 2 permanent Global Admins. Move to PIM eligible assignments." -ForegroundColor Yellow
        $report.Add([PSCustomObject]@{ Check = "LeastPrivilege"; Status = "NEEDS_FIX"; Action = "Convert $($globalAdmins.Count - 2) permanent Global Admin(s) to PIM eligible" })
    } elseif ($globalAdmins.Count -eq 0) {
        Write-Host "  [WARN] No permanent Global Admins found (ensure break-glass accounts exist)." -ForegroundColor Yellow
        $report.Add([PSCustomObject]@{ Check = "LeastPrivilege"; Status = "WARN"; Action = "Verify break-glass accounts have Global Admin assigned" })
    } else {
        Write-Host "  [OK] Global Admin count is acceptable ($($globalAdmins.Count))." -ForegroundColor Green
        $report.Add([PSCustomObject]@{ Check = "LeastPrivilege"; Status = "OK"; Action = "None" })
    }
} catch {
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $report.Add([PSCustomObject]@{ Check = "LeastPrivilege"; Status = "ERROR"; Action = $_.Exception.Message })
}

# ── 4. MFA Registration Gap Report ───────────────────────────
# Secure Score: "Ensure all users can complete multifactor authentication"
# Lists users not yet MFA-registered so IT can target the MFA registration campaign.
Write-Host "`n[4/4] Reporting MFA registration gaps..."
try {
    $allRegs = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails" `
        -Headers $headers
    $noMFA = $allRegs.value | Where-Object { -not $_.isMfaRegistered }
    Write-Host "  Users without MFA registered: $($noMFA.Count)"

    if ($noMFA.Count -gt 0) {
        Write-Host "  Users to target in MFA registration campaign:" -ForegroundColor Yellow
        $noMFA | ForEach-Object { Write-Host "    - $($_.userDisplayName) ($($_.userPrincipalName))" }
        Write-Host ""
        Write-Host "  ACTION: Send MFA registration campaign via:" -ForegroundColor Cyan
        Write-Host "    Entra Admin → Security → Authentication methods → Registration campaign" -ForegroundColor Cyan
        $report.Add([PSCustomObject]@{
            Check  = "MFARegistration"
            Status = "NEEDS_FIX"
            Action = "Launch MFA registration campaign for $($noMFA.Count) users"
        })
    } else {
        Write-Host "  [OK] All users are MFA-registered." -ForegroundColor Green
        $report.Add([PSCustomObject]@{ Check = "MFARegistration"; Status = "OK"; Action = "None" })
    }

    # Export gap list
    $gapPath = Join-Path $PSScriptRoot "..\data\mfa_gap_report.json"
    $gapPath  = [System.IO.Path]::GetFullPath($gapPath)
    $noMFA | Select-Object userDisplayName, userPrincipalName, authMethods | ConvertTo-Json | Out-File $gapPath -Encoding utf8
    Write-Host "  Gap report saved: $gapPath" -ForegroundColor Cyan
} catch {
    Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
    $report.Add([PSCustomObject]@{ Check = "MFARegistration"; Status = "ERROR"; Action = $_.Exception.Message })
}

# ── Summary ───────────────────────────────────────────────────
Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host " REMEDIATION REPORT"                               -ForegroundColor Cyan
$report | Format-Table -AutoSize
$ok      = ($report | Where-Object Status -eq "OK").Count
$fixed   = ($report | Where-Object Status -eq "FIXED").Count
$needs   = ($report | Where-Object Status -in @("NEEDS_FIX", "WARN")).Count
$errors  = ($report | Where-Object Status -eq "ERROR").Count
Write-Host " OK: $ok  Fixed: $fixed  Needs action: $needs  Errors: $errors" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

$rptPath = Join-Path $PSScriptRoot "..\data\security_remediation_report.json"
$rptPath  = [System.IO.Path]::GetFullPath($rptPath)
$report | ConvertTo-Json | Out-File $rptPath -Encoding utf8
Write-Host "Full report saved: $rptPath`n" -ForegroundColor Cyan
