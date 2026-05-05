# pillar3_pim/audit_pim_roles.ps1
# ============================================================
# Audits MediZuva PIM role state in Entra ID:
#   - Eligible assignments (JIT, must be activated)
#   - Active assignments (currently elevated)
#   - Recent activation history (last 30 days)
#
# Outputs a console report and exports data/pim_audit.json
# for the dashboard.
#
# Usage: .\audit_pim_roles.ps1
# ============================================================

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

# Roles we track for MediZuva IT staff
$MANAGED_ROLES = @(
    "User Administrator",
    "Privileged Role Administrator",
    "Helpdesk Administrator",
    "Security Administrator",
    "Security Reader",
    "Reports Reader"
)

# ── Auth ─────────────────────────────────────────────────────
Write-Host "Obtaining access token..." -ForegroundColor Yellow
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
Write-Host " MediZuva - PIM Audit Report (Pillar 3)"         -ForegroundColor Cyan
Write-Host " Tenant: micrlabs.onmicrosoft.com"               -ForegroundColor Cyan
Write-Host " Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# ── Helper: resolve user display name ────────────────────────
$userCache = @{}
function Get-UserName {
    param([string]$UserId)
    if ($userCache.ContainsKey($UserId)) { return $userCache[$UserId] }
    try {
        $u = Invoke-RestMethod -Method GET `
            -Uri "https://graph.microsoft.com/v1.0/users/$UserId`?`$select=displayName,jobTitle,department" `
            -Headers $headers
        $userCache[$UserId] = $u.displayName
        return $u.displayName
    } catch {
        $userCache[$UserId] = $UserId
        return $UserId
    }
}

# ── Eligible assignments ──────────────────────────────────────
Write-Host "`n--- Eligible PIM Assignments (JIT) ---" -ForegroundColor Cyan
try {
    $eligibleResult = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$expand=roleDefinition,principal" `
        -Headers $headers
    $eligibleAll = $eligibleResult.value
} catch {
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
    $eligibleAll = @()
}

$eligibleRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($e in $eligibleAll) {
    $roleName = $e.roleDefinition.displayName
    if ($roleName -notin $MANAGED_ROLES) { continue }

    $userName = if ($e.principal.displayName) { $e.principal.displayName } else { Get-UserName $e.principalId }
    Write-Host "  [ELIGIBLE] $userName → $roleName" -ForegroundColor Green
    $eligibleRows.Add([PSCustomObject]@{
        User       = $userName
        UserId     = $e.principalId
        Role       = $roleName
        RoleId     = $e.roleDefinitionId
        ScopeId    = $e.directoryScopeId
        StartDate  = $e.startDateTime
        EndDate    = $e.endDateTime
    })
}
Write-Host "  Total eligible: $($eligibleRows.Count)" -ForegroundColor White

# ── Active assignments (currently elevated) ───────────────────
Write-Host "`n--- Active PIM Assignments (Currently Elevated) ---" -ForegroundColor Cyan
try {
    $activeResult = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$expand=roleDefinition,principal&`$filter=assignmentType eq 'Activated'" `
        -Headers $headers
    $activeAll = $activeResult.value
} catch {
    Write-Host "  [WARN] Could not fetch active assignments: $($_.Exception.Message)" -ForegroundColor Yellow
    $activeAll = @()
}

$activeRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($a in $activeAll) {
    $roleName = $a.roleDefinition.displayName
    if ($roleName -notin $MANAGED_ROLES) { continue }

    $userName = if ($a.principal.displayName) { $a.principal.displayName } else { Get-UserName $a.principalId }
    $expiry   = if ($a.endDateTime) { $a.endDateTime } else { "No expiry" }
    Write-Host "  [ACTIVE] $userName → $roleName (expires: $expiry)" -ForegroundColor Yellow
    $activeRows.Add([PSCustomObject]@{
        User      = $userName
        UserId    = $a.principalId
        Role      = $roleName
        RoleId    = $a.roleDefinitionId
        StartDate = $a.startDateTime
        EndDate   = $expiry
    })
}
if ($activeRows.Count -eq 0) {
    Write-Host "  No active JIT elevations right now." -ForegroundColor DarkGray
}

# ── Activation history (last 30 days) ────────────────────────
Write-Host "`n--- Activation History (Last 30 Days) ---" -ForegroundColor Cyan
$since = (Get-Date).AddDays(-30).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
try {
    $historyResult = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Add eligible member to role in PIM completed (permanent)' or activityDisplayName eq 'Add member to role in PIM requested (timebound)' and activityDateTime ge $since&`$top=50" `
        -Headers $headers
    $historyAll = $historyResult.value
} catch {
    Write-Host "  [WARN] Audit log query failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $historyAll = @()
}

$historyRows = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($h in $historyAll) {
    $initiatedBy = $h.initiatedBy.user.displayName
    $target      = ($h.targetResources | Select-Object -First 1).displayName
    Write-Host "  [$($h.activityDateTime)] $initiatedBy — $($h.activityDisplayName) — $target" -ForegroundColor DarkGray
    $historyRows.Add([PSCustomObject]@{
        Date        = $h.activityDateTime
        InitiatedBy = $initiatedBy
        Activity    = $h.activityDisplayName
        Target      = $target
        Result      = $h.result
    })
}
if ($historyRows.Count -eq 0) {
    Write-Host "  No activation history found." -ForegroundColor DarkGray
}

# ── Role coverage summary ─────────────────────────────────────
Write-Host "`n--- Role Coverage Summary ---" -ForegroundColor Cyan
foreach ($role in $MANAGED_ROLES) {
    $count = ($eligibleRows | Where-Object Role -eq $role).Count
    Write-Host ("  {0,-40} {1} eligible" -f $role, $count) -ForegroundColor $(if ($count -gt 0) { "Green" } else { "Yellow" })
}

# ── Posture evaluation ────────────────────────────────────────
$unassignedRoles = ($MANAGED_ROLES | Where-Object { ($eligibleRows | Where-Object Role -eq $_).Count -eq 0 }).Count
$posture = if ($unassignedRoles -eq 0 -and $eligibleRows.Count -gt 0) { "COMPLIANT" }
           elseif ($eligibleRows.Count -eq 0)                          { "AT RISK"   }
           else                                                         { "PARTIAL"   }
$postureColour = switch ($posture) { "COMPLIANT" { "Green" } "AT RISK" { "Red" } default { "Yellow" } }

Write-Host "`n  Zero-Trust PIM Posture: $posture" -ForegroundColor $postureColour
Write-Host "=================================================" -ForegroundColor Cyan

# ── Export for dashboard ──────────────────────────────────────
$exportData = @{
    AuditDate  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Tenant     = "micrlabs.onmicrosoft.com"
    Eligible   = $eligibleRows
    Active     = $activeRows
    History    = $historyRows
    Summary    = @{
        TotalEligible    = $eligibleRows.Count
        ActiveNow        = $activeRows.Count
        ActivationsLast30= $historyRows.Count
        UnassignedRoles  = $unassignedRoles
        Posture          = $posture
    }
}

$exportPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\pim_audit.json"
$exportData | ConvertTo-Json -Depth 6 | Out-File $exportPath -Encoding utf8
Write-Host "Audit exported: $exportPath" -ForegroundColor Cyan
Write-Host "Run dashboard\generate_dashboard.py to render the HTML report.`n" -ForegroundColor Cyan
