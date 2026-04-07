# pillar3_pim/assign_pim_roles.ps1
# ============================================================
# Assigns eligible (just-in-time) PIM roles to MediZuva IT
# staff based on job title. No permanent active assignments —
# users must activate and justify each session.
#
# Role mapping (least-privilege per job function):
#   IT Administrator  → User Administrator, Privileged Role Administrator
#   Help Desk         → Helpdesk Administrator
#   Security Analyst  → Security Administrator, Security Reader
#   Network Engineer  → Reports Reader
#
# Safe to re-run — skips assignments that already exist.
#
# Usage: .\assign_pim_roles.ps1
# ============================================================

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

# Entra ID built-in role template IDs
# Source: learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
$ROLE_IDS = @{
    "User Administrator"            = "fe930be7-5e62-47db-91af-98c3a49a38b1"
    "Privileged Role Administrator" = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "Helpdesk Administrator"        = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    "Security Administrator"        = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "Security Reader"               = "5d6b6bb7-de71-4623-b4af-96380a352509"
    "Reports Reader"                = "4a5d8f65-41da-4de4-8968-e035b65339cf"
}

# Title → eligible roles
$TITLE_ROLE_MAP = @{
    "IT Administrator" = @("User Administrator", "Privileged Role Administrator")
    "Help Desk"        = @("Helpdesk Administrator")
    "Security Analyst" = @("Security Administrator", "Security Reader")
    "Network Engineer" = @("Reports Reader")
}

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
Write-Host " MediZuva - PIM Role Assignment (Pillar 3)"      -ForegroundColor Cyan
Write-Host " Tenant: micrlabs.onmicrosoft.com"               -ForegroundColor Cyan
Write-Host " Date:   $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# ── Resolve MZV-Dept-IT group ────────────────────────────────
Write-Host "`nResolving MZV-Dept-IT group..." -ForegroundColor Yellow
try {
    $groupResult = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq 'MZV-Dept-IT'&`$select=id,displayName" `
        -Headers $headers
    $group = $groupResult.value | Select-Object -First 1
    if (-not $group) { throw "Group not found" }
    Write-Host "  [OK] Group ID: $($group.id)" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ── Fetch group members ───────────────────────────────────────
Write-Host "`nFetching IT department members..." -ForegroundColor Yellow
try {
    $membersResult = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members?`$select=id,displayName,jobTitle" `
        -Headers $headers
    $members = $membersResult.value
    Write-Host "  [OK] Found $($members.Count) members" -ForegroundColor Green
} catch {
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# ── Fetch existing eligible assignments (to skip duplicates) ──
Write-Host "`nFetching existing PIM eligibility assignments..." -ForegroundColor Yellow
try {
    $existingResult = Invoke-RestMethod -Method GET `
        -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$select=principalId,roleDefinitionId" `
        -Headers $headers
    $existingSet = @{}
    foreach ($e in $existingResult.value) {
        $existingSet["$($e.principalId)|$($e.roleDefinitionId)"] = $true
    }
    Write-Host "  [OK] $($existingSet.Count) existing assignments indexed" -ForegroundColor Green
} catch {
    Write-Host "  [WARN] Could not fetch existing assignments - will attempt all" -ForegroundColor Yellow
    $existingSet = @{}
}

# ── Assign eligible roles ─────────────────────────────────────
Write-Host "`n--- Assigning eligible PIM roles ---" -ForegroundColor Cyan

$results  = [System.Collections.Generic.List[PSCustomObject]]::new()
$startDt  = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

foreach ($member in $members) {
    $title = $member.jobTitle
    $roles = $TITLE_ROLE_MAP[$title]

    if (-not $roles) {
        Write-Host "  [SKIP] $($member.displayName) — no role mapping for title '$title'" -ForegroundColor DarkGray
        continue
    }

    foreach ($roleName in $roles) {
        $roleId = $ROLE_IDS[$roleName]
        $key    = "$($member.id)|$roleId"

        if ($existingSet.ContainsKey($key)) {
            Write-Host "  [SKIP] $($member.displayName) → $roleName (already eligible)" -ForegroundColor Yellow
            $results.Add([PSCustomObject]@{
                User     = $member.displayName
                UserId   = $member.id
                Title    = $title
                Role     = $roleName
                RoleId   = $roleId
                Status   = "SKIPPED"
            })
            continue
        }

        try {
            $body = @{
                action           = "adminAssign"
                justification    = "MediZuva Zero-Trust PIM baseline — Pillar 3"
                roleDefinitionId = $roleId
                directoryScopeId = "/"
                principalId      = $member.id
                scheduleInfo     = @{
                    startDateTime = $startDt
                    expiration    = @{ type = "noExpiration" }
                }
            } | ConvertTo-Json -Depth 5

            Invoke-RestMethod -Method POST `
                -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests" `
                -Headers $headers `
                -ContentType "application/json" `
                -Body $body | Out-Null

            Write-Host "  [OK]   $($member.displayName) → $roleName" -ForegroundColor Green
            $results.Add([PSCustomObject]@{
                User     = $member.displayName
                UserId   = $member.id
                Title    = $title
                Role     = $roleName
                RoleId   = $roleId
                Status   = "ASSIGNED"
            })
        } catch {
            $errBody = ""
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $errBody = $reader.ReadToEnd()
            } catch {}
            Write-Host "  [FAIL] $($member.displayName) → $roleName — $errBody" -ForegroundColor Red
            $results.Add([PSCustomObject]@{
                User     = $member.displayName
                UserId   = $member.id
                Title    = $title
                Role     = $roleName
                RoleId   = $roleId
                Status   = "FAILED"
            })
        }
    }
}

# ── Summary ───────────────────────────────────────────────────
$assigned = ($results | Where-Object Status -eq "ASSIGNED").Count
$skipped  = ($results | Where-Object Status -eq "SKIPPED").Count
$failed   = ($results | Where-Object Status -eq "FAILED").Count

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "ASSIGNMENT SUMMARY"                               -ForegroundColor Cyan
Write-Host "  Assigned : $assigned" -ForegroundColor Green
Write-Host "  Skipped  : $skipped"  -ForegroundColor Yellow
Write-Host "  Failed   : $failed"   -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "=================================================" -ForegroundColor Cyan

$exportPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\pim_assignments.json"
$results | ConvertTo-Json | Out-File $exportPath -Encoding utf8
Write-Host "Assignments exported: $exportPath" -ForegroundColor Cyan
Write-Host "Run audit_pim_roles.ps1 then generate_dashboard.py to render the report.`n" -ForegroundColor Cyan
