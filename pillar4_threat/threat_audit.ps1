# pillar4_threat/threat_audit.ps1
# ============================================================
# Aggregates all Pillar 4 threat signals into a unified risk
# report and exports data/threat_audit.json for the dashboard.
#
# Inputs (run these first):
#   check_risky_users.ps1      → data/risky_users.json
#   osint_exposure_check.py    → data/osint_results/hibp_results.json
#
# Risk Tier Classification:
#   CRITICAL — Identity Protection HIGH risk, OR HIBP exposed + no MFA
#   HIGH     — Identity Protection MEDIUM risk, OR HIBP exposed, OR no MFA
#   MEDIUM   — Non-compliant device, OR RiskScore > 15
#   LOW      — No signals detected
#
# Usage: .\threat_audit.ps1
# ============================================================

$TenantId     = $env:ENTRA_TENANT_ID
$ClientId     = $env:ENTRA_CLIENT_ID
$ClientSecret = $env:ENTRA_CLIENT_SECRET

$RiskyUsersPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\risky_users.json"
$HIBPPath       = "C:\Users\Kudzaishe\medizuva-zt-framework\data\osint_results\hibp_results.json"
$PersonasPath   = "C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\medizuva_500_personas.csv"
$ExportPath     = "C:\Users\Kudzaishe\medizuva-zt-framework\data\threat_audit.json"

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host " MediZuva - Threat Audit (Pillar 4)"             -ForegroundColor Cyan
Write-Host " Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan

# ── Load signal files ─────────────────────────────────────────
Write-Host "`nLoading threat signals..." -ForegroundColor Yellow

$riskyData  = if (Test-Path $RiskyUsersPath) { Get-Content $RiskyUsersPath | ConvertFrom-Json } else { $null }
$hibpData   = if (Test-Path $HIBPPath)       { Get-Content $HIBPPath       | ConvertFrom-Json } else { $null }

if (-not $riskyData) { Write-Host "  [WARN] risky_users.json not found — run check_risky_users.ps1" -ForegroundColor Yellow }
if (-not $hibpData)  { Write-Host "  [WARN] hibp_results.json not found — run osint_exposure_check.py" -ForegroundColor Yellow }

# ── Load personas CSV ─────────────────────────────────────────
Write-Host "  Loading personas CSV..." -ForegroundColor DarkGray
$personas = Import-Csv $PersonasPath
Write-Host "  [OK] $($personas.Count) personas loaded" -ForegroundColor Green

# ── Build lookup tables ───────────────────────────────────────

# Identity Protection: UPN → risk level
$idpRisk = @{}
if ($riskyData) {
    foreach ($u in $riskyData.RiskyUsers) {
        $idpRisk[$u.UPN.ToLower()] = $u.RiskLevel
    }
}

# MFA gaps: UPN → true if missing MFA
$mfaMissing = @{}
if ($riskyData) {
    foreach ($u in $riskyData.MFAGaps) {
        $mfaMissing[$u.UPN.ToLower()] = $true
    }
}

# Device gaps: UPN → non-compliant device count
$deviceNonCompliant = @{}
if ($riskyData) {
    foreach ($d in $riskyData.DeviceGaps) {
        $upn = $d.UPN.ToLower()
        $deviceNonCompliant[$upn] = ($deviceNonCompliant[$upn] -as [int]) + 1
    }
}

# HIBP: email → breach list
$hibpExposed = @{}
if ($hibpData) {
    foreach ($r in $hibpData.Results) {
        if ($r.Exposed) {
            $hibpExposed[$r.Email.ToLower()] = $r.Breaches
        }
    }
}

Write-Host "  [OK] Signals loaded — IdP:$($idpRisk.Count) MFA-gaps:$($mfaMissing.Count) Device-gaps:$($deviceNonCompliant.Count) HIBP:$($hibpExposed.Count)" -ForegroundColor Green

# ── Classify each persona ─────────────────────────────────────
Write-Host "`n--- Classifying risk tiers ---" -ForegroundColor Cyan

$userRisks = [System.Collections.Generic.List[PSCustomObject]]::new()
$tierCount = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0 }

foreach ($p in $personas) {
    $upn        = $p.Email.ToLower()
    $idpLevel   = $idpRisk[$upn]
    $noMFA      = $mfaMissing.ContainsKey($upn) -or ($p.MFARegistered -eq "False")
    $noDev      = $deviceNonCompliant.ContainsKey($upn) -or ($p.DeviceCompliant -eq "False")
    $hibp       = $hibpExposed.ContainsKey($upn)
    $riskScore  = [int]$p.RiskScore

    $signals = [System.Collections.Generic.List[string]]::new()
    if ($idpLevel -eq "high")   { $signals.Add("IdP-High") }
    if ($idpLevel -eq "medium") { $signals.Add("IdP-Medium") }
    if ($noMFA)                  { $signals.Add("No-MFA") }
    if ($noDev)                  { $signals.Add("Non-Compliant-Device") }
    if ($hibp)                   { $signals.Add("HIBP-Exposed") }
    if ($riskScore -gt 15)       { $signals.Add("HighRiskScore($riskScore)") }

    $tier = if ($idpLevel -eq "high" -or ($hibp -and $noMFA)) {
        "CRITICAL"
    } elseif ($idpLevel -eq "medium" -or $hibp -or $noMFA) {
        "HIGH"
    } elseif ($noDev -or $riskScore -gt 15) {
        "MEDIUM"
    } else {
        "LOW"
    }

    $tierCount[$tier]++

    if ($tier -in @("CRITICAL", "HIGH")) {
        $colour = if ($tier -eq "CRITICAL") { "Red" } else { "Yellow" }
        Write-Host ("  [{0,-8}] {1} {2} ({3}) — {4}" -f $tier, $p.FirstName, $p.LastName, $p.JobTitle, ($signals -join ", ")) -ForegroundColor $colour
    }

    $userRisks.Add([PSCustomObject]@{
        UPN        = $upn
        Name       = "$($p.FirstName) $($p.LastName)"
        Department = $p.Department
        JobTitle   = $p.JobTitle
        Location   = $p.Location
        Tier       = $tier
        Signals    = ($signals -join ", ")
        RiskScore  = $riskScore
        IdPRisk    = if ($idpLevel) { $idpLevel } else { "none" }
        MFAGap     = $noMFA
        DeviceGap  = $noDev
        HIBPExp    = $hibp
    })
}

# ── Summary ───────────────────────────────────────────────────
$total        = $personas.Count
$atRiskCount  = $tierCount["CRITICAL"] + $tierCount["HIGH"]
$posture      = if ($tierCount["CRITICAL"] -gt 0) { "AT RISK" }
                elseif ($tierCount["HIGH"] -gt 10)  { "AT RISK" }
                elseif ($tierCount["HIGH"] -gt 0)    { "PARTIAL" }
                else                                  { "COMPLIANT" }

$postureColour = switch ($posture) { "AT RISK" { "Red" } "PARTIAL" { "Yellow" } default { "Green" } }

Write-Host "`n=================================================" -ForegroundColor Cyan
Write-Host "THREAT AUDIT SUMMARY"                             -ForegroundColor Cyan
Write-Host "  Total users   : $total"                        -ForegroundColor White
Write-Host "  CRITICAL       : $($tierCount['CRITICAL'])"    -ForegroundColor Red
Write-Host "  HIGH           : $($tierCount['HIGH'])"        -ForegroundColor Yellow
Write-Host "  MEDIUM         : $($tierCount['MEDIUM'])"      -ForegroundColor DarkYellow
Write-Host "  LOW            : $($tierCount['LOW'])"         -ForegroundColor Green
Write-Host "  HIBP Exposed   : $($hibpExposed.Count)"        -ForegroundColor $(if ($hibpExposed.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  MFA Gaps       : $($mfaMissing.Count + ($personas | Where-Object { $_.MFARegistered -eq 'False' }).Count | Sort-Object -Unique | Measure-Object -Sum | Select-Object -ExpandProperty Sum)" -ForegroundColor $(if ($mfaMissing.Count -gt 0) { "Red" } else { "Green" })
Write-Host "`n  Zero-Trust Posture: $posture"                -ForegroundColor $postureColour
Write-Host "=================================================" -ForegroundColor Cyan

# ── Export ────────────────────────────────────────────────────
$noMFATotal   = ($personas | Where-Object { $_.MFARegistered -eq "False" }).Count
$noDevTotal   = ($personas | Where-Object { $_.DeviceCompliant -eq "False" }).Count

$export = @{
    AuditDate  = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Tenant     = "micrlabs.onmicrosoft.com"
    UserRisks  = $userRisks
    Summary    = @{
        TotalUsers    = $total
        Critical      = $tierCount["CRITICAL"]
        High          = $tierCount["HIGH"]
        Medium        = $tierCount["MEDIUM"]
        Low           = $tierCount["LOW"]
        HIBPExposed   = $hibpExposed.Count
        MFAGaps       = $noMFATotal
        DeviceGaps    = $noDevTotal
        Posture       = $posture
    }
}

$export | ConvertTo-Json -Depth 6 | Out-File $ExportPath -Encoding utf8
Write-Host "Audit exported: $ExportPath" -ForegroundColor Cyan
Write-Host "Run dashboard\generate_central_dashboard.py to update the UI.`n" -ForegroundColor Cyan
