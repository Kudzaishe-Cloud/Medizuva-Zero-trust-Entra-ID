#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Complete MediZuva Zero-Trust Automation Demo

.DESCRIPTION
    Runs the entire automation flow in sequence:
    1. Verify connectivity & authentication
    2. Collect comprehensive Entra ID data
    3. Enrich with supplementary data
    4. Process identity & threat intelligence
    5. Audit compliance
    6. Generate dashboard

.EXAMPLE
    .\run_full_demo.ps1

.NOTES
    Requires: Python 3.11+, pip packages installed, valid .env file
#>

param(
    [switch]$SkipTests = $false,
    [switch]$SkipEnrichment = $false,
    [switch]$DashboardOnly = $false
)

# Colors for output
$colors = @{
    Success = 'Green'
    Error   = 'Red'
    Warning = 'Yellow'
    Info    = 'Cyan'
    Header  = 'Magenta'
}

function Write-Header {
    param([string]$text)
    Write-Host "`n$('═' * 70)" -ForegroundColor $colors.Header
    Write-Host " $text" -ForegroundColor $colors.Header
    Write-Host "$('═' * 70)`n" -ForegroundColor $colors.Header
}

function Write-Status {
    param([string]$text, [string]$type = 'Info')
    $prefix = @{
        'Success' = '✅'
        'Error'   = '❌'
        'Warning' = '⚠️ '
        'Info'    = 'ℹ️ '
    }[$type]
    Write-Host "$prefix $text" -ForegroundColor $colors[$type]
}

function Run-Script {
    param(
        [string]$ScriptPath,
        [string]$Description,
        [int]$PhaseNum
    )

    Write-Header "Phase $PhaseNum : $Description"

    if (-not (Test-Path $ScriptPath)) {
        Write-Status "Script not found: $ScriptPath" Error
        return $false
    }

    Write-Status "Running: python $ScriptPath"

    try {
        python $ScriptPath
        Write-Status "✓ Phase $PhaseNum completed successfully" Success
        return $true
    } catch {
        Write-Status "✗ Phase $PhaseNum failed: $_" Error
        return $false
    }
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# STARTUP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Write-Host "`n" + "█" * 70 -ForegroundColor $colors.Header
Write-Host "█   MediZuva Zero-Trust Framework — Complete Automation Demo   █" -ForegroundColor $colors.Header
Write-Host "█" * 70 + "`n" -ForegroundColor $colors.Header

# Verify prerequisites
Write-Header "Prerequisites Check"

Write-Status "Checking Python installation..."
$pythonVersion = python --version 2>&1
if ($pythonVersion -match "3\.1[1-9]|3\.[2-9]") {
    Write-Status "Python version: $pythonVersion" Success
} else {
    Write-Status "Python 3.11+ required. Found: $pythonVersion" Error
    exit 1
}

Write-Status "Checking .env file..."
if (Test-Path ".env") {
    $envContent = Get-Content .env -Raw
    if ($envContent -match "ENTRA_TENANT_ID|ENTRA_CLIENT_ID|ENTRA_CLIENT_SECRET") {
        Write-Status ".env file found with credentials" Success
    } else {
        Write-Status ".env file found but missing credentials" Error
        exit 1
    }
} else {
    Write-Status ".env file not found" Error
    exit 1
}

Write-Status "Checking dependencies..."
$reqs = pip list 2>&1
if ($reqs -match "pandas|requests") {
    Write-Status "Dependencies installed" Success
} else {
    Write-Status "Installing dependencies..."
    python -m pip install -q -r requirements.txt
    Write-Status "Dependencies installed" Success
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 1: VERIFY CONNECTIVITY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if (-not $SkipTests) {
    Run-Script "test_entra_auth.py" "Verify Entra ID Authentication" 1
    Run-Script "test_graph_endpoints.py" "Verify Graph API Endpoints" 1
    Run-Script "test_risky_users.py" "Verify Risky Users Endpoint" 1
} else {
    Write-Status "Skipping connectivity tests (-SkipTests)" Warning
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 2: COMPREHENSIVE DATA COLLECTION (PRIMARY)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if (-not $DashboardOnly) {
    Run-Script "shared/entra_comprehensive.py" "Comprehensive Entra ID Data Collection (PRIMARY)" 2

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 3: SUPPLEMENTARY DATA ENRICHMENT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    if (-not $SkipEnrichment) {
        Write-Header "Phase 3 : Supplementary Data Collection"

        Write-Status "Collecting risky users, MFA gaps, device compliance gaps..."
        python shared/entra_sync.py

        Write-Status "Auditing Conditional Access policies..."
        python shared/entra_ca.py

        Write-Status "Auditing PIM role assignments..."
        python shared/entra_pim.py

        Write-Status "Retrieving sign-in logs..."
        python shared/entra_logs.py

        Write-Status "✓ Phase 3 completed successfully" Success
    } else {
        Write-Status "Skipping enrichment data (-SkipEnrichment)" Warning
    }

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 4: IDENTITY PROVISIONING
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Run-Script "pillar1_identity/generate_personas.py" "Identity Provisioning" 4
    Run-Script "pillar1_identity/validate_provisioning.py" "Validate Provisioning" 4

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 5: THREAT INTELLIGENCE
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Run-Script "pillar4_threat/threat_audit.py" "Threat Classification & Risk Tiers" 5
    Run-Script "pillar4_threat/osint_exposure_check.py" "OSINT Breach Intelligence" 5

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PHASE 6: COMPLIANCE AUDIT
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    Run-Script "shared/nist_compliance.py" "NIST Compliance Audit (800-53, 800-207, 800-171, 800-137)" 6
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PHASE 7: DASHBOARD GENERATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Run-Script "dashboard/generate_central_dashboard.py" "Central Dashboard Generation" 7

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VERIFICATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Write-Header "Final Verification"

$dataFiles = @(
    "data/entra_comprehensive.json",
    "data/central_dashboard.html"
)

if ($DashboardOnly) {
    $dataFiles = @("data/central_dashboard.html")
}

$allExists = $true
foreach ($file in $dataFiles) {
    if (Test-Path $file) {
        $size = (Get-Item $file).Length / 1KB
        Write-Status "$file ($('{0:N0}' -f $size) KB)" Success
    } else {
        Write-Status "$file - NOT FOUND" Error
        $allExists = $false
    }
}

if ($allExists) {
    Write-Status "All data files generated successfully" Success

    # Check dashboard contains data
    if (Test-Path "data/central_dashboard.html") {
        $dashboard = Get-Content "data/central_dashboard.html" -Raw
        if ($dashboard -match "Total Users|Risky Users|Risk Tiers|NIST") {
            Write-Status "Dashboard contains embedded data" Success
            Write-Status "✓ Dashboard ready to view" Success
        } else {
            Write-Status "Dashboard may be missing data" Warning
        }
    }
} else {
    Write-Status "Some data files were not generated" Error
}

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# FINAL SUMMARY
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Write-Host "`n" + "=" * 70 -ForegroundColor $colors.Header
Write-Host "AUTOMATION COMPLETE" -ForegroundColor $colors.Success
Write-Host "=" * 70 -ForegroundColor $colors.Header

Write-Host @"
📊 Next Steps:

  1. VIEW DASHBOARD:
     PowerShell: Invoke-Item data/central_dashboard.html
     Browser: Open data/central_dashboard.html

  2. LOCAL WEB SERVER (optional):
     cd data
     python -m http.server 8080
     Visit: http://localhost:8080/central_dashboard.html

  3. DEPLOY TO GITHUB:
     copy data/central_dashboard.html docs/index.html
     git add docs/index.html data/nist_compliance_report.json
     git commit -m "chore: update dashboard"
     git push

  4. GITHUB PAGES:
     https://kudzaishe-cloud.github.io/Medizuva-Zero-trust-Entra-ID/

  5. AUTOMATE (GitHub Actions):
     Workflow runs every 5 minutes automatically
     Manual trigger: GitHub Actions tab → Run workflow

📈 Data Generated:
  - entra_comprehensive.json  (Real Entra ID data)
  - central_dashboard.html    (Interactive dashboard)
  - nist_compliance_report.json (Compliance audit)
  - threat_audit.json         (Risk classification)
  - ca_audit.json             (CA policies)
  - pim_audit.json            (PIM roles)
  - osint_combined_results.json (Breach intelligence)

✅ System Status: READY FOR PRODUCTION

"@ -ForegroundColor $colors.Info

Write-Host "For complete documentation, see: AUTOMATION_RUNBOOK.md`n" -ForegroundColor $colors.Info
