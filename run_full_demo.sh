#!/bin/bash
# MediZuva Zero-Trust Framework — Complete Automation Demo
# Run the entire automation flow in sequence

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Functions
print_header() {
    echo -e "\n${MAGENTA}$(printf '═%.0s' {1..70})${NC}"
    echo -e "${MAGENTA} $1${NC}"
    echo -e "${MAGENTA}$(printf '═%.0s' {1..70})${NC}\n"
}

print_status() {
    local status=$1
    local message=$2
    case $status in
        "success") echo -e "${GREEN}✅ $message${NC}" ;;
        "error")   echo -e "${RED}❌ $message${NC}" ;;
        "warning") echo -e "${YELLOW}⚠️  $message${NC}" ;;
        "info")    echo -e "${CYAN}ℹ️  $message${NC}" ;;
    esac
}

run_script() {
    local script=$1
    local description=$2
    local phase=$3

    print_header "Phase $phase : $description"

    if [ ! -f "$script" ]; then
        print_status "error" "Script not found: $script"
        return 1
    fi

    print_status "info" "Running: python $script"

    if python "$script"; then
        print_status "success" "Phase $phase completed successfully"
        return 0
    else
        print_status "error" "Phase $phase failed"
        return 1
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# STARTUP
# ─────────────────────────────────────────────────────────────────────────────

echo -e "\n${MAGENTA}$(printf '█%.0s' {1..70})${NC}"
echo -e "${MAGENTA}█   MediZuva Zero-Trust Framework — Complete Automation Demo   █${NC}"
echo -e "${MAGENTA}$(printf '█%.0s' {1..70})${NC}\n"

# Verify prerequisites
print_header "Prerequisites Check"

# Python version
if command -v python3 &> /dev/null; then
    python_version=$(python3 --version 2>&1 || echo "unknown")
    print_status "success" "Python version: $python_version"
    python_cmd="python3"
else
    python_version=$(python --version 2>&1 || echo "not found")
    print_status "error" "Python 3.11+ required"
    exit 1
fi

# .env file
if [ -f ".env" ]; then
    if grep -q "ENTRA_TENANT_ID\|ENTRA_CLIENT_ID\|ENTRA_CLIENT_SECRET" .env; then
        print_status "success" ".env file found with credentials"
    else
        print_status "error" ".env file found but missing credentials"
        exit 1
    fi
else
    print_status "error" ".env file not found"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1: VERIFY CONNECTIVITY
# ─────────────────────────────────────────────────────────────────────────────

print_header "Phase 1 : Verify Entra ID Authentication & Connectivity"

$python_cmd test_entra_auth.py || exit 1
$python_cmd test_graph_endpoints.py || exit 1
$python_cmd test_risky_users.py || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2: COMPREHENSIVE DATA COLLECTION (PRIMARY)
# ─────────────────────────────────────────────────────────────────────────────

run_script "shared/entra_comprehensive.py" \
    "Comprehensive Entra ID Data Collection (PRIMARY)" 2 || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3: SUPPLEMENTARY DATA ENRICHMENT
# ─────────────────────────────────────────────────────────────────────────────

print_header "Phase 3 : Supplementary Data Collection"

print_status "info" "Collecting risky users, MFA gaps, device compliance gaps..."
$python_cmd shared/entra_sync.py

print_status "info" "Auditing Conditional Access policies..."
$python_cmd shared/entra_ca.py

print_status "info" "Auditing PIM role assignments..."
$python_cmd shared/entra_pim.py

print_status "info" "Retrieving sign-in logs..."
$python_cmd shared/entra_logs.py

print_status "success" "Phase 3 completed successfully"

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4: IDENTITY PROVISIONING
# ─────────────────────────────────────────────────────────────────────────────

run_script "pillar1_identity/generate_personas.py" "Identity Provisioning" 4 || exit 1
run_script "pillar1_identity/validate_provisioning.py" "Validate Provisioning" 4 || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5: THREAT INTELLIGENCE
# ─────────────────────────────────────────────────────────────────────────────

run_script "pillar4_threat/threat_audit.py" "Threat Classification & Risk Tiers" 5 || exit 1
run_script "pillar4_threat/osint_exposure_check.py" "OSINT Breach Intelligence" 5 || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6: COMPLIANCE AUDIT
# ─────────────────────────────────────────────────────────────────────────────

run_script "shared/nist_compliance.py" \
    "NIST Compliance Audit (800-53, 800-207, 800-171, 800-137)" 6 || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7: DASHBOARD GENERATION
# ─────────────────────────────────────────────────────────────────────────────

run_script "dashboard/generate_central_dashboard.py" "Central Dashboard Generation" 7 || exit 1

# ─────────────────────────────────────────────────────────────────────────────
# VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────

print_header "Final Verification"

all_exists=true

# Check critical files
if [ -f "data/entra_comprehensive.json" ]; then
    size=$(du -h "data/entra_comprehensive.json" | cut -f1)
    print_status "success" "data/entra_comprehensive.json ($size)"
else
    print_status "error" "data/entra_comprehensive.json - NOT FOUND"
    all_exists=false
fi

if [ -f "data/central_dashboard.html" ]; then
    size=$(du -h "data/central_dashboard.html" | cut -f1)
    print_status "success" "data/central_dashboard.html ($size)"
else
    print_status "error" "data/central_dashboard.html - NOT FOUND"
    all_exists=false
fi

if [ "$all_exists" = true ]; then
    print_status "success" "All data files generated successfully"

    # Check dashboard contains data
    if grep -q "Total Users\|Risky Users\|Risk Tiers\|NIST" data/central_dashboard.html; then
        print_status "success" "Dashboard contains embedded data"
    else
        print_status "warning" "Dashboard may be missing data"
    fi
else
    print_status "error" "Some data files were not generated"
    exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${MAGENTA}$(printf '═%.0s' {1..70})${NC}"
echo -e "${GREEN}AUTOMATION COMPLETE${NC}"
echo -e "${MAGENTA}$(printf '═%.0s' {1..70})${NC}"

cat << 'EOF'

📊 Next Steps:

  1. VIEW DASHBOARD:
     open data/central_dashboard.html    (macOS)
     xdg-open data/central_dashboard.html (Linux)
     Browser: Open data/central_dashboard.html

  2. LOCAL WEB SERVER (optional):
     cd data
     python3 -m http.server 8080
     Visit: http://localhost:8080/central_dashboard.html

  3. DEPLOY TO GITHUB:
     cp data/central_dashboard.html docs/index.html
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

EOF

echo -e "\nFor complete documentation, see: AUTOMATION_RUNBOOK.md\n"
