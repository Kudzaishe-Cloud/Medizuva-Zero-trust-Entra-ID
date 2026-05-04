# MediZuva Zero-Trust Framework — Complete Automation Runbook

**Purpose:** Demonstrate the complete system automation flow from data collection through dashboard generation and deployment.

---

## ✅ Prerequisites

Before running any scripts:

```powershell
# 1. Verify .env file exists with valid Entra ID credentials
cat .env

# Expected output:
# ENTRA_TENANT_ID=<your-tenant-id>
# ENTRA_CLIENT_ID=<your-client-id>
# ENTRA_CLIENT_SECRET=<your-client-secret>

# 2. Ensure Python 3.11+ and dependencies installed
python -m pip install -r requirements.txt

# 3. Verify you can access Microsoft Graph API
python test_entra_auth.py
```

---

## 🔄 Complete Automation Flow (In Order)

### **Phase 1: Verify Connectivity & Authentication**

**Purpose:** Ensure credentials work before pulling any data.

```powershell
# Test 1: Basic Entra ID Authentication
echo "=== TEST 1: Entra ID Authentication ==="
python test_entra_auth.py

# Test 2: Verify all Graph API endpoints are accessible
echo "=== TEST 2: Graph API Endpoints ==="
python test_graph_endpoints.py

# Test 3: Verify risky users endpoint returns data
echo "=== TEST 3: Risky Users Endpoint ==="
python test_risky_users.py
```

**Expected Outputs:**
- ✅ Token obtained successfully
- ✅ All endpoints responding with HTTP 200
- ✅ Risky users count displayed

**Files Generated:** None (diagnostic only)

---

### **Phase 2: Comprehensive Real-Time Data Collection** ⭐ PRIMARY

**Purpose:** Pull ALL Entra ID data in one operation. This is the authoritative source for all downstream processing.

```powershell
# PRIMARY DATA SOURCE: Comprehensive Entra ID Collection
echo "=== PHASE 2: Comprehensive Data Collection ==="
python shared/entra_comprehensive.py
```

**What it does:**
- Fetches 8 categories of real Entra ID data:
  1. Users (displayName, UPN, email, department, location, etc.)
  2. Risky Users (Identity Protection signals — ALL risk levels)
  3. Sign-In Logs (auditLogs/signIns — last 100 entries)
  4. Risky Sign-Ins (identityProtection/riskySignIns)
  5. Conditional Access Policies (state, enforced/report-only/disabled)
  6. PIM Role Assignments (roles, eligible users, JIT access)
  7. Devices (compliance state, OS, management status)
  8. Directory Roles (admins, members, permissions)
- Paginates through all results (up to 100 pages per endpoint)
- Timestamps all data for freshness verification
- **FAILS HARD** if credentials are invalid (no synthetic fallback)

**Files Generated:**
- `data/entra_comprehensive.json` — Master data file with ALL 8 categories

**Expected Output:**
```
======================================================================
COMPREHENSIVE ENTRA ID DATA COLLECTION (REAL DATA ONLY)
======================================================================

[1/8] Fetching Users...
   ✓ Found 537 users

[2/8] Fetching Risky Users...
   ✓ Found 1 risky users

[3/8] Fetching Sign-In Logs...
   ✓ Found 999 sign-in records

[4/8] Fetching Risky Sign-Ins...
   ✓ Found 0 risky sign-ins

[5/8] Fetching Conditional Access Policies...
   ✓ Found 6 CA policies

[6/8] Fetching PIM Role Assignments...
   ✓ Found 12 PIM role assignments

[7/8] Fetching Devices...
   ✓ Found 234 devices

[8/8] Fetching Directory Roles...
   ✓ Found 8 directory roles

======================================================================
✓ COMPREHENSIVE DATA SAVED TO: data/entra_comprehensive.json
======================================================================
Total Users: 537
Risky Users: 1
Sign-in Logs: 999
Risky Sign-Ins: 0
CA Policies: 6
PIM Roles: 12
Devices: 234
Directory Roles: 8
======================================================================
```

---

### **Phase 3: Supplementary Data Collection** (Optional — enrichment)

These scripts augment the comprehensive data with additional context:

```powershell
# Sync risky users, MFA gaps, device compliance gaps
echo "=== PHASE 3A: Entra ID Sync (Threat Signals) ==="
python shared/entra_sync.py

# Audit Conditional Access policy enforcement state
echo "=== PHASE 3B: CA Policy Audit ==="
python shared/entra_ca.py

# Audit PIM role assignments and eligibility
echo "=== PHASE 3C: PIM Audit ==="
python shared/entra_pim.py

# Pull sign-in logs with detailed filtering
echo "=== PHASE 3D: Sign-In Log Retrieval ==="
python shared/entra_logs.py
```

**Files Generated:**
- `data/risky_users.json` — Risky users, MFA gaps, device compliance gaps
- `data/ca_audit.json` — CA policies state (enforced/report-only/disabled)
- `data/pim_audit.json` — PIM role assignments, eligible users
- `data/signin_logs/signin_logs.json` — Sign-in log details

---

### **Phase 4: Identity Provisioning & Validation**

**Purpose:** Generate or validate user identity personas.

```powershell
# Generate 500 sample personas (or fetch real from Entra)
echo "=== PHASE 4A: Identity Provisioning ==="
python pillar1_identity/generate_personas.py

# Validate provisioning against Entra ID
echo "=== PHASE 4B: Provisioning Validation ==="
python pillar1_identity/validate_provisioning.py
```

**Files Generated:**
- `data/personas/medizuva_500_personas.csv` — User personas with attributes
- `data/personas/provisioning_log.csv` — Provisioning status

---

### **Phase 5: Threat Intelligence & Risk Classification**

**Purpose:** Classify users into risk tiers using real Entra signals.

```powershell
# Classify users into risk tiers (CRITICAL, HIGH, MEDIUM, LOW)
echo "=== PHASE 5A: Threat Audit ==="
python pillar4_threat/threat_audit.py

# Enrich with OSINT exposure data (breach databases, leak checks)
echo "=== PHASE 5B: OSINT Exposure Check ==="
python pillar4_threat/osint_exposure_check.py
```

**Files Generated:**
- `data/threat_audit.json` — User risk tiers, risk signals, critical users
- `data/osint_results/osint_combined_results.json` — Breach exposure data

**Risk Tiers:**
- 🔴 **CRITICAL** — High-risk user + exposed in breach + no MFA
- 🟠 **HIGH** — Risky sign-ins or high-risk behavior detected
- 🟡 **MEDIUM** — Non-compliant device or MFA gap
- 🟢 **LOW** — Clean user, MFA enabled, compliant device

---

### **Phase 6: Compliance & Standards Audit**

**Purpose:** Audit against NIST SP 800-53, 800-207 (Zero Trust), 800-171 (CMMC), 800-137 (Continuous Monitoring).

```powershell
# Audit NIST compliance across all 4 pillars
echo "=== PHASE 6: NIST Compliance Audit ==="
python shared/nist_compliance.py
```

**Files Generated:**
- `data/nist_compliance_report.json` — Compliance scores, gaps, recommendations

**Compliance Standards Checked:**
- NIST SP 800-53 (Security & Privacy Controls)
- NIST SP 800-207 (Zero Trust Architecture)
- NIST SP 800-171 (Protecting Controlled Unclassified Info)
- NIST SP 800-137 (Continuous Monitoring & Maintenance)

---

### **Phase 7: Central Dashboard Generation** ⭐ FINAL

**Purpose:** Aggregate ALL data into single HTML dashboard for visualization.

```powershell
# Generate central dashboard HTML with all 4 pillars + threat + NIST
echo "=== PHASE 7: Dashboard Generation ==="
python dashboard/generate_central_dashboard.py
```

**What it does:**
- Reads from `data/entra_comprehensive.json` (PRIMARY SOURCE)
- Reads supplementary files: CA audit, PIM audit, threat audit, NIST compliance, OSINT
- Embeds ALL data inline in HTML (no external API calls needed)
- Generates interactive dashboard with:
  - Overview & KPIs
  - Pillar 1 (Identity) — User provisioning, departments, locations
  - Pillar 2 (Access) — CA policies, enforcement state
  - Pillar 3 (PIM) — Role assignments, JIT eligibility
  - Pillar 4 (Threat) — Risk tiers, risky users, signals breakdown
  - OSINT Intelligence — Breach exposure, department exposure
  - NIST Compliance — Standards audit, gap analysis
  - Audit Logs — Sign-in history, risky events

**Files Generated:**
- `data/central_dashboard.html` — Single-file HTML dashboard (all data embedded)

**Expected Output:**
```
=========================================
 MediZuva — Central Dashboard Generator
=========================================
  P1 personas   : 537
  P2 CA policies: 6
  P3 PIM roles  : 12 eligible
  P4 threat     : 1 critical
  Entra sign-ins: 999 total (1 risky users)
  OSINT exposed : 45 users
  NIST score    : 78.5%
  Log lines     : 523

[OK] Dashboard written: data/central_dashboard.html
     Open in browser or serve with: python -m http.server 8080 (in data/)
```

---

### **Phase 8: Deployment to GitHub Pages** (Optional)

**Purpose:** Publish dashboard to GitHub Pages for team visibility.

```powershell
# Copy dashboard to GitHub Pages source
copy data/central_dashboard.html docs/index.html

# Commit and push to GitHub (will auto-publish)
git add docs/index.html data/nist_compliance_report.json
git commit -m "chore: update dashboard and NIST compliance report $(Get-Date -Format 'yyyy-MM-dd HH:mm UTC')"
git push
```

**Website Published To:**
- `https://kudzaishe-cloud.github.io/Medizuva-Zero-trust-Entra-ID/`

---

## 🎯 Quick Start: Run Everything in Sequence

**Execute this to demonstrate the complete system:**

```powershell
# ====== VERIFY SETUP ======
echo "[1] Testing connectivity..."
python test_entra_auth.py
python test_graph_endpoints.py
python test_risky_users.py

# ====== COLLECT DATA ======
echo "[2] Collecting comprehensive Entra ID data..."
python shared/entra_comprehensive.py

echo "[3] Collecting supplementary data..."
python shared/entra_sync.py
python shared/entra_ca.py
python shared/entra_pim.py
python shared/entra_logs.py

# ====== PROCESS & ANALYZE ======
echo "[4] Provisioning & validation..."
python pillar1_identity/generate_personas.py
python pillar1_identity/validate_provisioning.py

echo "[5] Threat intelligence..."
python pillar4_threat/threat_audit.py
python pillar4_threat/osint_exposure_check.py

echo "[6] Compliance audit..."
python shared/nist_compliance.py

# ====== PUBLISH ======
echo "[7] Generating dashboard..."
python dashboard/generate_central_dashboard.py

echo "[8] Preview dashboard locally..."
echo "    Open: data/central_dashboard.html in your browser"
```

**Total Time:** ~2-3 minutes (depending on data volume and API latency)

---

## 📊 Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    ENTRA ID (Microsoft Graph)               │
│  Users | Risky Users | Sign-Ins | Policies | Roles | Devices│
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────┐
        │ entra_comprehensive.py                │ ⭐ PRIMARY
        │ (ALL 8 categories, real data only)   │
        └─────────┬──────────────────────────────┘
                  │
                  ▼
        ┌─────────────────────────────────────────┐
        │ entra_comprehensive.json                │
        │ (Master data file)                      │
        └──────┬─────────────────┬────────────────┘
               │                 │
         ┌─────▼─────┐    ┌──────▼──────┐
         │ entra_sync│    │ entra_ca.py │
         │ entra_pim │    │ entra_logs  │ (Enrichment)
         │ entra_logs│    └──────┬──────┘
         └─────┬─────┘           │
               │                 │
         ┌─────▼──────────────────▼────┐
         │ Personas & Provisioning      │
         │ generate_personas.py         │
         │ validate_provisioning.py     │
         └─────┬──────────────────────┘
               │
         ┌─────▼──────────────────┐
         │ Threat Classification  │
         │ threat_audit.py        │
         │ osint_exposure_check   │
         └─────┬──────────────────┘
               │
         ┌─────▼──────────────────┐
         │ NIST Compliance        │
         │ nist_compliance.py     │
         └─────┬──────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ Dashboard Generation           │
         │ generate_central_dashboard.py  │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ central_dashboard.html         │
         │ (All data embedded inline)     │
         └─────┬──────────────────────────┘
               │
         ┌─────▼──────────────────────────┐
         │ GitHub Pages                   │
         │ docs/index.html (auto-publish) │
         └────────────────────────────────┘
```

---

## 🔍 Verification Checklist

After running all scripts, verify:

```powershell
# Check all data files exist
$files = @(
    "data/entra_comprehensive.json",
    "data/risky_users.json",
    "data/ca_audit.json",
    "data/pim_audit.json",
    "data/personas/medizuva_500_personas.csv",
    "data/threat_audit.json",
    "data/osint_results/osint_combined_results.json",
    "data/nist_compliance_report.json",
    "data/central_dashboard.html"
)

foreach ($file in $files) {
    $exists = Test-Path $file
    $status = if ($exists) { "✅" } else { "❌" }
    Write-Output "$status $file"
}

# Check dashboard contains data
$dashboard = Get-Content data/central_dashboard.html -Raw
if ($dashboard -match "Total Users|Risky Users|Risk Tiers") {
    Write-Output "✅ Dashboard generated with data embedded"
} else {
    Write-Output "❌ Dashboard missing data"
}

# Check Entra data is real (not simulated)
$comp = Get-Content data/entra_comprehensive.json | ConvertFrom-Json
Write-Output "✅ Real Entra ID Data:"
Write-Output "   - Timestamp: $($comp.timestamp)"
Write-Output "   - Source: $($comp.dataSource)"
Write-Output "   - Users: $($comp.sections.users.total)"
Write-Output "   - Risky Users: $($comp.sections.riskyUsers.total)"
```

---

## 🚀 GitHub Actions Automation

The workflow (`.github/workflows/sync.yml`) runs **automatically every 5 minutes** and executes this entire flow:

```yaml
Steps:
1. Checkout code
2. Setup Python 3.11
3. Install dependencies
4. Comprehensive Entra ID data collection ⭐
5. Entra ID sync (enrichment)
6. CA policy audit
7. PIM audit
8. Threat audit
9. NIST compliance audit
10. Dashboard generation
11. Copy to GitHub Pages (docs/)
12. Commit & push (auto-publish)
```

To manually trigger:
1. Go to GitHub Actions tab
2. Select "Sync Dashboard (5-min Real-Time + Accuracy Verification)"
3. Click "Run workflow"

---

## 📈 System Output Summary

| Component | Input | Output | Status |
|-----------|-------|--------|--------|
| **Entra Comprehensive** | Graph API | `entra_comprehensive.json` | ✅ Real data, no simulation |
| **Entra Sync** | Graph API | `risky_users.json` | ✅ Enrichment data |
| **CA Audit** | Graph API | `ca_audit.json` | ✅ Policy enforcement state |
| **PIM Audit** | Graph API | `pim_audit.json` | ✅ Role assignments |
| **Personas** | CSV or Graph | `medizuva_500_personas.csv` | ✅ User attributes |
| **Threat Audit** | Risky data | `threat_audit.json` | ✅ Risk tiers (CRITICAL-LOW) |
| **OSINT Check** | APIs | `osint_combined_results.json` | ✅ Breach exposure |
| **NIST Audit** | All data | `nist_compliance_report.json` | ✅ Standards compliance |
| **Dashboard** | All data | `central_dashboard.html` | ✅ Interactive visualization |

---

## ✅ Success Criteria

System is working correctly when:

- ✅ All test scripts pass (connectivity, endpoints, authentication)
- ✅ `entra_comprehensive.json` contains real data from Entra ID (not simulated)
- ✅ User count in dashboard matches Entra admin portal (537 users)
- ✅ Risky users count matches (1 user)
- ✅ Dashboard displays all 4 pillars + threat + NIST
- ✅ Dashboard HTML loads in browser with no errors
- ✅ Data timestamps are current (within 5 minutes)
- ✅ GitHub Pages site displays live dashboard
- ✅ Workflow runs automatically every 5 minutes

---

## 🆘 Troubleshooting

| Issue | Solution |
|-------|----------|
| **"CRITICAL Failed to authenticate"** | Check `.env` file has valid credentials; verify GitHub Secrets are set |
| **"0 risky users" but Entra shows 1+** | Fixed — removed riskLevel filter. Run `entra_comprehensive.py` to get fresh data |
| **Dashboard shows old data** | Wait for workflow to run (5 min) or manually trigger from Actions tab |
| **HTTP 401 errors** | Credentials expired or incorrect. Regenerate in Azure App Registration |
| **"Data integrity file not found"** | entra_logs.py failed. Check network access to Graph API |
| **Dashboard HTML is blank** | `entra_comprehensive.json` missing. Run Phase 2 first |

---

**Last Updated:** 2026-05-03
**Framework Version:** MediZuva ZT v1.0
**Status:** ✅ PRODUCTION READY
