# MediZuva Zero-Trust Framework — Quick Start Guide

**Run the complete system automation in ONE command**

---

## 🚀 Start Here

### Windows (PowerShell)
```powershell
.\run_full_demo.ps1
```

### Windows (Command Prompt)
```cmd
run_full_demo.bat
```

### Linux / macOS (Bash)
```bash
chmod +x run_full_demo.sh
./run_full_demo.sh
```

---

## ✅ What Gets Executed

The demo script runs all 7 phases in sequence:

| Phase | Script | What It Does |
|-------|--------|-------------|
| **1** | `test_entra_auth.py` | Verify Entra ID authentication |
| **1** | `test_graph_endpoints.py` | Test Graph API endpoints |
| **1** | `test_risky_users.py` | Verify risky users endpoint |
| **2** | `shared/entra_comprehensive.py` | ⭐ **PRIMARY** — Fetch ALL Entra ID data |
| **3** | `shared/entra_sync.py` | Risky users, MFA gaps, device compliance |
| **3** | `shared/entra_ca.py` | Conditional Access policy audit |
| **3** | `shared/entra_pim.py` | PIM role assignments audit |
| **3** | `shared/entra_logs.py` | Sign-in log retrieval |
| **4** | `pillar1_identity/generate_personas.py` | Generate user personas |
| **4** | `pillar1_identity/validate_provisioning.py` | Validate provisioning |
| **5** | `pillar4_threat/threat_audit.py` | Classify users into risk tiers |
| **5** | `pillar4_threat/osint_exposure_check.py` | Breach intelligence |
| **6** | `shared/nist_compliance.py` | NIST 800-53, 800-207, 800-171, 800-137 audit |
| **7** | `dashboard/generate_central_dashboard.py` | 📊 **Generate interactive dashboard** |

---

## 📊 Output Files Created

After running the demo, you'll have:

```
data/
├── entra_comprehensive.json          ← PRIMARY data source (8 categories)
├── central_dashboard.html            ← OPEN THIS IN BROWSER
├── nist_compliance_report.json       ← Compliance audit results
├── threat_audit.json                 ← User risk classification
├── ca_audit.json                     ← Conditional Access policies
├── pim_audit.json                    ← PIM role assignments
├── risky_users.json                  ← Risky users detail
└── osint_results/
    ├── osint_combined_results.json   ← Breach exposure data
    └── osint_run.log                 ← OSINT execution log

data/personas/
├── medizuva_500_personas.csv         ← User personas
└── provisioning_log.csv              ← Provisioning status

docs/
└── index.html                        ← GitHub Pages (after push)
```

---

## 🌐 View the Dashboard

### Locally (Immediate)
```powershell
# Windows PowerShell
Invoke-Item data/central_dashboard.html

# Windows CMD
start data/central_dashboard.html

# macOS
open data/central_dashboard.html

# Linux
xdg-open data/central_dashboard.html
```

### Local Web Server
```bash
cd data
python -m http.server 8080
# Visit: http://localhost:8080/central_dashboard.html
```

### GitHub Pages (After Push)
```bash
cp data/central_dashboard.html docs/index.html
git add docs/index.html
git commit -m "chore: update dashboard"
git push

# Visit: https://kudzaishe-cloud.github.io/Medizuva-Zero-trust-Entra-ID/
```

---

## 📋 Prerequisites Checklist

Before running the demo:

- ✅ Python 3.11+ installed
- ✅ `.env` file exists with credentials:
  - `ENTRA_TENANT_ID=<your-tenant-id>`
  - `ENTRA_CLIENT_ID=<your-client-id>`
  - `ENTRA_CLIENT_SECRET=<your-client-secret>`
- ✅ Dependencies installed: `pip install -r requirements.txt`
- ✅ Network access to `graph.microsoft.com`

---

## 🎯 Complete Documentation

For detailed information about each script and phase, see:

📖 **[AUTOMATION_RUNBOOK.md](AUTOMATION_RUNBOOK.md)**

- Detailed explanation of each phase
- Individual script descriptions
- Data flow diagram
- Troubleshooting guide
- Success criteria checklist

---

## ⏱️ Execution Time

- **Connectivity Tests:** ~10 seconds
- **Comprehensive Data Collection:** ~1-2 minutes
- **Supplementary Data (Enrichment):** ~30 seconds
- **Identity Processing:** ~20 seconds
- **Threat Intelligence:** ~30 seconds
- **Compliance Audit:** ~20 seconds
- **Dashboard Generation:** ~10 seconds

**Total: ~3-5 minutes** (depending on data volume and API latency)

---

## 🔄 Automated Execution

The system also runs automatically via GitHub Actions:

- **Frequency:** Every 5 minutes
- **Trigger:** Manual from Actions tab
- **Output:** Automatic GitHub Pages deployment

To manually trigger:
1. Go to: `https://github.com/Kudzaishe-Cloud/Medizuva-Zero-trust-Entra-ID`
2. Click **Actions** tab
3. Select workflow: **"Sync Dashboard (5-min Real-Time + Accuracy Verification)"**
4. Click **Run workflow**

---

## 💡 System Architecture

```
┌─────────────────────────┐
│  Microsoft Entra ID     │
│  (Microsoft Graph API)  │
└────────────┬────────────┘
             │
      ┌──────▼──────┐
      │ Authenticate│
      │  (OAuth2)   │
      └──────┬──────┘
             │
      ┌──────▼────────────────────────────┐
      │ Comprehensive Data Collection    │ ⭐ Primary
      │ - Users (537)                     │
      │ - Risky Users (1+)                │
      │ - Sign-In Logs (999+)             │
      │ - CA Policies (6+)                │
      │ - PIM Roles (12+)                 │
      │ - Devices (234+)                  │
      │ - Directory Roles (8+)            │
      └──────┬────────────────────────────┘
             │
      ┌──────▼──────────────────────────────┐
      │ Enrichment & Analysis              │
      │ - Threat Classification            │
      │ - OSINT Exposure Check             │
      │ - NIST Compliance Audit            │
      │ - CA Policy Enforcement Check      │
      │ - PIM Eligibility Analysis         │
      └──────┬──────────────────────────────┘
             │
      ┌──────▼──────────────────────┐
      │ Dashboard Generation        │
      │ - Embed all data inline     │
      │ - Interactive HTML          │
      │ - Single-file deployment    │
      └──────┬──────────────────────┘
             │
      ┌──────▼──────────────────────┐
      │ GitHub Pages                │
      │ (Auto-publish via workflow) │
      └─────────────────────────────┘
```

---

## 🆘 Troubleshooting

| Problem | Solution |
|---------|----------|
| **"CRITICAL Failed to authenticate"** | Check .env credentials; verify GitHub Secrets if using Actions |
| **"Script not found"** | Ensure you're in the repo root directory |
| **Dashboard shows old data** | Run the demo again or wait for next workflow run (5 min) |
| **"0 risky users" mismatch** | Already fixed — comprehensive collection has no filters |
| **Permission denied (Bash)** | Run: `chmod +x run_full_demo.sh` first |

---

## 📞 Support

- **Full Documentation:** See `AUTOMATION_RUNBOOK.md`
- **Individual Scripts:** See inline comments in each `*.py` file
- **GitHub Issues:** Report bugs at your repository issues page

---

**Status:** ✅ **PRODUCTION READY**

**Last Updated:** 2026-05-03

**Framework Version:** MediZuva ZT v1.0
