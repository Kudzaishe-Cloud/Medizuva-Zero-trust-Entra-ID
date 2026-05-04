# MediZuva Zero-Trust Framework — Complete Scripts Reference

All scripts you can run to explain and demonstrate the complete system automation.

---

## 🚀 ONE-COMMAND AUTOMATION (RUN ONE OF THESE)

**Start here to see everything work end-to-end:**

### Windows
```powershell
# PowerShell
.\run_full_demo.ps1

# Command Prompt
run_full_demo.bat
```

### Linux/macOS
```bash
chmod +x run_full_demo.sh
./run_full_demo.sh
```

**Duration:** 3-5 minutes  
**Output:** Complete dashboard + all data files

---

## 📖 DOCUMENTATION SCRIPTS

Read these FIRST to understand the system:

| File | Purpose |
|------|---------|
| `QUICK_START.md` | One-page quick reference |
| `AUTOMATION_RUNBOOK.md` | Complete 7-phase breakdown |
| `ALL_SCRIPTS.md` | This file — complete reference |

---

## 🔍 PHASE-BY-PHASE SCRIPTS

Run these individually to test each phase:

### PHASE 1: Connectivity Verification
```bash
python test_entra_auth.py          # Test authentication
python test_graph_endpoints.py     # Test Graph API
python test_risky_users.py         # Test risky users endpoint
```

### PHASE 2: Comprehensive Data Collection ⭐ PRIMARY
```bash
python shared/entra_comprehensive.py
# Fetches ALL 8 categories from Entra ID:
# - Users (537)
# - Risky Users (Identity Protection)
# - Sign-In Logs
# - Risky Sign-Ins
# - Conditional Access Policies
# - PIM Role Assignments
# - Devices
# - Directory Roles
# Output: data/entra_comprehensive.json
```

### PHASE 3: Supplementary Data
```bash
python shared/entra_sync.py        # Risky users, MFA gaps, device compliance
python shared/entra_ca.py          # CA policy enforcement
python shared/entra_pim.py         # PIM role assignments
python shared/entra_logs.py        # Sign-in logs
```

### PHASE 4: Identity Provisioning
```bash
python pillar1_identity/generate_personas.py      # Generate personas
python pillar1_identity/validate_provisioning.py  # Validate
python pillar1_identity/fix_domain.py             # Fix domain (optional)
```

### PHASE 5: Threat Intelligence
```bash
python pillar4_threat/threat_audit.py             # Risk classification
python pillar4_threat/osint_exposure_check.py     # Breach intelligence
python pillar4_threat/seed_osint_data.py          # Synthetic data (optional)
```

### PHASE 6: Compliance Audit
```bash
python shared/nist_compliance.py   # NIST 800-53, 800-207, 800-171, 800-137
```

### PHASE 7: Dashboard Generation ⭐ FINAL OUTPUT
```bash
python dashboard/generate_central_dashboard.py    # Main dashboard
python pillar2_access/dashboard/generate_dashboard.py    # Pillar 2 dashboard
python pillar3_pim/dashboard/generate_dashboard.py       # Pillar 3 dashboard
python pillar3_pim/validate_pim.py                       # Validate PIM
```

---

## 📊 DATA FILES GENERATED

After running scripts, you'll have:

```
data/
├── entra_comprehensive.json                    ← Primary data source
├── central_dashboard.html                      ← MAIN DASHBOARD
├── risky_users.json                           ← Risky user details
├── ca_audit.json                              ← CA policies
├── pim_audit.json                             ← PIM roles
├── threat_audit.json                          ← Risk classification
├── nist_compliance_report.json                ← NIST audit
├── signin_logs/
│   ├── signin_logs.json
│   ├── risky_signins.json
│   └── directory_audits.json
└── osint_results/
    ├── osint_combined_results.json            ← Breach data
    └── osint_run.log                          ← OSINT log

data/personas/
├── medizuva_500_personas.csv                  ← User list
└── provisioning_log.csv                       ← Provisioning status

docs/
└── index.html                                 ← GitHub Pages (after push)
```

---

## 🎯 EXAMPLE WORKFLOW

**Complete system demonstration in 4 steps:**

```powershell
# Step 1: Run the complete demo
.\run_full_demo.ps1

# Step 2: View the dashboard (opens automatically)
# Or manually open: data/central_dashboard.html

# Step 3: Deploy to GitHub
copy data/central_dashboard.html docs/index.html
git add docs/index.html
git commit -m "chore: update dashboard"
git push

# Step 4: View on GitHub Pages
# https://kudzaishe-cloud.github.io/Medizuva-Zero-trust-Entra-ID/
```

---

## 🔧 INDIVIDUAL SCRIPT BREAKDOWN

### Test Scripts
- **test_entra_auth.py** — OAuth2 authentication test
- **test_graph_endpoints.py** — Graph API connectivity test  
- **test_risky_users.py** — Risky users endpoint variations test

### Data Collection (Shared)
- **shared/entra_comprehensive.py** — ⭐ PRIMARY: All 8 data categories
- **shared/entra_sync.py** — Risky users, MFA, device compliance
- **shared/entra_ca.py** — Conditional Access policies
- **shared/entra_pim.py** — PIM role assignments
- **shared/entra_logs.py** — Sign-in logs
- **shared/nist_compliance.py** — NIST compliance audit
- **shared/schemas.py** — Data schemas (utility)

### Pillar 1: Identity
- **pillar1_identity/generate_personas.py** — User persona generation
- **pillar1_identity/validate_provisioning.py** — Provisioning validation
- **pillar1_identity/fix_domain.py** — Domain name fixes

### Pillar 2: Access (Dashboards)
- **pillar2_access/dashboard/generate_dashboard.py** — Pillar 2 dashboard

### Pillar 3: PIM (Privileged Identity Management)
- **pillar3_pim/dashboard/generate_dashboard.py** — Pillar 3 dashboard
- **pillar3_pim/validate_pim.py** — PIM validation

### Pillar 4: Threat
- **pillar4_threat/threat_audit.py** — User risk classification
- **pillar4_threat/osint_exposure_check.py** — Breach intelligence
- **pillar4_threat/seed_osint_data.py** — Synthetic OSINT data

### Dashboard
- **dashboard/generate_central_dashboard.py** — ⭐ Main central dashboard

---

## ⏱️ EXECUTION TIMES

| Component | Duration |
|-----------|----------|
| Tests | ~10 sec |
| Comprehensive Collection | ~1-2 min |
| Enrichment Data | ~30 sec |
| Identity Processing | ~20 sec |
| Threat Intelligence | ~30 sec |
| Compliance Audit | ~20 sec |
| Dashboard Generation | ~10 sec |
| **TOTAL** | **~3-5 min** |

---

## 📈 EXPECTED OUTPUT

### Console Output
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
```

### Dashboard Content
- 📊 4 Pillars (Identity, Access, PIM, Threat)
- 🎯 Risk Classification (CRITICAL, HIGH, MEDIUM, LOW)
- 🛡️ NIST Compliance (800-53, 800-207, 800-171, 800-137)
- 🌐 OSINT Intelligence (breach exposure)
- 📈 Interactive KPIs and charts
- 📋 Audit logs and metrics

---

## 🔄 GITHUB ACTIONS AUTOMATION

The workflow (`.github/workflows/sync.yml`) automatically:

1. Runs every 5 minutes
2. Executes all 7 phases
3. Generates dashboard
4. Auto-deploys to GitHub Pages

**Manual Trigger:**
1. Go to GitHub Actions tab
2. Select workflow
3. Click "Run workflow"

---

## ✅ SUCCESS CRITERIA

After running the demo, verify:

- ✅ `data/entra_comprehensive.json` exists and is >1 MB
- ✅ `data/central_dashboard.html` exists and is >100 KB
- ✅ Dashboard opens in browser
- ✅ User count matches Entra portal (537)
- ✅ All timestamps are recent (within 5 min)
- ✅ No simulated/synthetic data in output

---

## 🆘 QUICK TROUBLESHOOTING

| Issue | Solution |
|-------|----------|
| Scripts not found | Ensure you're in repo root directory |
| "No module named..." | Run: `pip install -r requirements.txt` |
| Auth errors (401) | Check `.env` file credentials |
| 0 risky users | Already fixed — run comprehensive script |
| Dashboard blank | Ensure `entra_comprehensive.json` exists |

---

## 📞 GETTING HELP

1. **Quick answers:** See `QUICK_START.md`
2. **Detailed info:** See `AUTOMATION_RUNBOOK.md`
3. **Script source:** Check individual `.py` files for inline comments
4. **Specific phase:** Run that phase individually and check output

---

**Status:** ✅ Production Ready  
**Last Updated:** 2026-05-03  
**Framework Version:** MediZuva ZT v1.0
