# MediZuva Zero-Trust Framework

> A comprehensive zero-trust security architecture framework for healthcare organizations built on Microsoft Entra ID and aligned with NIST cybersecurity standards.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [The 4 Pillars of Zero Trust](#the-4-pillars-of-zero-trust)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [NIST Compliance](#nist-compliance)
- [Output & Results](#output--results)
- [Troubleshooting](#troubleshooting)

---

## Overview

**MediZuva** is a production-ready zero-trust security framework designed specifically for healthcare organizations. It integrates with **Microsoft Entra ID** and **Microsoft Graph API** to provide continuous security monitoring, compliance auditing, and threat detection across your organization.

The framework automates the collection, analysis, and visualization of security data across four critical pillars:

1. **Identity Verification** — User provisioning and identity validation
2. **Access Control** — Conditional Access policies and privilege escalation detection
3. **Privileged Access Management (PAM)** — PIM role assignments and entitlements audit
4. **Threat Detection** — Risk classification and breach intelligence

---

## Key Features

### 🔐 Zero-Trust Architecture
- **Assume Breach Mentality** — Every access request is verified
- **Least Privilege Access** — Users get minimal required permissions
- **Continuous Verification** — Real-time risk assessment and monitoring

### 📊 Compliance & Auditing
- **NIST 800-207** — Zero Trust Architecture framework
- **NIST 800-53** — Security and privacy controls
- **NIST 800-63B** — Identity and access management guidelines
- **NIST 800-171** — Healthcare data protection requirements
- **NIST 800-137** — Continuous monitoring and assessment

### 🎯 Automated Detection
- **Risky User Identification** — Flagged by Azure risk engine
- **MFA Gap Analysis** — Users without multi-factor authentication
- **Device Compliance Audit** — Non-compliant devices
- **Privileged Role Analysis** — Excessive entitlements
- **Breach Intelligence** — OSINT-based exposure detection

### 📈 Interactive Dashboard
- Real-time security metrics and KPIs
- Drill-down capabilities for investigation
- Risk scoring and trending analysis
- Automated GitHub Pages deployment

---

## The 4 Pillars of Zero Trust

### Pillar 1: Identity Verification
**Purpose:** Validate all user identities and ensure proper provisioning

- ✅ Generates realistic user personas with risk profiles
- ✅ Validates identity provisioning against Entra ID
- ✅ Detects orphaned or inactive accounts
- ✅ Identifies identity attribute gaps

**Key Scripts:**
- `pillar1_identity/generate_personas.py` — User persona generation
- `pillar1_identity/validate_provisioning.py` — Identity validation

---

### Pillar 2: Access Control
**Purpose:** Enforce least-privilege access and verify authorization

- ✅ Audits Conditional Access policies
- ✅ Detects policy gaps and misconfigurations
- ✅ Verifies MFA enforcement
- ✅ Monitors device compliance

**Key Scripts:**
- `pillar2_access/dashboard/generate_dashboard.py` — CA policy visualization

---

### Pillar 3: Privileged Access Management
**Purpose:** Monitor and control privileged role assignments

- ✅ Audits Azure AD/Entra ID PIM assignments
- ✅ Identifies excessive privilege grants
- ✅ Tracks privilege escalation patterns
- ✅ Generates entitlements reports

**Key Scripts:**
- `pillar3_pim/validate_pim.py` — PIM role audit
- `pillar3_pim/dashboard/generate_dashboard.py` — PIM visualization

---

### Pillar 4: Threat Detection
**Purpose:** Identify and classify security threats

- ✅ Risk-based user classification (Low/Medium/High/Critical)
- ✅ OSINT breach intelligence (Have I Been Pwned)
- ✅ Sign-in anomaly detection
- ✅ Threat correlation and scoring

**Key Scripts:**
- `pillar4_threat/threat_audit.py` — Risk classification engine
- `pillar4_threat/osint_exposure_check.py` — Breach intelligence

---

## Prerequisites

### System Requirements
- **Python 3.11+** — Core runtime
- **Git** — Version control and deployment
- **Node.js 18+** (optional) — Dashboard development
- **Windows/Linux/macOS** — Cross-platform compatible

### Microsoft Entra ID Setup
You need valid Entra ID credentials with appropriate permissions:

1. **Create an Application Registration** in Azure Portal
   - Navigate to: Azure Portal → Entra ID → App Registrations → New Registration
   - Name: "MediZuva Zero-Trust Framework"
   - Account type: "Single tenant"

2. **Add API Permissions:**
   - `User.Read.All` — Read user profiles
   - `AuditLog.Read.All` — Read audit logs
   - `Policy.Read.All` — Read policies
   - `RoleManagement.Read.Directory` — Read role assignments
   - `PrivilegedAccess.Read.AzureAD` — Read PIM data

3. **Create Client Secret**
   - In App Registration: Certificates & secrets → New client secret
   - Copy the secret value (you'll only see it once)

4. **Grant Admin Consent**
   - In API Permissions → Grant admin consent for your organization

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Kudzaishe-Cloud/Medizuva-Zero-trust-Entra-ID.git
cd Medizuva-Zero-trust-Entra-ID
```

### 2. Install Python Dependencies

```bash
# Create virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install requirements
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the project root:

```bash
# .env file template
ENTRA_TENANT_ID=your-tenant-id
ENTRA_CLIENT_ID=your-app-registration-client-id
ENTRA_CLIENT_SECRET=your-client-secret-value
```

**⚠️ Security Note:** Never commit `.env` to version control. It's included in `.gitignore`.

### 4. Verify Configuration

```bash
# Test Entra ID authentication
python test_entra_auth.py

# Expected output: "✓ Authentication successful"
```

---

## Quick Start

Run the complete system automation with a single command:

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

The automation will:
1. Verify all credentials and API connectivity
2. Collect comprehensive Entra ID data
3. Perform security audits across all 4 pillars
4. Classify users by risk level
5. Generate compliance reports (NIST 800-53, 800-207, etc.)
6. Create interactive dashboard
7. Deploy dashboard to GitHub Pages (optional)

**Expected execution time:** 5-10 minutes (depending on organization size)

---

## How It Works

### Data Flow Architecture

```
┌─────────────────────────────────────────────────────────┐
│         Microsoft Entra ID & Graph API                  │
│  (Users, Devices, Sign-ins, Policies, Roles, Logs)      │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│    Data Collection Layer (shared/entra_*.py)            │
│  • Identity data extraction                             │
│  • Access policy analysis                               │
│  • PIM role enumeration                                 │
│  • Sign-in log processing                               │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│    Analysis & Enrichment Layer (pillar*/)               │
│  • Persona generation & validation                      │
│  • Policy compliance checking                           │
│  • Risk classification engine                           │
│  • Breach intelligence (OSINT)                          │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│    Compliance & Reporting (shared/nist_compliance.py)   │
│  • NIST control mapping                                 │
│  • Gap analysis                                         │
│  • Evidence generation                                  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│    Visualization Layer (dashboard/)                     │
│  • Interactive web dashboard                            │
│  • Real-time metrics                                    │
│  • GitHub Pages deployment                              │
└─────────────────────────────────────────────────────────┘
```

### Key Workflows

#### Workflow 1: Identity & Risk Assessment
1. Fetch all users from Entra ID
2. Extract risk signals from Azure risk engine
3. Identify risky users, inactive accounts, MFA gaps
4. Generate risk profiles and personas
5. Validate provisioning accuracy

#### Workflow 2: Access Control Audit
1. Retrieve all Conditional Access policies
2. Analyze policy rules and scope
3. Identify gaps (missing MFA, unprotected apps, etc.)
4. Check device compliance status
5. Generate policy recommendations

#### Workflow 3: Privilege Escalation Detection
1. Enumerate all PIM-eligible and active roles
2. Identify excessive privilege assignments
3. Detect privilege escalation patterns
4. Cross-reference with sign-in logs
5. Generate entitlements audit

#### Workflow 4: Threat Intelligence
1. Classify users by risk tier using ML-based scoring
2. Query breach databases (Have I Been Pwned)
3. Correlate with sign-in anomalies
4. Generate risk reports
5. Alert on critical findings

---

## Project Structure

```
medizuva-zt-framework/
├── README.md                           # This file
├── requirements.txt                    # Python dependencies
├── .env.example                        # Environment variable template
│
├── # === Core Automation ===
├── run_full_demo.ps1                  # Windows PowerShell automation
├── run_full_demo.bat                  # Windows Command Prompt automation
├── run_full_demo.sh                   # Linux/macOS automation
│
├── # === Testing & Validation ===
├── test_entra_auth.py                 # Verify Entra ID credentials
├── test_graph_endpoints.py            # Test Graph API connectivity
├── test_risky_users.py                # Test risky users endpoint
│
├── # === Shared Utilities ===
├── shared/
│   ├── entra_comprehensive.py         # PRIMARY: Fetch all Entra ID data
│   ├── entra_sync.py                  # Risky users, MFA, device compliance
│   ├── entra_ca.py                    # Conditional Access policy audit
│   ├── entra_pim.py                   # PIM role assignments audit
│   ├── entra_logs.py                  # Sign-in log retrieval
│   ├── nist_compliance.py             # NIST compliance reporting
│   └── schemas.py                     # Data models and validation
│
├── # === Pillar 1: Identity ===
├── pillar1_identity/
│   ├── generate_personas.py           # User persona generation
│   └── validate_provisioning.py       # Identity provisioning validation
│
├── # === Pillar 2: Access Control ===
├── pillar2_access/
│   └── dashboard/
│       └── generate_dashboard.py      # CA policy visualization
│
├── # === Pillar 3: Privileged Access ===
├── pillar3_pim/
│   ├── validate_pim.py                # PIM role audit
│   └── dashboard/
│       └── generate_dashboard.py      # PIM visualization
│
├── # === Pillar 4: Threat Detection ===
├── pillar4_threat/
│   ├── threat_audit.py                # Risk classification
│   ├── osint_exposure_check.py        # Breach intelligence
│   └── seed_osint_data.py             # OSINT data seeding
│
├── # === Dashboards & Reports ===
├── dashboard/
│   ├── generate_central_dashboard.py  # Main interactive dashboard
│   ├── index.html                     # Dashboard web interface
│   └── data/                          # Dashboard data files
│
├── # === Data Storage ===
├── data/
│   ├── entra_comprehensive.json       # Complete Entra ID snapshot
│   ├── nist_compliance_report.json    # Compliance audit results
│   └── osint_results/                 # Breach intelligence data
│
└── # === Documentation ===
    ├── QUICK_START.md                 # Quick start guide
    ├── AUTOMATION_RUNBOOK.md          # Complete automation guide
    ├── ENTRA_ID_SETUP.md              # Entra ID setup instructions
    └── ALL_SCRIPTS.md                 # Complete script reference
```

---

## NIST Compliance

The framework generates comprehensive compliance reports against multiple NIST standards:

### Supported Standards

| Standard | Focus Area | Reports |
|----------|-----------|---------|
| **NIST 800-207** | Zero Trust Architecture | Control mapping, gap analysis |
| **NIST 800-53** | Security Controls | ~220 security controls |
| **NIST 800-63B** | Identity & Authentication | Password, MFA, account mgmt |
| **NIST 800-171** | Healthcare Data Protection | CUI safeguards for healthcare |
| **NIST 800-137** | Continuous Monitoring | Metrics, assessment procedures |

### Accessing Compliance Reports

After running the automation:

```bash
# View NIST compliance report
cat data/nist_compliance_report.json | python -m json.tool

# Key sections in the report:
# - coverage_summary: What % of controls are addressed
# - control_mappings: Detailed control assessments
# - gaps: Identified compliance gaps
# - recommendations: Remediation actions
```

---

## Output & Results

### Generated Files

After running the automation, the following outputs are created:

#### 1. Data Files
- **`data/entra_comprehensive.json`** — Complete snapshot of all Entra ID data
- **`data/nist_compliance_report.json`** — NIST compliance audit results
- **`data/osint_results/`** — Breach intelligence findings

#### 2. Dashboards
- **`dashboard/index.html`** — Interactive web dashboard (open in browser)
- **GitHub Pages Deployment** — Auto-deployed to `github.com/<user>/Medizuva-Zero-trust-Entra-ID`

#### 3. Console Output
Real-time progress and findings printed to console for immediate review

### Dashboard Features

The interactive dashboard includes:

- 📊 **Security Metrics** — Overall security posture scores
- 👥 **Risk Classification** — Users by risk tier (Low/Medium/High/Critical)
- 🔐 **MFA Coverage** — MFA adoption and gaps
- 🛡️ **Policy Analysis** — Conditional Access policy effectiveness
- 📋 **Compliance Status** — NIST control compliance
- ⚠️ **Alerts & Recommendations** — Actionable security findings

---

## Troubleshooting

### Common Issues

#### "Authentication failed"
```bash
# Verify credentials in .env file
cat .env

# Test authentication
python test_entra_auth.py

# Troubleshooting steps:
# 1. Verify ENTRA_TENANT_ID is correct (get from Entra ID > Overview)
# 2. Confirm app registration has correct API permissions
# 3. Check client secret hasn't expired (expires after ~1-2 years)
# 4. Ensure .env file has no quotes around values
```

#### "Permission denied" errors
```bash
# Grant admin consent in Azure Portal:
# 1. Azure Portal > Entra ID > App Registrations
# 2. Select your app > API Permissions
# 3. Click "Grant admin consent for <organization>"
# 4. Wait 5 minutes for permissions to propagate
```

#### "Module not found" errors
```bash
# Reinstall dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Or use virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

#### Dashboard not loading
```bash
# Verify dashboard was generated
ls dashboard/index.html

# Open directly in browser
# Windows: start dashboard\index.html
# macOS: open dashboard/index.html
# Linux: xdg-open dashboard/index.html
```

---

## Support & Contributing

### Getting Help
- Review `QUICK_START.md` for common questions
- Check `AUTOMATION_RUNBOOK.md` for detailed workflows
- Read `ENTRA_ID_SETUP.md` for Entra ID configuration

### Reporting Issues
If you encounter issues:
1. Check the troubleshooting section above
2. Review console output for error messages
3. Enable debug logging (set `DEBUG=true` in `.env`)

---

## Security Notice

⚠️ **Important Security Considerations:**

- Never commit `.env` file with credentials to version control
- Use service accounts with minimal required permissions
- Rotate client secrets annually
- Review data retention policies for sensitive information
- Audit access to dashboards and reports
- Follow your organization's data classification standards

---

## License & Attribution

**MediZuva Zero-Trust Framework** — Built for healthcare organizations seeking enterprise-grade zero-trust security.

Aligned with industry standards and best practices for identity, access, and threat management.

---

## Changelog

### Version 1.0.0
- ✅ Initial release with 4-pillar architecture
- ✅ NIST 800-207, 800-53, 800-63B, 800-171, 800-137 compliance
- ✅ Interactive dashboard with GitHub Pages deployment
- ✅ Automated end-to-end security framework
- ✅ Cross-platform support (Windows, Linux, macOS)

---

**Last Updated:** May 2026  
**Maintained By:** MediZuva Security Team
