# 🔐 Zero Trust Framework

![Status](https://img.shields.io/badge/Status-Active-00C851?style=for-the-badge&logo=github)
![Framework](https://img.shields.io/badge/Framework-Zero%20Trust-1976D2?style=for-the-badge&logo=security)
![Standards](https://img.shields.io/badge/Standards-NIST%20800--207-FF6B6B?style=for-the-badge&logo=shield)
![Platform](https://img.shields.io/badge/Platform-Microsoft%20Entra%20ID-0078D4?style=for-the-badge&logo=microsoft)
![Architecture](https://img.shields.io/badge/Architecture-Cloud%20Native-4A90E2?style=for-the-badge&logo=cloud)

---

## 📋 Project Overview

This is a **4-pillar Zero Trust Framework** implementation that enforces the core principle: **"Never Trust, Always Verify"** across every access request in the system.

This framework enforces:
- ✅ **Identity Verification** - Every user authenticates with MFA and attribute validation
- ✅ **Conditional Access** - 9 intelligent policies evaluate risk in real-time
- ✅ **Privileged Access Management** - Just-In-Time elevation with full audit trails
- ✅ **Continuous Monitoring** - Breach detection and risk assessment every 6 hours

Compliant with **NIST SP 800-207**, **NIST 800-53**, **NIST 800-63B**, and **NIST 800-137**.

---

## 🔐 How the System Works

### 🎯 The Access Decision Pipeline

Every sign-in request flows through **4 sequential steps**:

#### **Step 1️⃣ User Authentication**
- 🔑 User attempts to sign in via the application portal
- 🌐 Request routes to **Microsoft Entra ID** (cloud identity platform)
- ✅ Username and password validated, but access is **NOT granted yet**

#### **Step 2️⃣ Conditional Access Policy Evaluation**
⚡ Nine policies evaluate simultaneously:

| 🎯 Policy | 🔍 Check | 🛡️ Action |
|-----------|---------|----------|
| **CA001** | 📱 Multi-Factor Authentication | Push notification MFA challenge |
| **CA003** | 💻 Device Compliance | Block non-compliant devices |
| **CA004** | 🚨 High-Risk Locations | Block sign-in from flagged countries |
| **CA006** | ⏰ Session Timeout | Enforce 8-hour session limit |
| **CA008** | 🌍 Geographic Location | Verify authorized regions |
| **ABAC** | 👤 Department Attribute | Route access by user department |
| **CA009** | ⚠️ Breach Detection | Force password reset if breached |
| **Risk-Based** | 📊 Sign-in Risk Score | Step-up verification if needed |
| **Device State** | 🖥️ Mobile/Desktop | Apply tier-specific controls |

**💡 Real Example:**
- ✅ **Clinical User** in Zimbabwe signs in → Department = Clinical → **Portal Access Granted**
- ❌ **Billing User** attempts clinical portal → Department = Billing → **Access Blocked**

#### **Step 3️⃣ Token Issuance**
- 🎟️ Entra ID issues short-lived **OAuth 2.0 access token**
- 📋 Token includes claims: Department, Risk Level, Device State
- ✔️ Application validates token and claims before session creation

#### **Step 4️⃣ Continuous Background Monitoring**
- 🔍 **OSINT Pipeline:** Scans 500 accounts against 4 breach databases every 6 hours
- 🚨 **Breach Detection:** If credentials appear in a breach database:
  - 🔴 User moved to "High Risk" status
  - 🛑 CA004 blocks sign-in
  - 🔐 CA009 forces immediate password reset
  - 📢 Admin notified via dashboard

---

## 🏛️ Zero Trust Core Principles

### **1️⃣ Verify Explicitly**
Never assume trust based on network location. Always authenticate and authorize using **all available data:**
- 👤 User identity
- 💻 Device state
- 🗺️ Location/IP
- 📊 Risk score
- 🏷️ Attribute data

### **2️⃣ Use Least Privilege Access**
Users receive **minimum necessary access** for their role:
- ⏱️ **Just-In-Time (JIT):** Access granted only when needed
- 📌 **Just-Enough-Access (JEA):** Only the minimum permissions required
- ⏰ **Time-Limited:** Admin roles expire after 1 hour and require re-elevation

### **3️⃣ Assume Breach**
Design assuming credentials are compromised:
- 🔒 All data encrypted in transit and at rest
- 📡 Continuous monitoring for breach indicators
- ⚡ Rapid session revocation on risk elevation
- 🚧 Segmentation between departments

---

## 🔧 The 4 Pillars

### **Pillar 1️⃣: Identity Management** 👥
Governs user lifecycle from hire to departure.
- 📝 **Joiner:** Automated provisioning when hired
- 🔄 **Mover:** Updated role assignments and access during transfers
- 🚪 **Leaver:** Immediate deprovisioning and access revocation

**📂 Files:**
- `joiner.ps1` - Automated new user provisioning
- `mover.ps1` - Role change automation
- `leaver.ps1` - Complete access removal

---

### **Pillar 2️⃣: Conditional Access** 🎯
Intelligent policy engine that evaluates 9 rules simultaneously.
- 🚨 Real-time risk assessment
- 🌍 Geographic enforcement
- 💻 Device compliance validation
- ⏰ Session management (8-hour limit)

**📂 Files:**
- `ca_dashboard.html` - Real-time CA policy monitoring
- `create_breakglass.ps1` - Emergency admin account setup

---

### **Pillar 3️⃣: Privileged Identity Management (PIM)** 🔑
Removes standing admin access; everything is time-limited and justified.
- ✅ Admins request 1-hour elevations with business justification
- 🆘 Break-glass account for disaster recovery
- 📋 Full audit trail of all privilege usage

**📂 Files:**
- `pim_dashboard.html` - PIM activation and approval tracking
- `generate_dashboard.py` - Dashboard rendering

---

### **Pillar 4️⃣: Continuous Monitoring** 📡
Background processes detect breaches and anomalies.
- 🔍 6-hour breach database scans (4 data sources)
- 📊 Risk score recalculation
- 🤖 Automated response to security events

**📂 Files:**
- `generate_dashboard.py` - Orchestrates all dashboards
- GitHub Actions - 15-minute refresh cycle

---

## 📚 Key Terminology

| 🎯 Term | 📖 Definition | 💡 Example |
|---------|---------------|-----------|
| **ABAC** | Attribute-Based Access Control | Department = "Clinical" → Access Portal |
| **CA Policy** | Conditional Access Rule | IF (Device = Non-Compliant) THEN (Block) |
| **MFA** | Multi-Factor Authentication | Password + Push notification to phone |
| **JIT Access** | Just-In-Time Elevation | Admin requests 1-hour access with justification |
| **Risk Score** | Probability sign-in is compromised | 0-100; >80 = High Risk → Block |
| **Session Control** | Time limit for continuous access | 8 hours for staff, 30 min for admins |
| **Break-glass** | Emergency admin account (no CA policies) | Used only if all admin access is lost |
| **Entra ID** | Microsoft cloud identity platform | Hosts all users, policies, tokens |
| **OAuth 2.0** | Access token standard | Format: JWT with claims (Department, Risk, etc.) |
| **OSINT** | Open-Source Intelligence | Scans breach databases for leaked credentials |

---

## 🚀 Getting Started

### ✅ Prerequisites
- 🔐 Microsoft Entra ID tenant
- 🖥️ PowerShell 7+
- 🐍 Python 3.8+
- ⚙️ GitHub Actions enabled (for automated dashboard updates)

### 📁 Directory Structure
```
zero-trust-framework/
├── 👥 pillar1_identity/
│   ├── joiner.ps1              # ➕ New user provisioning
│   ├── mover.ps1               # 🔄 Role change workflow
│   ├── leaver.ps1              # 🚪 Offboarding automation
│   ├── provision_users.ps1      # 📦 Bulk provisioning
│   └── validate_provisioning.py # ✅ Verification script
│
├── 🎯 pillar2_access/
│   ├── create_breakglass.ps1    # 🆘 Emergency admin setup
│   └── dashboard/
│       └── generate_dashboard.py # 📊 CA policy dashboard
│
├── 🔑 pillar3_pim/
│   └── dashboard/
│       └── generate_dashboard.py # 📋 PIM activation tracking
│
├── 📡 pillar4_monitoring/
│   └── (breach detection & OSINT pipeline)
│
├── 📊 data/
│   ├── ca_dashboard.html        # 📈 Conditional Access dashboard
│   └── pim_dashboard.html       # 📉 PIM management dashboard
│
└── 📄 README.md                 # This file
```

### ⚡ Quick Start
1. 📥 Clone the repository
2. 📖 Review `pillar1_identity/joiner.ps1` for user provisioning
3. 📊 Check `data/ca_dashboard.html` to view CA policies
4. 🚀 Run `pillar3_pim/dashboard/generate_dashboard.py` to generate PIM dashboard
5. ⚙️ Set up GitHub Actions for 15-minute dashboard refreshes

---

## 📊 Monitoring & Dashboards

### 📈 Real-Time Dashboards
- 🎯 **CA Dashboard** (`data/ca_dashboard.html`) - View all 9 conditional access policies, block rates, and risky users
- 🔑 **PIM Dashboard** (`data/pim_dashboard.html`) - Track active elevations, pending approvals, and audit logs
- 📡 **Central Dashboard** (`data/central_dashboard.html`) - Unified view of all security metrics

### 🔄 Dashboard Refresh
⚙️ **Automated via GitHub Actions** every 15 minutes.

**Manual refresh:**
```powershell
python pillar3_pim/dashboard/generate_dashboard.py
python pillar2_access/dashboard/generate_dashboard.py
```

---

## 🔐 Security Architecture

### 🛡️ Defense-in-Depth Layers

```
╔═══════════════════════════════════════════════╗
║  Layer 1️⃣: Authentication (Entra ID)         ║
║  ✅ Password + MFA Verification              ║
╠═══════════════════════════════════════════════╣
║  Layer 2️⃣: Conditional Access (9 Policies)   ║
║  ✅ Device, Location, Risk, Department       ║
╠═══════════════════════════════════════════════╣
║  Layer 3️⃣: Privilege Management (PIM)        ║
║  ✅ Time-Limited, Justified Elevation        ║
╠═══════════════════════════════════════════════╣
║  Layer 4️⃣: Continuous Monitoring             ║
║  ✅ Breach Detection, Risk Reassessment      ║
╚═══════════════════════════════════════════════╝
```

### 📋 Compliance Framework
- ✅ **NIST SP 800-207** — Zero Trust Architecture
- ✅ **NIST 800-53** — Access Control & Identification
- ✅ **NIST 800-63B** — Authentication & Lifecycle
- ✅ **NIST 800-137** — Information Security Continuous Monitoring

---

## 📝 Audit & Logging

**All security events are logged and auditable:**
- 👤 User provisioning/deprovisioning
- ❌ Failed authentication attempts
- 🔑 Privilege elevation requests
- ⚖️ Policy enforcement decisions
- 🚨 Breach detections

**Access logs available via:**
- 📊 Microsoft Entra ID audit logs
- 📈 Azure Monitor
- 🚀 GitHub Actions run history

---

## 🤝 Contributing

**Contributions are welcome!** Please ensure:
1. ✅ All changes follow Zero Trust principles
2. 🧪 Conditional Access policies are tested in Report-Only mode first
3. 📋 PIM audit trails are preserved
4. ⚙️ Dashboard automation continues to function

---

## 📄 License

🔐 **Enterprise-Grade Zero Trust Framework**
This implementation follows industry best practices and compliance standards for enterprise identity and access management.

---

---

<div align="center">

### 🚀 Author & Maintainer

#### **Mr. Kudzaishe Rutsinga**
**Identity & Access Management Lead** | **Zero Trust Security Architect**

---

<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; margin: 20px 0;">

📧 **Email:** kudzyruts11@gmail.com

💼 **Specialization:** Enterprise Identity, Zero Trust Architecture, NIST Compliance

🔐 **Framework:** Never Trust, Always Verify

</div>

---

</div>
