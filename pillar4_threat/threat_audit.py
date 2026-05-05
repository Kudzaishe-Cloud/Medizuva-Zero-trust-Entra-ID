"""
pillar4_threat/threat_audit.py
============================================================
Python replacement for threat_audit.ps1.
Aggregates all Pillar 4 threat signals into a unified risk
report and exports data/threat_audit.json for the dashboard.

Inputs (run these first):
  shared/entra_sync.py           → data/risky_users.json
  osint_exposure_check.py        → data/osint_results/hibp_results.json

Risk Tier Classification:
  CRITICAL — IdP HIGH risk, OR OSINT exposed + no MFA
  HIGH     — IdP MEDIUM risk, OR OSINT exposed, OR no MFA
  MEDIUM   — Non-compliant device, OR RiskScore > 15
  LOW      — No signals detected

Usage: python pillar4_threat/threat_audit.py
Output: data/threat_audit.json
============================================================
"""

import json
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

REPO_ROOT      = Path(__file__).resolve().parents[1]
PERSONAS_CSV   = REPO_ROOT / "data" / "personas" / "medizuva_500_personas.csv"
RISKY_USERS    = REPO_ROOT / "data" / "risky_users.json"
HIBP_RESULTS   = REPO_ROOT / "data" / "osint_results" / "hibp_results.json"
OSINT_COMBINED = REPO_ROOT / "data" / "osint_results" / "osint_combined_results.json"
EXPORT_PATH    = REPO_ROOT / "data" / "threat_audit.json"
TENANT         = "micrlabs.onmicrosoft.com"


def load_json(path: Path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)


def main():
    print("\n================================================")
    print(" MediZuva — Threat Audit (Pillar 4)")
    print(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================\n")

    # ── Load inputs ───────────────────────────────────────────
    risky_data  = load_json(RISKY_USERS)
    hibp_data   = load_json(HIBP_RESULTS)
    osint_data  = load_json(OSINT_COMBINED)

    if not risky_data:
        print("  [WARN] risky_users.json not found — run shared/entra_sync.py first")
    if not hibp_data:
        print("  [WARN] hibp_results.json not found — run osint_exposure_check.py first")

    df = pd.read_csv(PERSONAS_CSV)
    print(f"  Loaded {len(df)} personas")

    # ── Build lookup tables ───────────────────────────────────

    # Identity Protection: UPN → risk level
    idp_risk: dict[str, str] = {}
    if risky_data:
        for u in (risky_data.get("RiskyUsers") or []):
            idp_risk[u["UPN"].lower()] = u["RiskLevel"]

    # MFA gaps: UPN → True
    mfa_missing: dict[str, bool] = {}
    if risky_data:
        for u in (risky_data.get("MFAGaps") or []):
            mfa_missing[u["UPN"].lower()] = True

    # Device gaps: UPN → count
    device_nc: dict[str, int] = {}
    if risky_data:
        for d in (risky_data.get("DeviceGaps") or []):
            upn = d["UPN"].lower()
            device_nc[upn] = device_nc.get(upn, 0) + 1

    # HIBP / OSINT exposure: email → breach list
    # Prefer richer osint_combined; fall back to hibp_results
    osint_exposed: dict[str, list] = {}
    if osint_data:
        for r in (osint_data.get("Results") or []):
            if r.get("Exposed"):
                osint_exposed[r["Email"].lower()] = r.get("BreachSources", [])
    elif hibp_data:
        for r in (hibp_data.get("Results") or []):
            if r.get("Exposed"):
                osint_exposed[r["Email"].lower()] = r.get("Breaches", [])

    print(f"  IdP risky    : {len(idp_risk)}")
    print(f"  MFA gaps     : {len(mfa_missing)}")
    print(f"  Device gaps  : {len(device_nc)}")
    print(f"  OSINT exposed: {len(osint_exposed)}")

    # ── Classify each persona ─────────────────────────────────
    print("\n--- Classifying risk tiers ---")

    user_risks = []
    tier_count = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for _, row in df.iterrows():
        upn       = str(row["Email"]).lower()
        idp_level = idp_risk.get(upn, "")
        no_mfa    = mfa_missing.get(upn, False) or str(row.get("MFARegistered", "True")) == "False"
        no_dev    = upn in device_nc or str(row.get("DeviceCompliant", "True")) == "False"
        osint_hit = upn in osint_exposed
        risk_score= int(row.get("RiskScore", 0))

        signals = []
        if idp_level == "high":   signals.append("IdP-High")
        if idp_level == "medium": signals.append("IdP-Medium")
        if no_mfa:                signals.append("No-MFA")
        if no_dev:                signals.append("Non-Compliant-Device")
        if osint_hit:             signals.append("OSINT-Exposed")
        if risk_score > 15:       signals.append(f"HighRiskScore({risk_score})")

        if idp_level == "high" or (osint_hit and no_mfa):
            tier = "CRITICAL"
        elif idp_level == "medium" or osint_hit or no_mfa:
            tier = "HIGH"
        elif no_dev or risk_score > 15:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        tier_count[tier] += 1

        if tier in ("CRITICAL", "HIGH"):
            label = f"  [{tier:8s}] {row['FirstName']} {row['LastName']} ({row['JobTitle']}) — {', '.join(signals)}"
            print(label)

        user_risks.append({
            "UPN":        upn,
            "Name":       f"{row['FirstName']} {row['LastName']}",
            "Department": row["Department"],
            "JobTitle":   row["JobTitle"],
            "Location":   row["Location"],
            "Tier":       tier,
            "Signals":    ", ".join(signals),
            "RiskScore":  risk_score,
            "IdPRisk":    idp_level or "none",
            "MFAGap":     no_mfa,
            "DeviceGap":  no_dev,
            "HIBPExp":    osint_hit,
        })

    # ── Summary ───────────────────────────────────────────────
    total   = len(df)
    posture = (
        "AT RISK"   if tier_count["CRITICAL"] > 0 or tier_count["HIGH"] > 10
        else "PARTIAL"   if tier_count["HIGH"] > 0
        else "COMPLIANT"
    )

    no_mfa_total = sum(1 for u in user_risks if u["MFAGap"])
    no_dev_total = sum(1 for u in user_risks if u["DeviceGap"])

    print(f"\n{'='*48}")
    print("THREAT AUDIT SUMMARY")
    print(f"  Total users  : {total}")
    print(f"  CRITICAL     : {tier_count['CRITICAL']}")
    print(f"  HIGH         : {tier_count['HIGH']}")
    print(f"  MEDIUM       : {tier_count['MEDIUM']}")
    print(f"  LOW          : {tier_count['LOW']}")
    print(f"  OSINT Exposed: {len(osint_exposed)}")
    print(f"  MFA Gaps     : {no_mfa_total}")
    print(f"  Device Gaps  : {no_dev_total}")
    print(f"  Posture      : {posture}")
    print(f"{'='*48}")

    # ── Export ────────────────────────────────────────────────
    export = {
        "AuditDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tenant":    TENANT,
        "UserRisks": user_risks,
        "Summary": {
            "TotalUsers":  total,
            "Critical":    tier_count["CRITICAL"],
            "High":        tier_count["HIGH"],
            "Medium":      tier_count["MEDIUM"],
            "Low":         tier_count["LOW"],
            "HIBPExposed": len(osint_exposed),
            "MFAGaps":     no_mfa_total,
            "DeviceGaps":  no_dev_total,
            "Posture":     posture,
        },
    }

    EXPORT_PATH.write_text(json.dumps(export, indent=2), encoding="utf-8")
    print(f"\n[OK] Threat audit saved: {EXPORT_PATH}")
    print("     Next: python dashboard/generate_central_dashboard.py\n")


if __name__ == "__main__":
    main()
