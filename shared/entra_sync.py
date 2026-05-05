"""
shared/entra_sync.py
============================================================
Python replacement for check_risky_users.ps1.
Queries three Entra ID (Microsoft Graph) threat signals:
  1. Identity Protection — risky users (high/medium)
  2. MFA registration gaps — users not MFA-registered
  3. Device compliance gaps — non-compliant managed devices

Reads credentials from environment variables (safe for CI/CD):
  ENTRA_TENANT_ID
  ENTRA_CLIENT_ID
  ENTRA_CLIENT_SECRET

Falls back to SIMULATE mode if no credentials are set.

Output: data/risky_users.json

Usage:
  python shared/entra_sync.py
  python shared/entra_sync.py --simulate
============================================================
"""

import argparse
import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parents[1]
OUT_PATH   = REPO_ROOT / "data" / "risky_users.json"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


# ── Auth ──────────────────────────────────────────────────────

def get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain an access token via client_credentials grant."""
    url  = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "grant_type":    "client_credentials",
        "client_id":     client_id,
        "client_secret": client_secret,
        "scope":         "https://graph.microsoft.com/.default",
    }).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["access_token"]


def graph_get(url: str, headers: dict) -> list:
    """Paginate through a Graph API endpoint, returning all items."""
    items = []
    while url:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
            items += data.get("value", [])
            url = data.get("@odata.nextLink")
        except urllib.error.HTTPError as e:
            print(f"  [WARN] Graph query failed: {url} — HTTP {e.code}")
            break
    return items


# ── Live checks ───────────────────────────────────────────────

def fetch_risky_users(headers: dict) -> list:
    print("[1/3] Querying Identity Protection risky users...")
    url = (
        f"{GRAPH_BASE}/identityProtection/riskyUsers"
        f"?$filter=riskLevel eq 'high' or riskLevel eq 'medium'"
        f"&$select=id,userDisplayName,userPrincipalName,riskLevel,riskState,riskLastUpdatedDateTime,isDeleted"
    )
    users = []
    for u in graph_get(url, headers):
        if u.get("isDeleted"):
            continue
        print(f"  [{u['riskLevel'].upper()}] {u['userDisplayName']} — {u['riskState']}")
        users.append({
            "UserId":      u["id"],
            "DisplayName": u["userDisplayName"],
            "UPN":         u["userPrincipalName"],
            "RiskLevel":   u["riskLevel"],
            "RiskState":   u["riskState"],
            "LastUpdated": u.get("riskLastUpdatedDateTime", ""),
            "Source":      "IdentityProtection",
        })
    print(f"  Total risky users: {len(users)}")
    return users


def fetch_mfa_gaps(headers: dict) -> list:
    print("[2/3] Querying MFA registration gaps...")
    url  = f"{GRAPH_BASE}/reports/credentialUserRegistrationDetails"
    gaps = []
    for u in graph_get(url, headers):
        if not u.get("isMfaRegistered"):
            gaps.append({
                "UserId":       u.get("id", ""),
                "DisplayName":  u.get("userDisplayName", ""),
                "UPN":          u.get("userPrincipalName", ""),
                "MFARegistered":False,
                "AuthMethods":  ", ".join(u.get("authMethods", [])),
            })
    print(f"  Users without MFA: {len(gaps)}")
    return gaps


def fetch_device_gaps(headers: dict) -> list:
    print("[3/3] Querying non-compliant managed devices...")
    url  = (
        f"{GRAPH_BASE}/deviceManagement/managedDevices"
        f"?$filter=complianceState ne 'compliant'"
        f"&$select=id,deviceName,userDisplayName,userPrincipalName,complianceState,operatingSystem,lastSyncDateTime"
    )
    gaps = []
    for d in graph_get(url, headers):
        gaps.append({
            "DeviceId":        d.get("id", ""),
            "DeviceName":      d.get("deviceName", ""),
            "UserDisplayName": d.get("userDisplayName", ""),
            "UPN":             d.get("userPrincipalName", ""),
            "ComplianceState": d.get("complianceState", ""),
            "OS":              d.get("operatingSystem", ""),
            "LastSync":        d.get("lastSyncDateTime", ""),
        })
    print(f"  Non-compliant devices: {len(gaps)}")
    return gaps


# ── CSV-based mode (no Entra creds) ──────────────────────────

PERSONAS_CSV = REPO_ROOT / "data" / "personas" / "medizuva_500_personas.csv"

def simulate_data() -> tuple[list, list, list]:
    """
    Read MFA and device truth directly from the personas CSV.
    This is NOT random — it reflects the actual values set during provisioning.
    MFARegistered=False means the user genuinely has no MFA registered.
    DeviceCompliant=False means their device is genuinely non-compliant.
    """
    try:
        import pandas as pd
        df = pd.read_csv(PERSONAS_CSV)
    except Exception as e:
        print(f"  [WARN] Could not read personas CSV: {e}")
        return [], [], []

    # MFA gaps — users where MFARegistered is False in the CSV (56 users)
    mfa_gaps = []
    for _, row in df[df["MFARegistered"] == False].iterrows():
        mfa_gaps.append({
            "UserId":        str(row["EmployeeID"]),
            "DisplayName":   f"{row['FirstName']} {row['LastName']}",
            "UPN":           row["Email"],
            "MFARegistered": False,
            "AuthMethods":   "",
        })

    # Device gaps — users where DeviceCompliant is False in the CSV (156 users)
    device_gaps = []
    for _, row in df[df["DeviceCompliant"] == False].iterrows():
        device_gaps.append({
            "DeviceId":        f"dev-{row['EmployeeID']}",
            "DeviceName":      f"{row['FirstName'].lower()}-workstation",
            "UserDisplayName": f"{row['FirstName']} {row['LastName']}",
            "UPN":             row["Email"],
            "ComplianceState": "noncompliant",
            "OS":              "Windows",
            "LastSync":        "",
        })

    print(f"  [CSV] MFA gaps from personas data   : {len(mfa_gaps)}")
    print(f"  [CSV] Device gaps from personas data: {len(device_gaps)}")
    print("        (These are real provisioning values, not random)")
    return [], mfa_gaps, device_gaps


# ── Main ──────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="MediZuva Entra ID sync")
    parser.add_argument("--simulate", action="store_true",
                        help="Force simulate mode even if credentials are set")
    args = parser.parse_args()

    tenant_id     = os.environ.get("ENTRA_TENANT_ID",     "")
    client_id     = os.environ.get("ENTRA_CLIENT_ID",     "")
    client_secret = os.environ.get("ENTRA_CLIENT_SECRET", "")

    live_mode = bool(client_secret) and not args.simulate

    print("\n================================================")
    print(" MediZuva — Entra ID Sync")
    print(f" Mode   : {'LIVE' if live_mode else 'SIMULATE'}")
    print(f" Tenant : {tenant_id}")
    print(f" Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================\n")

    if live_mode:
        try:
            print("Obtaining access token...")
            token   = get_token(tenant_id, client_id, client_secret)
            headers = {"Authorization": f"Bearer {token}"}
            print("  [OK] Token obtained\n")
            risky_users  = fetch_risky_users(headers)
            mfa_gaps     = fetch_mfa_gaps(headers)
            device_gaps  = fetch_device_gaps(headers)
        except Exception as e:
            print(f"  [ERROR] Live sync failed: {e}")
            print("  Falling back to simulate mode...")
            risky_users, mfa_gaps, device_gaps = simulate_data()
    else:
        risky_users, mfa_gaps, device_gaps = simulate_data()

    export = {
        "CheckDate":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tenant":     "medizuva",
        "Mode":       "live" if live_mode else "simulated",
        "RiskyUsers": risky_users,
        "MFAGaps":    mfa_gaps,
        "DeviceGaps": device_gaps,
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(export, indent=2), encoding="utf-8")

    print(f"\n  Risky users  : {len(risky_users)}")
    print(f"  MFA gaps     : {len(mfa_gaps)}")
    print(f"  Device gaps  : {len(device_gaps)}")
    print(f"\n[OK] Saved: {OUT_PATH}")
    print("     Next: python pillar4_threat/threat_audit.py\n")


if __name__ == "__main__":
    main()
