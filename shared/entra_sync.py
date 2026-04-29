"""
shared/entra_sync.py
============================================================
Queries three Entra ID (Microsoft Graph) threat signals:
  1. Identity Protection — risky users (high/medium)
  2. MFA registration gaps — users not MFA-registered
  3. Device compliance gaps — non-compliant managed devices

Reads credentials from environment variables (safe for CI/CD):
  ENTRA_TENANT_ID
  ENTRA_CLIENT_ID
  ENTRA_CLIENT_SECRET

Required Microsoft Graph API permissions (application):
  IdentityRiskyUser.Read.All
  UserAuthenticationMethod.Read.All
  DeviceManagementManagedDevices.Read.All

Output: data/risky_users.json

Usage:
  python shared/entra_sync.py
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


def _load_dotenv():
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
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
        f"?$filter=riskLevel%20eq%20'high'%20or%20riskLevel%20eq%20'medium'"
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
        f"?$filter=complianceState%20ne%20'compliant'"
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


# ── Main ──────────────────────────────────────────────────────

def main():
    _load_dotenv()
    parser = argparse.ArgumentParser(description="MediZuva Entra ID sync")
    args = parser.parse_args()

    tenant_id     = os.environ.get("ENTRA_TENANT_ID",     "")
    client_id     = os.environ.get("ENTRA_CLIENT_ID",     "")
    client_secret = os.environ.get("ENTRA_CLIENT_SECRET", "")

    if not all([tenant_id, client_id, client_secret]):
        print("[ERROR] Missing required environment variables.")
        if not tenant_id:     print("  ENTRA_TENANT_ID is not set")
        if not client_id:     print("  ENTRA_CLIENT_ID is not set")
        if not client_secret: print("  ENTRA_CLIENT_SECRET is not set")
        print("\nSet these in your .env file or as repository secrets.")
        sys.exit(1)

    print("\n================================================")
    print(" MediZuva — Entra ID Sync (LIVE)")
    print(f" Tenant : {tenant_id}")
    print(f" Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================\n")

    print("Obtaining access token...")
    token   = get_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}
    print("  [OK] Token obtained\n")

    risky_users = fetch_risky_users(headers)
    mfa_gaps    = fetch_mfa_gaps(headers)
    device_gaps = fetch_device_gaps(headers)

    export = {
        "CheckDate":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tenant":     tenant_id,
        "Mode":       "live",
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
