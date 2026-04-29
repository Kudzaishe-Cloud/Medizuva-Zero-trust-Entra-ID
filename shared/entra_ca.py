"""
shared/entra_ca.py
============================================================
Fetches Conditional Access policy state from Microsoft Entra
ID via the Microsoft Graph API and writes data/ca_audit.json
for the central dashboard (Pillar 2).

Requires environment variables:
  ENTRA_TENANT_ID
  ENTRA_CLIENT_ID
  ENTRA_CLIENT_SECRET

Required Graph API permission (application):
  Policy.Read.All

Output:
  data/ca_audit.json
============================================================
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parents[1]
OUT_PATH   = REPO_ROOT / "data" / "ca_audit.json"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

EXPECTED_POLICIES = [
    "MZV-CA001-RequireMFA-AllUsers",
    "MZV-CA002-BlockLegacyAuth",
    "MZV-CA003-RequireCompliantDevice-Clinical",
    "MZV-CA004-BlockHighRiskSignin",
    "MZV-CA005-RequireMFAAndDevice-Admins",
    "MZV-CA006-SessionControl-8h",
]

STATE_MAP = {
    "enabled":                           "ENFORCED",
    "enabledForReportingButNotEnforced": "REPORT-ONLY",
    "disabled":                          "DISABLED",
}


def _load_dotenv():
    env_file = REPO_ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())


def get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
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
    items = []
    while url:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
            items += data.get("value", [])
            url = data.get("@odata.nextLink")
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            print(f"  [WARN] Graph query failed — HTTP {e.code}: {body[:200]}")
            break
    return items


def main():
    _load_dotenv()

    tenant_id     = os.environ.get("ENTRA_TENANT_ID",     "")
    client_id     = os.environ.get("ENTRA_CLIENT_ID",     "")
    client_secret = os.environ.get("ENTRA_CLIENT_SECRET", "")

    if not all([tenant_id, client_id, client_secret]):
        print("[ERROR] Missing Entra ID credentials (ENTRA_TENANT_ID / ENTRA_CLIENT_ID / ENTRA_CLIENT_SECRET).")
        sys.exit(1)

    print("\n================================================")
    print(" MediZuva — Conditional Access Audit (Pillar 2)")
    print(f" Tenant : {tenant_id}")
    print(f" Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================\n")

    print("Obtaining access token...")
    token   = get_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}
    print("  [OK] Token obtained\n")

    # Total user count (best-effort)
    try:
        req = urllib.request.Request(
            f"{GRAPH_BASE}/users?$count=true&$top=1",
            headers={**headers, "ConsistencyLevel": "eventual"},
        )
        with urllib.request.urlopen(req) as resp:
            total_users = json.loads(resp.read()).get("@odata.count", 500)
    except Exception:
        total_users = 500

    # Fetch all CA policies
    print("Fetching Conditional Access policies...")
    all_policies = graph_get(
        f"{GRAPH_BASE}/identity/conditionalAccess/policies", headers
    )
    policy_map = {p["displayName"]: p for p in all_policies}
    print(f"  Retrieved {len(all_policies)} policies from Entra ID\n")

    policies = []
    for name in EXPECTED_POLICIES:
        if name not in policy_map:
            print(f"  [MISSING]     {name}")
            policies.append({
                "PolicyName": name,
                "State":      "MISSING",
                "Id":         "",
                "CreatedAt":  "",
                "ModifiedAt": "",
            })
        else:
            p     = policy_map[name]
            state = STATE_MAP.get(p.get("state", ""), "DISABLED")
            print(f"  [{state:<12}] {name}")
            policies.append({
                "PolicyName": name,
                "State":      state,
                "Id":         p.get("id", ""),
                "CreatedAt":  p.get("createdDateTime", ""),
                "ModifiedAt": p.get("modifiedDateTime", ""),
            })

    enforced    = sum(1 for p in policies if p["State"] == "ENFORCED")
    report_only = sum(1 for p in policies if p["State"] == "REPORT-ONLY")
    disabled    = sum(1 for p in policies if p["State"] == "DISABLED")
    missing     = sum(1 for p in policies if p["State"] == "MISSING")
    total       = len(EXPECTED_POLICIES)
    coverage    = round(enforced / total * 100, 1) if total else 0

    if missing == 0 and disabled == 0 and enforced > 0:
        posture = "COMPLIANT"
    elif missing > 0 or disabled > 2:
        posture = "AT RISK"
    else:
        posture = "PARTIAL"

    export = {
        "AuditDate":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tenant":     "micrlabs.onmicrosoft.com",
        "TotalUsers": total_users,
        "Policies":   policies,
        "Summary": {
            "Enforced":   enforced,
            "ReportOnly": report_only,
            "Disabled":   disabled,
            "Missing":    missing,
            "Total":      total,
            "Coverage":   coverage,
            "Posture":    posture,
        },
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(export, indent=2), encoding="utf-8")

    print(f"\n================================================")
    print(f" CA AUDIT COMPLETE — Posture: {posture}")
    print(f"  Enforced    : {enforced}/{total}")
    print(f"  Report-only : {report_only}")
    print(f"  Disabled    : {disabled}")
    print(f"  Missing     : {missing}")
    print(f"  Coverage    : {coverage}%")
    print(f"================================================")
    print(f"\n[OK] CA audit written to {OUT_PATH}")


if __name__ == "__main__":
    main()
