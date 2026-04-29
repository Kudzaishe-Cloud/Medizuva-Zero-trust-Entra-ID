"""
shared/entra_pim.py
============================================================
Fetches Privileged Identity Management (PIM) role assignments
from Microsoft Entra ID via the Microsoft Graph API and writes
data/pim_audit.json for the central dashboard (Pillar 3).

Fetches:
  1. Eligible assignments  — JIT roles awaiting activation
  2. Active assignments    — currently elevated sessions
  3. Activation history    — last 30 days via audit logs

Requires environment variables:
  ENTRA_TENANT_ID
  ENTRA_CLIENT_ID
  ENTRA_CLIENT_SECRET

Required Graph API permissions (application):
  RoleManagement.Read.All
  AuditLog.Read.All

Output:
  data/pim_audit.json
============================================================
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parents[1]
OUT_PATH   = REPO_ROOT / "data" / "pim_audit.json"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

MANAGED_ROLES = [
    "User Administrator",
    "Privileged Role Administrator",
    "Helpdesk Administrator",
    "Security Administrator",
    "Security Reader",
    "Reports Reader",
]


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


def graph_get(url: str, headers: dict, max_pages: int = 20) -> list:
    items = []
    pages = 0
    while url and pages < max_pages:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
            items += data.get("value", [])
            url = data.get("@odata.nextLink")
            pages += 1
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
    print(" MediZuva — PIM Audit (Pillar 3)")
    print(f" Tenant : {tenant_id}")
    print(f" Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================\n")

    print("Obtaining access token...")
    token   = get_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}
    print("  [OK] Token obtained\n")

    # ── 1. Eligible assignments ───────────────────────────────
    print("[1/3] Fetching eligible PIM assignments...")
    eligible_raw = graph_get(
        f"{GRAPH_BASE}/roleManagement/directory/roleEligibilityScheduleInstances"
        f"?$expand=roleDefinition,principal",
        headers,
    )
    eligible = []
    for e in eligible_raw:
        role_name = (e.get("roleDefinition") or {}).get("displayName", "")
        if role_name not in MANAGED_ROLES:
            continue
        principal = e.get("principal") or {}
        user_name = principal.get("displayName") or e.get("principalId", "")
        eligible.append({
            "User":      user_name,
            "UserId":    e.get("principalId", ""),
            "Role":      role_name,
            "RoleId":    e.get("roleDefinitionId", ""),
            "ScopeId":   e.get("directoryScopeId", ""),
            "StartDate": e.get("startDateTime", ""),
            "EndDate":   e.get("endDateTime", ""),
        })
    print(f"  Eligible (managed roles) : {len(eligible)}")

    # ── 2. Active assignments ─────────────────────────────────
    print("[2/3] Fetching active (elevated) PIM assignments...")
    active_raw = graph_get(
        f"{GRAPH_BASE}/roleManagement/directory/roleAssignmentScheduleInstances"
        f"?$expand=roleDefinition,principal"
        f"&$filter=assignmentType%20eq%20%27Activated%27",
        headers,
    )
    active = []
    for a in active_raw:
        role_name = (a.get("roleDefinition") or {}).get("displayName", "")
        if role_name not in MANAGED_ROLES:
            continue
        principal = a.get("principal") or {}
        user_name = principal.get("displayName") or a.get("principalId", "")
        active.append({
            "User":      user_name,
            "UserId":    a.get("principalId", ""),
            "Role":      role_name,
            "RoleId":    a.get("roleDefinitionId", ""),
            "StartDate": a.get("startDateTime", ""),
            "EndDate":   a.get("endDateTime", "") or "No expiry",
        })
    print(f"  Active elevations        : {len(active)}")

    # ── 3. Activation history (last 30 days) ──────────────────
    print("[3/3] Fetching PIM activation history (last 30 days)...")
    since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    history_raw = graph_get(
        f"{GRAPH_BASE}/auditLogs/directoryAudits"
        f"?$top=200"
        f"&$filter=category%20eq%20%27RoleManagement%27"
        f"%20and%20activityDateTime%20ge%20{since}"
        f"&$select=activityDateTime,activityDisplayName,initiatedBy,targetResources,result",
        headers,
    )
    history = []
    for h in history_raw:
        initiated = h.get("initiatedBy", {})
        actor     = (initiated.get("user") or initiated.get("app") or {})
        targets   = h.get("targetResources", [])
        target    = (targets[0].get("displayName", "") if targets else "")
        history.append({
            "Date":        h.get("activityDateTime", ""),
            "InitiatedBy": actor.get("displayName") or actor.get("userPrincipalName", ""),
            "Activity":    h.get("activityDisplayName", ""),
            "Target":      target,
            "Result":      h.get("result", ""),
        })
    print(f"  Activation history events: {len(history)}")

    # ── Summary ───────────────────────────────────────────────
    unassigned = sum(
        1 for r in MANAGED_ROLES
        if not any(e["Role"] == r for e in eligible)
    )
    if len(eligible) == 0:
        posture = "AT RISK"
    elif unassigned == 0:
        posture = "COMPLIANT"
    else:
        posture = "PARTIAL"

    export = {
        "AuditDate": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tenant":    "micrlabs.onmicrosoft.com",
        "Eligible":  eligible,
        "Active":    active,
        "History":   history,
        "Summary": {
            "TotalEligible":     len(eligible),
            "ActiveNow":         len(active),
            "ActivationsLast30": len(history),
            "UnassignedRoles":   unassigned,
            "Posture":           posture,
        },
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(export, indent=2), encoding="utf-8")

    print(f"\n================================================")
    print(f" PIM AUDIT COMPLETE — Posture: {posture}")
    print(f"  Eligible roles   : {len(eligible)}")
    print(f"  Active elevations: {len(active)}")
    print(f"  History (30d)    : {len(history)}")
    print(f"  Unassigned roles : {unassigned}/6")
    print(f"================================================")
    print(f"\n[OK] PIM audit written to {OUT_PATH}")


if __name__ == "__main__":
    main()
