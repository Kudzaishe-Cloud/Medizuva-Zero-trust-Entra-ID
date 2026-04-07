"""
pillar3_pim/validate_pim.py
============================================================
Validates that every MediZuva IT staff member has the correct
eligible PIM roles assigned in Entra ID.

Approach (mirrors pillar1_identity/validate_provisioning.py):
  1. Load expected assignments from the personas CSV + role map
  2. Query Entra ID for actual eligible PIM assignments
  3. Compare expected vs actual
  4. Emit a PASS/FAIL report and save evidence to data/

Usage:
    python validate_pim.py

Output:
    data/pim_validation_report.txt
    data/pim_validation_issues.csv  (only if issues found)
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

import pandas as pd

# ── Config ────────────────────────────────────────────────────
TENANT_ID     = os.environ["ENTRA_TENANT_ID"]
CLIENT_ID     = os.environ["ENTRA_CLIENT_ID"]
CLIENT_SECRET = os.environ["ENTRA_CLIENT_SECRET"]

REPO_ROOT     = Path(__file__).resolve().parents[1]
PERSONAS_CSV  = REPO_ROOT / "data" / "personas" / "medizuva_500_personas.csv"
REPORT_OUT    = REPO_ROOT / "data" / "pim_validation_report.txt"
ISSUES_OUT    = REPO_ROOT / "data" / "pim_validation_issues.csv"

# Must match assign_pim_roles.ps1 exactly
TITLE_ROLE_MAP = {
    "IT Administrator": ["User Administrator", "Privileged Role Administrator"],
    "Help Desk":        ["Helpdesk Administrator"],
    "Security Analyst": ["Security Administrator", "Security Reader"],
    "Network Engineer": ["Reports Reader"],
}

ROLE_IDS = {
    "User Administrator":            "fe930be7-5e62-47db-91af-98c3a49a38b1",
    "Privileged Role Administrator": "e8611ab8-c189-46e8-94e1-60213ab1f814",
    "Helpdesk Administrator":        "729827e3-9c14-49f7-bb1b-9608f156bbb8",
    "Security Administrator":        "194ae4cb-b126-40b2-bd5b-6091b380977d",
    "Security Reader":               "5d6b6bb7-de71-4623-b4af-96380a352509",
    "Reports Reader":                "4a5d8f65-41da-4de4-8968-e035b65339cf",
}
# Reverse map for display
ROLE_NAMES = {v: k for k, v in ROLE_IDS.items()}


# ── Auth ──────────────────────────────────────────────────────
def get_token() -> str:
    print("Obtaining access token...", end=" ", flush=True)
    data = urllib.parse.urlencode({
        "grant_type":    "client_credentials",
        "client_id":     CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope":         "https://graph.microsoft.com/.default",
    }).encode()
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
        data=data, method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        token = json.loads(resp.read())["access_token"]
    print("[OK]")
    return token


def graph_get(token: str, url: str) -> dict:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


# ── Build expected assignments ────────────────────────────────
def build_expected(personas_csv: Path) -> dict:
    """Returns {upn: [role_name, ...]} for all IT staff."""
    df = pd.read_csv(personas_csv)
    it = df[df["Department"] == "IT"]
    expected = {}
    for _, row in it.iterrows():
        upn   = row["Email"].lower()
        title = row["JobTitle"]
        roles = TITLE_ROLE_MAP.get(title, [])
        if roles:
            expected[upn] = {"title": title, "roles": roles}
    return expected


# ── Fetch actual PIM eligible assignments ─────────────────────
def fetch_actual_eligible(token: str) -> dict:
    """Returns {(principalId, roleDefinitionId): True}."""
    print("Fetching PIM eligible assignments from Entra ID...", end=" ", flush=True)
    url = (
        "https://graph.microsoft.com/v1.0/roleManagement/directory"
        "/roleEligibilityScheduleInstances"
        "?$expand=principal&$select=principalId,roleDefinitionId,principal"
    )
    assignments = {}
    while url:
        page = graph_get(token, url)
        for item in page.get("value", []):
            pid  = item["principalId"]
            rid  = item["roleDefinitionId"]
            upn  = (item.get("principal") or {}).get("userPrincipalName", "").lower()
            assignments[(pid, rid)] = upn
        url = page.get("@odata.nextLink")
    print(f"[OK] — {len(assignments)} total eligible assignments found")
    return assignments


def fetch_user_ids(token: str, upns: list) -> dict:
    """Returns {upn: objectId} for the given list of UPNs."""
    print(f"Resolving {len(upns)} user IDs from Entra ID...")
    lookup = {}
    for upn in upns:
        try:
            encoded = urllib.parse.quote(upn)
            data = graph_get(token, f"https://graph.microsoft.com/v1.0/users/{encoded}?$select=id,userPrincipalName")
            lookup[upn] = data["id"]
        except urllib.error.HTTPError:
            lookup[upn] = None
    found = sum(1 for v in lookup.values() if v)
    print(f"  Resolved {found}/{len(upns)} users")
    return lookup


# ── Validate ──────────────────────────────────────────────────
def validate(expected: dict, actual_assignments: dict, user_ids: dict) -> list:
    """Returns list of issue dicts."""
    # Build a set of (userId, roleId) for fast lookup
    actual_set = set(actual_assignments.keys())

    issues = []
    for upn, info in expected.items():
        uid = user_ids.get(upn)
        if not uid:
            for role in info["roles"]:
                issues.append({
                    "UPN":      upn,
                    "Title":    info["title"],
                    "Role":     role,
                    "Issue":    "User not found in Entra ID",
                })
            continue

        for role in info["roles"]:
            rid = ROLE_IDS[role]
            if (uid, rid) not in actual_set:
                issues.append({
                    "UPN":   upn,
                    "Title": info["title"],
                    "Role":  role,
                    "Issue": "Eligible assignment missing in PIM",
                })

    return issues


# ── Main ──────────────────────────────────────────────────────
def main():
    print("\n=================================================")
    print(" MediZuva - PIM Validation (Pillar 3)")
    print(f" Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=================================================\n")

    # 1. Expected
    print(f"Loading personas from {PERSONAS_CSV.name}...")
    expected = build_expected(PERSONAS_CSV)
    total_expected = sum(len(v["roles"]) for v in expected.values())
    print(f"  IT staff: {len(expected)} users | Expected assignments: {total_expected}\n")

    # 2. Auth + fetch
    try:
        token = get_token()
    except Exception as e:
        print(f"[FAIL] Could not obtain token: {e}")
        sys.exit(1)

    user_ids         = fetch_user_ids(token, list(expected.keys()))
    actual_eligible  = fetch_actual_eligible(token)

    # 3. Compare
    print("\nComparing expected vs actual...")
    issues = validate(expected, actual_eligible, user_ids)

    covered   = total_expected - len(issues)
    accuracy  = (covered / total_expected * 100) if total_expected else 0
    result    = "PASS" if accuracy == 100.0 else "FAIL"

    # 4. Report
    report = f"""
=== MEDIZUVA PIM VALIDATION REPORT ===
Date:                 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
IT staff validated:   {len(expected)}
Expected assignments: {total_expected}
Issues found:         {len(issues)}
Coverage:             {accuracy:.2f}%
Target:               100.00%
Result:               {result}
=======================================
"""

    print(report)
    REPORT_OUT.write_text(report, encoding="utf-8")
    print(f"Report saved: {REPORT_OUT}")

    if issues:
        df_issues = pd.DataFrame(issues)
        df_issues.to_csv(ISSUES_OUT, index=False)
        print(f"Issues saved: {ISSUES_OUT}")
        print("\nFirst 10 issues:")
        print(df_issues.head(10).to_string(index=False))
    else:
        print("No issues — all eligible PIM assignments confirmed in Entra ID.")
        print("pim_validation_report.txt saved as Pillar 3 evidence.")

    sys.exit(0 if result == "PASS" else 1)


if __name__ == "__main__":
    main()
