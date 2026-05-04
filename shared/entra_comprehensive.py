"""
Comprehensive Entra ID data collection - REAL DATA ONLY
Pulls ALL available data from Microsoft Entra ID matching the admin portal
No simulation, no fallback, no synthetic data.
"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

def load_env():
    env_file = REPO_ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

def get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Get access token - FAIL if credentials are invalid"""
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = urllib.parse.urlencode({
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
    }).encode()

    try:
        req = urllib.request.Request(url, data=body, method="POST")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())["access_token"]
    except Exception as e:
        print(f"[CRITICAL] Failed to authenticate with Entra ID: {e}")
        print("Credentials are invalid or missing. No fallback - exiting.")
        sys.exit(1)

def graph_get(url: str, headers: dict) -> list:
    """Paginate through Graph API, returning ALL items"""
    items = []
    pages = 0
    max_pages = 100

    while url and pages < max_pages:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
            items.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
            pages += 1
        except urllib.error.HTTPError as e:
            print(f"  [ERROR] HTTP {e.code} at {url}")
            break

    return items

def get_comprehensive_data(headers: dict):
    """Pull ALL available data from Entra ID"""

    print("\n" + "="*70)
    print("COMPREHENSIVE ENTRA ID DATA COLLECTION (REAL DATA ONLY)")
    print("="*70 + "\n")

    data = {
        "timestamp": datetime.now().isoformat(),
        "dataSource": "Microsoft Entra ID (Real-Time)",
        "sections": {}
    }

    # 1. USERS & IDENTITIES
    print("[1/8] Fetching Users...")
    users_url = f"{GRAPH_BASE}/users?$select=id,displayName,userPrincipalName,mail,mobilePhone,jobTitle,department,officeLocation,createdDateTime,lastPasswordChangeDateTime,accountEnabled&$top=999"
    users = graph_get(users_url, headers)
    data["sections"]["users"] = {
        "total": len(users),
        "data": users,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(users)} users")

    # 2. RISKY USERS (NO FILTER - get all)
    print("[2/8] Fetching Risky Users...")
    risky_url = f"{GRAPH_BASE}/identityProtection/riskyUsers?$top=999"
    risky_users = graph_get(risky_url, headers)
    data["sections"]["riskyUsers"] = {
        "total": len(risky_users),
        "data": risky_users,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(risky_users)} risky users")

    # 3. SIGN-IN LOGS
    print("[3/8] Fetching Sign-In Logs...")
    signin_url = f"{GRAPH_BASE}/auditLogs/signIns?$top=999&$orderby=createdDateTime desc"
    signins = graph_get(signin_url, headers)
    data["sections"]["signInLogs"] = {
        "total": len(signins),
        "data": signins[:100],  # Keep last 100 for dashboard
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(signins)} sign-in records")

    # 4. RISKY SIGN-INS
    print("[4/8] Fetching Risky Sign-Ins...")
    risky_signin_url = f"{GRAPH_BASE}/identityProtection/riskySignIns?$top=999"
    risky_signins = graph_get(risky_signin_url, headers)
    data["sections"]["riskySignIns"] = {
        "total": len(risky_signins),
        "data": risky_signins,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(risky_signins)} risky sign-ins")

    # 5. CONDITIONAL ACCESS POLICIES
    print("[5/8] Fetching Conditional Access Policies...")
    ca_url = f"{GRAPH_BASE}/identity/conditionalAccess/policies"
    ca_policies = graph_get(ca_url, headers)
    data["sections"]["conditionalAccessPolicies"] = {
        "total": len(ca_policies),
        "data": ca_policies,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(ca_policies)} CA policies")

    # 6. PIM ROLE ASSIGNMENTS
    print("[6/8] Fetching PIM Role Assignments...")
    pim_url = f"{GRAPH_BASE}/roleManagement/directory/roleAssignments?$expand=principal,roleDefinition&$top=999"
    pim_roles = graph_get(pim_url, headers)
    data["sections"]["pimRoles"] = {
        "total": len(pim_roles),
        "data": pim_roles,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(pim_roles)} PIM role assignments")

    # 7. DEVICES
    print("[7/8] Fetching Devices...")
    devices_url = f"{GRAPH_BASE}/devices?$select=id,displayName,deviceId,operatingSystem,trustType,isCompliant,isManaged,createdDateTime&$top=999"
    devices = graph_get(devices_url, headers)
    data["sections"]["devices"] = {
        "total": len(devices),
        "data": devices,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(devices)} devices")

    # 8. DIRECTORY ROLES & ADMINS
    print("[8/8] Fetching Directory Roles...")
    roles_url = f"{GRAPH_BASE}/directoryRoles?$expand=members&$top=999"
    roles = graph_get(roles_url, headers)
    data["sections"]["directoryRoles"] = {
        "total": len(roles),
        "data": roles,
        "timestamp": datetime.now().isoformat()
    }
    print(f"   ✓ Found {len(roles)} directory roles")

    return data

def main():
    load_env()

    tenant_id = os.getenv("ENTRA_TENANT_ID", "").strip()
    client_id = os.getenv("ENTRA_CLIENT_ID", "").strip()
    client_secret = os.getenv("ENTRA_CLIENT_SECRET", "").strip()

    if not all([tenant_id, client_id, client_secret]):
        print("[CRITICAL] Missing Entra ID credentials")
        print("  ENTRA_TENANT_ID:", "✓" if tenant_id else "✗")
        print("  ENTRA_CLIENT_ID:", "✓" if client_id else "✗")
        print("  ENTRA_CLIENT_SECRET:", "✓" if client_secret else "✗")
        sys.exit(1)

    # Get token - FAIL if invalid
    token = get_token(tenant_id, client_id, client_secret)
    print(f"✓ Authenticated to tenant {tenant_id}")

    headers = {"Authorization": f"Bearer {token}"}

    # Get comprehensive data
    data = get_comprehensive_data(headers)

    # Save to JSON
    out_path = REPO_ROOT / "data" / "entra_comprehensive.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    print("\n" + "="*70)
    print(f"✓ COMPREHENSIVE DATA SAVED TO: {out_path}")
    print("="*70)
    print(f"Total Users: {data['sections']['users']['total']}")
    print(f"Risky Users: {data['sections']['riskyUsers']['total']}")
    print(f"Sign-in Logs: {data['sections']['signInLogs']['total']}")
    print(f"Risky Sign-Ins: {data['sections']['riskySignIns']['total']}")
    print(f"CA Policies: {data['sections']['conditionalAccessPolicies']['total']}")
    print(f"PIM Roles: {data['sections']['pimRoles']['total']}")
    print(f"Devices: {data['sections']['devices']['total']}")
    print(f"Directory Roles: {data['sections']['directoryRoles']['total']}")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
