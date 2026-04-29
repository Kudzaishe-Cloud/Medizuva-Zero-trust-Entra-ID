# generate_personas.py
# ============================================================
# PURPOSE: Fetch real MediZuva staff accounts from Microsoft Entra ID
#          via Microsoft Graph API and save as the canonical personas CSV
#          used by every downstream pillar script.
#
# Requires environment variables:
#   ENTRA_TENANT_ID     — Azure AD tenant ID
#   ENTRA_CLIENT_ID     — App registration client ID
#   ENTRA_CLIENT_SECRET — App registration client secret
#
# Required Microsoft Graph API permissions (application):
#   User.Read.All
#   Directory.Read.All
#
# The following fields are initialised to safe defaults and are
# updated by later pipeline stages:
#   RiskScore       — set to 0; updated by pillar4_threat/threat_audit.py
#   DeviceCompliant — set to True; updated by shared/entra_sync.py
#   MFARegistered   — set to True; updated by shared/entra_sync.py
#   HIBPExposed     — set to False; updated by pillar4_threat/osint_exposure_check.py
#   HIBPBreachCount — set to 0; updated by pillar4_threat/osint_exposure_check.py
# ============================================================

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path


def _load_dotenv():
    env_file = Path(__file__).resolve().parents[1] / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
import pandas as pd
from datetime import datetime
from pathlib import Path

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from shared.schemas import LOCATIONS

REPO_ROOT  = Path(__file__).resolve().parents[1]
OUT_PATH   = REPO_ROOT / "data" / "personas" / "medizuva_500_personas.csv"
GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# Map known MediZuva office cities to their verified GPS coordinates.
# These coordinates are sourced from shared/schemas.py and reference
# real Zimbabwean cities — verifiable via any public mapping service.
OFFICE_COORDS = {city: (cfg["lat"], cfg["lon"]) for city, cfg in LOCATIONS.items()}


def get_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain an OAuth 2.0 access token via client_credentials grant."""
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
    """Paginate through a Graph API endpoint and return all items."""
    items = []
    while url:
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
            items += data.get("value", [])
            url = data.get("@odata.nextLink")
        except urllib.error.HTTPError as e:
            print(f"  [ERROR] Graph API call failed: HTTP {e.code} — {e.reason}")
            print(f"  URL: {url}")
            sys.exit(1)
    return items


def lookup_coords(office_location: str) -> tuple[float, float]:
    """
    Return (lat, lon) for a known MediZuva office city.
    If the officeLocation field does not match any known city, returns (0.0, 0.0).
    """
    if not office_location:
        return 0.0, 0.0
    for city, (lat, lon) in OFFICE_COORDS.items():
        if city.lower() in office_location.lower():
            return lat, lon
    return 0.0, 0.0


def is_service_account(upn: str) -> bool:
    """
    Exclude non-human accounts from the personas CSV.
    Service accounts and external guests typically contain these markers.
    """
    markers = ["#EXT#", "$", "svc-", "svc_", ".bot@", ".system@"]
    return any(m in upn for m in markers)


def main():
    _load_dotenv()
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

    print("=" * 60)
    print(" MediZuva — Entra ID User Fetch")
    print(f" Tenant : {tenant_id}")
    print(f" Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    print("Obtaining access token...")
    try:
        token = get_token(tenant_id, client_id, client_secret)
    except urllib.error.HTTPError as e:
        print(f"  [ERROR] Token request failed: HTTP {e.code} — {e.reason}")
        print("  Check ENTRA_CLIENT_ID and ENTRA_CLIENT_SECRET are correct.")
        sys.exit(1)
    headers = {"Authorization": f"Bearer {token}"}
    print("  [OK] Token obtained\n")

    # Fetch all enabled user accounts with the fields we need.
    # employeeHireDate requires the HR data extension; falls back to createdDateTime.
    print("Fetching users from Entra ID (this may take a moment)...")
    url = (
        f"{GRAPH_BASE}/users"
        f"?$select=id,givenName,surname,userPrincipalName,department,jobTitle"
        f",officeLocation,employeeHireDate,createdDateTime,accountEnabled"
        f"&$filter=accountEnabled%20eq%20true"
        f"&$top=999"
    )
    raw_users = graph_get(url, headers)
    print(f"  Retrieved {len(raw_users)} active accounts from Entra ID\n")

    rows = []
    skipped = 0
    emp_num = 1

    for u in raw_users:
        upn = u.get("userPrincipalName", "")
        if is_service_account(upn):
            skipped += 1
            continue

        first = (u.get("givenName")  or "").strip()
        last  = (u.get("surname")    or "").strip()

        # Use UPN prefix as display name for accounts missing givenName/surname
        if not first and not last:
            first = upn.split("@")[0]

        office   = (u.get("officeLocation") or "").strip()
        lat, lon = lookup_coords(office)

        # Prefer employeeHireDate (HR-managed); fall back to account creation date
        hire_date = u.get("employeeHireDate") or u.get("createdDateTime") or ""
        if hire_date:
            hire_date = hire_date[:10]  # ISO date: YYYY-MM-DD

        rows.append({
            "EmployeeID":      f"MZ{emp_num:04d}",
            "FirstName":       first,
            "LastName":        last,
            "Email":           upn,
            "Department":      (u.get("department") or "Unassigned").strip(),
            "JobTitle":        (u.get("jobTitle")   or "Unassigned").strip(),
            "Location":        office or "Unknown",
            "Latitude":        lat,
            "Longitude":       lon,
            # These are default values — updated by later pipeline stages
            "RiskScore":       0,
            "DeviceCompliant": True,
            "MFARegistered":   True,
            "AccountStatus":   "Active",
            "HIBPExposed":     False,
            "HIBPBreachCount": 0,
            "HireDate":        hire_date,
            "CreatedDate":     datetime.now().isoformat(),
        })
        emp_num += 1

    if not rows:
        print("[ERROR] No user records were returned from Entra ID.")
        print("  Verify the app registration has User.Read.All permission.")
        sys.exit(1)

    df = pd.DataFrame(rows)
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT_PATH, index=False)

    print(f"[OK] {len(df)} real user accounts saved to: {OUT_PATH}")
    if skipped:
        print(f"     {skipped} service/guest accounts excluded")
    print("\nDepartment breakdown:")
    print(df["Department"].value_counts().to_string())
    print("\nFirst 3 UPNs fetched:")
    print(df["Email"].head(3).to_string(index=False))
    print("\nNext: python shared/entra_sync.py")


if __name__ == "__main__":
    main()
