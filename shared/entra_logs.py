"""
shared/entra_logs.py
============================================================
Retrieves audit and sign-in logs from Microsoft Entra ID
via the Microsoft Graph API and saves them locally.

Logs pulled:
  1. Sign-in logs      — last N days of user sign-ins
  2. Directory audits  — admin/config change events
  3. Risky sign-ins    — Identity Protection flagged sign-ins

Requires environment variables:
  ENTRA_TENANT_ID
  ENTRA_CLIENT_ID
  ENTRA_CLIENT_SECRET

Required Microsoft Graph API permissions (application):
  AuditLog.Read.All

Outputs:
  data/signin_logs/signin_logs.json        — user sign-in events
  data/signin_logs/risky_signins.json      — flagged sign-ins
  data/signin_logs/directory_audits.json   — admin audit trail
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

REPO_ROOT   = Path(__file__).resolve().parents[1]
OUT_DIR     = REPO_ROOT / "data" / "signin_logs"
GRAPH_BASE  = "https://graph.microsoft.com/v1.0"
GRAPH_BETA  = "https://graph.microsoft.com/beta"


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


def graph_get(url: str, headers: dict, max_pages: int = 10) -> list:
    """Paginate through a Graph API endpoint, up to max_pages pages."""
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


# ── 1. Sign-in logs ───────────────────────────────────────────

def fetch_signin_logs(headers: dict, days: int = 7) -> list:
    print(f"[1/3] Fetching sign-in logs (last {days} days)...")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        f"{GRAPH_BASE}/auditLogs/signIns"
        f"?$top=500"
        f"&$filter=createdDateTime ge {since}"
        f"&$select=id,createdDateTime,userDisplayName,userPrincipalName,"
        f"appDisplayName,ipAddress,location,status,riskLevelDuringSignIn,"
        f"riskState,conditionalAccessStatus,clientAppUsed,deviceDetail,mfaDetail"
        f"&$orderby=createdDateTime desc"
    )
    logs = []
    for s in graph_get(url, headers):
        status   = s.get("status", {})
        location = s.get("location", {})
        device   = s.get("deviceDetail", {})
        logs.append({
            "Id":               s.get("id", ""),
            "DateTime":         s.get("createdDateTime", ""),
            "User":             s.get("userDisplayName", ""),
            "UPN":              s.get("userPrincipalName", ""),
            "App":              s.get("appDisplayName", ""),
            "IPAddress":        s.get("ipAddress", ""),
            "City":             location.get("city", ""),
            "Country":          location.get("countryOrRegion", ""),
            "Success":          status.get("errorCode", -1) == 0,
            "FailureReason":    status.get("failureReason", ""),
            "RiskLevel":        s.get("riskLevelDuringSignIn", "none"),
            "RiskState":        s.get("riskState", "none"),
            "CAStatus":         s.get("conditionalAccessStatus", ""),
            "ClientApp":        s.get("clientAppUsed", ""),
            "DeviceName":       device.get("displayName", ""),
            "DeviceOS":         device.get("operatingSystem", ""),
            "DeviceCompliant":  device.get("isCompliant", None),
            "MFADetail":        s.get("mfaDetail"),
        })
    failed  = sum(1 for l in logs if not l["Success"])
    risky   = sum(1 for l in logs if l["RiskLevel"] not in ("none", ""))
    print(f"  Total sign-ins : {len(logs)}")
    print(f"  Failed         : {failed}")
    print(f"  Risky          : {risky}")
    return logs


# ── 2. Risky sign-ins ─────────────────────────────────────────

def fetch_risky_signins(headers: dict, days: int = 7) -> list:
    print(f"[2/3] Fetching risky sign-ins (last {days} days)...")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        f"{GRAPH_BASE}/identityProtection/riskyUsers"
        f"?$select=id,userDisplayName,userPrincipalName,riskLevel,"
        f"riskState,riskLastUpdatedDateTime"
    )
    risky = []
    for u in graph_get(url, headers):
        if u.get("riskLevel") in ("high", "medium"):
            risky.append({
                "UserId":      u.get("id", ""),
                "User":        u.get("userDisplayName", ""),
                "UPN":         u.get("userPrincipalName", ""),
                "RiskLevel":   u.get("riskLevel", ""),
                "RiskState":   u.get("riskState", ""),
                "LastUpdated": u.get("riskLastUpdatedDateTime", ""),
            })
    print(f"  High/medium risk users : {len(risky)}")
    return risky


# ── 3. Directory audits ───────────────────────────────────────

def fetch_directory_audits(headers: dict, days: int = 7) -> list:
    print(f"[3/3] Fetching directory audit logs (last {days} days)...")
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    url = (
        f"{GRAPH_BASE}/auditLogs/directoryAudits"
        f"?$top=500"
        f"&$filter=activityDateTime ge {since}"
        f"&$select=id,activityDateTime,activityDisplayName,category,"
        f"operationType,result,initiatedBy,targetResources,loggedByService"
        f"&$orderby=activityDateTime desc"
    )
    audits = []
    for a in graph_get(url, headers):
        initiated = a.get("initiatedBy", {})
        actor     = (initiated.get("user") or initiated.get("app") or {})
        targets   = [t.get("userPrincipalName") or t.get("displayName", "") for t in a.get("targetResources", [])]
        audits.append({
            "Id":           a.get("id", ""),
            "DateTime":     a.get("activityDateTime", ""),
            "Activity":     a.get("activityDisplayName", ""),
            "Category":     a.get("category", ""),
            "Operation":    a.get("operationType", ""),
            "Result":       a.get("result", ""),
            "Actor":        actor.get("userPrincipalName") or actor.get("displayName", ""),
            "Targets":      targets,
            "Service":      a.get("loggedByService", ""),
        })
    failed = sum(1 for a in audits if a["Result"] == "failure")
    print(f"  Total audit events : {len(audits)}")
    print(f"  Failures           : {failed}")
    return audits


# ── Summary stats ─────────────────────────────────────────────

def build_summary(signin_logs: list, risky_signins: list, directory_audits: list) -> dict:
    total     = len(signin_logs)
    failed    = sum(1 for l in signin_logs if not l["Success"])
    mfa_used  = sum(1 for l in signin_logs if l.get("MFADetail"))
    countries = list({l["Country"] for l in signin_logs if l["Country"]})

    top_apps: dict[str, int] = {}
    for l in signin_logs:
        app = l["App"] or "Unknown"
        top_apps[app] = top_apps.get(app, 0) + 1
    top_apps_list = sorted(top_apps.items(), key=lambda x: x[1], reverse=True)[:5]

    audit_categories: dict[str, int] = {}
    for a in directory_audits:
        c = a["Category"] or "Unknown"
        audit_categories[c] = audit_categories.get(c, 0) + 1

    return {
        "GeneratedAt":      datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "SignInTotal":       total,
        "SignInFailed":      failed,
        "SignInSuccessRate": round((total - failed) / total * 100, 1) if total else 0,
        "MFAUsed":          mfa_used,
        "MFARatePct":       round(mfa_used / total * 100, 1) if total else 0,
        "RiskyUsers":       len(risky_signins),
        "Countries":        countries,
        "TopApps":          [{"App": a, "Count": c} for a, c in top_apps_list],
        "AuditTotal":       len(directory_audits),
        "AuditCategories":  audit_categories,
        "AuditFailures":    sum(1 for a in directory_audits if a["Result"] == "failure"),
    }


# ── Main ──────────────────────────────────────────────────────

def main():
    _load_dotenv()

    tenant_id     = os.environ.get("ENTRA_TENANT_ID",     "")
    client_id     = os.environ.get("ENTRA_CLIENT_ID",     "")
    client_secret = os.environ.get("ENTRA_CLIENT_SECRET", "")

    if not all([tenant_id, client_id, client_secret]):
        print("[ERROR] Missing Entra ID credentials.")
        if not tenant_id:     print("  ENTRA_TENANT_ID is not set")
        if not client_id:     print("  ENTRA_CLIENT_ID is not set")
        if not client_secret: print("  ENTRA_CLIENT_SECRET is not set")
        print("\nSet these in your .env file or as repository secrets.")
        sys.exit(1)

    print("\n================================================")
    print(" MediZuva — Entra ID Log Retrieval")
    print(f" Tenant : {tenant_id}")
    print(f" Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("================================================\n")

    print("Obtaining access token...")
    token   = get_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}"}
    print("  [OK] Token obtained\n")

    signin_logs      = fetch_signin_logs(headers, days=7)
    risky_signins    = fetch_risky_signins(headers, days=7)
    directory_audits = fetch_directory_audits(headers, days=7)
    summary          = build_summary(signin_logs, risky_signins, directory_audits)

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    (OUT_DIR / "signin_logs.json").write_text(
        json.dumps({"RetrievedAt": summary["GeneratedAt"], "Logs": signin_logs}, indent=2),
        encoding="utf-8"
    )
    (OUT_DIR / "risky_signins.json").write_text(
        json.dumps({"RetrievedAt": summary["GeneratedAt"], "RiskyUsers": risky_signins}, indent=2),
        encoding="utf-8"
    )
    (OUT_DIR / "directory_audits.json").write_text(
        json.dumps({"RetrievedAt": summary["GeneratedAt"], "Audits": directory_audits}, indent=2),
        encoding="utf-8"
    )
    (OUT_DIR / "log_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8"
    )

    print(f"\n================================================")
    print(f" RETRIEVAL COMPLETE")
    print(f"  Sign-ins     : {summary['SignInTotal']} ({summary['SignInFailed']} failed)")
    print(f"  MFA usage    : {summary['MFAUsed']} / {summary['SignInTotal']} ({summary['MFARatePct']}%)")
    print(f"  Risky users  : {summary['RiskyUsers']}")
    print(f"  Audit events : {summary['AuditTotal']} ({summary['AuditFailures']} failures)")
    print(f"  Countries    : {', '.join(summary['Countries']) or 'none'}")
    print(f"================================================")
    print(f"\n[OK] Logs saved to {OUT_DIR}")
    print(f"     Next: python dashboard/generate_central_dashboard.py")


if __name__ == "__main__":
    main()
