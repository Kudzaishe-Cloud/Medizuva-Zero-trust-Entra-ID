"""
pillar2_access/dashboard/generate_dashboard.py
============================================================
Reads the CA audit JSON produced by audit_ca_policies.ps1
and generates a self-contained HTML dashboard.

Usage:
    python generate_dashboard.py
    python generate_dashboard.py --audit path/to/ca_audit.json
    python generate_dashboard.py --out path/to/report.html

Output: data/ca_dashboard.html (open in any browser)
============================================================
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parents[2]
AUDIT_JSON = REPO_ROOT / "data" / "ca_audit.json"
OUT_HTML   = REPO_ROOT / "data" / "ca_dashboard.html"


# ─────────────────────────────────────────────────────────────
# Colours / badges
# ─────────────────────────────────────────────────────────────

STATE_BADGE = {
    "ENFORCED":    ('<span class="badge enforced">ENFORCED</span>',    "#10b981"),
    "REPORT-ONLY": ('<span class="badge report">REPORT ONLY</span>',   "#f59e0b"),
    "DISABLED":    ('<span class="badge disabled">DISABLED</span>',    "#ef4444"),
    "MISSING":     ('<span class="badge missing">MISSING</span>',      "#6b7280"),
}

POSTURE_COLOUR = {
    "COMPLIANT": "#10b981",
    "PARTIAL":   "#f59e0b",
    "AT RISK":   "#ef4444",
}

POLICY_DESCRIPTIONS = {
    "MZV-CA001-RequireMFA-AllUsers":
        "Requires multi-factor authentication for every user on every cloud app. Zero-trust baseline.",
    "MZV-CA002-BlockLegacyAuth":
        "Blocks legacy protocols (SMTP/IMAP/POP3/ActiveSync) that cannot enforce MFA.",
    "MZV-CA003-RequireCompliantDevice-Clinical":
        "Clinical, Pharmacy and Radiology staff must use an Intune-compliant device to access patient data.",
    "MZV-CA004-BlockHighRiskSignin":
        "Blocks any sign-in flagged as high-risk by Entra ID Identity Protection (likely compromise).",
    "MZV-CA005-RequireMFAAndDevice-Admins":
        "IT administrators must satisfy both MFA AND a compliant device — the strictest gate.",
    "MZV-CA006-SessionControl-8h":
        "Forces re-authentication every 8 hours and disables persistent browser sessions.",
}


# ─────────────────────────────────────────────────────────────
# HTML generation
# ─────────────────────────────────────────────────────────────

def policy_rows(policies: list) -> str:
    rows = []
    for p in policies:
        badge_html, _ = STATE_BADGE.get(p["State"], ('<span class="badge missing">UNKNOWN</span>', "#6b7280"))
        desc = POLICY_DESCRIPTIONS.get(p["PolicyName"], "—")
        modified = p.get("ModifiedAt", "") or "—"
        if modified and modified != "—":
            try:
                modified = datetime.fromisoformat(modified.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except ValueError:
                pass
        rows.append(f"""
        <tr>
            <td class="policy-name">{p['PolicyName']}</td>
            <td>{badge_html}</td>
            <td class="desc">{desc}</td>
            <td class="date">{modified}</td>
        </tr>""")
    return "\n".join(rows)


def stat_card(label: str, value, colour: str, subtitle: str = "") -> str:
    return f"""
    <div class="stat-card" style="border-top: 4px solid {colour};">
        <div class="stat-value" style="color:{colour};">{value}</div>
        <div class="stat-label">{label}</div>
        {"<div class='stat-sub'>" + subtitle + "</div>" if subtitle else ""}
    </div>"""


def build_html(data: dict) -> str:
    s        = data["Summary"]
    policies = data["Policies"]
    posture  = s["Posture"]
    p_colour = POSTURE_COLOUR.get(posture, "#6b7280")
    audit_date = data.get("AuditDate", "unknown")

    cards = (
        stat_card("Enforced",    s["Enforced"],   "#10b981", "Active enforcement") +
        stat_card("Report-Only", s["ReportOnly"], "#f59e0b", "Monitoring only") +
        stat_card("Disabled",    s["Disabled"],   "#ef4444", "Not active") +
        stat_card("Missing",     s["Missing"],    "#6b7280", "Not deployed") +
        stat_card("Coverage",    f"{s['Coverage']}%", p_colour, "Enforced policies") +
        stat_card("Total Users", data.get("TotalUsers", "—"), "#3b82f6", data.get("Tenant", ""))
    )

    rows = policy_rows(policies)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MediZuva — Conditional Access Dashboard</title>
<style>
  :root {{
    --bg: #0f172a; --surface: #1e293b; --surface2: #263347;
    --text: #f1f5f9; --muted: #94a3b8; --border: #334155;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
         font-size: 14px; line-height: 1.5; }}
  header {{ background: var(--surface); border-bottom: 1px solid var(--border);
            padding: 20px 32px; display: flex; align-items: center; gap: 20px; }}
  header h1 {{ font-size: 20px; font-weight: 700; }}
  header .sub {{ color: var(--muted); font-size: 13px; }}
  .posture-badge {{
    margin-left: auto; padding: 6px 18px; border-radius: 999px;
    font-weight: 700; font-size: 13px;
    background: {p_colour}22; color: {p_colour}; border: 1px solid {p_colour};
  }}
  main {{ padding: 28px 32px; max-width: 1300px; margin: 0 auto; }}
  h2 {{ font-size: 13px; font-weight: 600; letter-spacing: .08em;
        text-transform: uppercase; color: var(--muted); margin-bottom: 16px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 16px; margin-bottom: 36px; }}
  .stat-card {{ background: var(--surface); border-radius: 10px; padding: 20px 18px; }}
  .stat-value {{ font-size: 32px; font-weight: 800; margin-bottom: 4px; }}
  .stat-label {{ font-size: 13px; font-weight: 600; color: var(--text); }}
  .stat-sub {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .table-wrap {{ background: var(--surface); border-radius: 10px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{ background: var(--surface2); padding: 12px 16px; text-align: left;
              font-size: 12px; font-weight: 600; letter-spacing: .06em;
              text-transform: uppercase; color: var(--muted); }}
  tbody tr {{ border-top: 1px solid var(--border); }}
  tbody tr:hover {{ background: var(--surface2); }}
  tbody td {{ padding: 14px 16px; vertical-align: top; }}
  .policy-name {{ font-family: 'Cascadia Code', 'Consolas', monospace;
                  font-size: 12px; white-space: nowrap; color: #93c5fd; }}
  .desc {{ color: var(--muted); font-size: 13px; max-width: 420px; }}
  .date {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px;
            font-size: 11px; font-weight: 700; letter-spacing: .05em; }}
  .badge.enforced  {{ background: #10b98122; color: #10b981; }}
  .badge.report    {{ background: #f59e0b22; color: #f59e0b; }}
  .badge.disabled  {{ background: #ef444422; color: #ef4444; }}
  .badge.missing   {{ background: #6b728022; color: #94a3b8; }}
  footer {{ text-align: center; padding: 28px; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>

<header>
  <div>
    <h1>MediZuva — Conditional Access Dashboard</h1>
    <div class="sub">Pillar 2: Access Management &nbsp;|&nbsp; Tenant: {data.get('Tenant', '—')} &nbsp;|&nbsp; Audited: {audit_date}</div>
  </div>
  <div class="posture-badge">Zero-Trust Posture: {posture}</div>
</header>

<main>
  <h2>Coverage Metrics</h2>
  <div class="stats">{cards}</div>

  <h2>Conditional Access Policies</h2>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Policy Name</th>
          <th>State</th>
          <th>Purpose</th>
          <th>Last Modified</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>
</main>

<footer>
  MediZuva Zero-Trust Framework &mdash; Pillar 2: Access Management &mdash; Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</footer>

</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate MediZuva CA dashboard")
    parser.add_argument("--audit", default=str(AUDIT_JSON), help="Path to ca_audit.json")
    parser.add_argument("--out",   default=str(OUT_HTML),   help="Output HTML path")
    args = parser.parse_args()

    audit_path = Path(args.audit)
    if not audit_path.exists():
        print(f"[ERROR] Audit file not found: {audit_path}")
        print("        Run audit_ca_policies.ps1 first to generate it.")
        sys.exit(1)

    with open(audit_path, encoding="utf-8-sig") as f:
        data = json.load(f)

    # audit_ca_policies.ps1 wraps Policies as a list of objects —
    # handle both list-of-dicts and list-of-PSCustomObject exports
    if isinstance(data.get("Policies"), dict):
        # Single policy exported without array — wrap it
        data["Policies"] = [data["Policies"]]

    html = build_html(data)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    print(f"[OK] Dashboard written to: {out_path}")
    print(f"     Open in browser: file:///{out_path.as_posix()}")


if __name__ == "__main__":
    main()
