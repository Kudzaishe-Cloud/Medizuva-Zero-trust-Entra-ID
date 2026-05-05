"""
pillar3_pim/dashboard/generate_dashboard.py
============================================================
Reads the PIM audit JSON produced by audit_pim_roles.ps1
and generates a self-contained HTML dashboard.

Usage:
    python generate_dashboard.py
    python generate_dashboard.py --audit path/to/pim_audit.json
    python generate_dashboard.py --out path/to/report.html

Output: data/pim_dashboard.html (open in any browser)
============================================================
"""

import argparse
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parents[2]
AUDIT_JSON  = REPO_ROOT / "data" / "pim_audit.json"
OUT_HTML    = REPO_ROOT / "data" / "pim_dashboard.html"

POSTURE_COLOUR = {
    "COMPLIANT": "#10b981",
    "PARTIAL":   "#f59e0b",
    "AT RISK":   "#ef4444",
}

ROLE_DESCRIPTIONS = {
    "User Administrator":            "Create/manage users and groups. Assigned to IT Administrators.",
    "Privileged Role Administrator": "Manage role assignments in Entra ID. Highest-risk role — IT Admins only.",
    "Helpdesk Administrator":        "Reset passwords and manage service requests. Help Desk staff.",
    "Security Administrator":        "Configure security policies and review alerts. Security Analysts.",
    "Security Reader":               "Read-only access to security centre. Security Analysts.",
    "Reports Reader":                "Read usage and audit reports. Network Engineers.",
}


# ─────────────────────────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────────────────────────

def stat_card(label: str, value, colour: str, subtitle: str = "") -> str:
    return f"""
    <div class="stat-card" style="border-top: 4px solid {colour};">
        <div class="stat-value" style="color:{colour};">{value}</div>
        <div class="stat-label">{label}</div>
        {"<div class='stat-sub'>" + subtitle + "</div>" if subtitle else ""}
    </div>"""


def eligible_rows(eligible: list) -> str:
    if not eligible:
        return '<tr><td colspan="4" style="text-align:center;color:var(--muted);">No eligible assignments found</td></tr>'
    rows = []
    for e in eligible:
        desc = ROLE_DESCRIPTIONS.get(e.get("Role", ""), "—")
        end  = e.get("EndDate") or "No expiry"
        rows.append(f"""
        <tr>
            <td class="mono">{e.get('User', '—')}</td>
            <td class="role">{e.get('Role', '—')}</td>
            <td class="desc">{desc}</td>
            <td class="date">{end}</td>
        </tr>""")
    return "\n".join(rows)


def active_rows(active: list) -> str:
    if not active:
        return '<tr><td colspan="3" style="text-align:center;color:var(--muted);">No active elevations right now — good.</td></tr>'
    rows = []
    for a in active:
        end = a.get("EndDate") or "No expiry"
        rows.append(f"""
        <tr>
            <td class="mono">{a.get('User', '—')}</td>
            <td class="role">{a.get('Role', '—')}</td>
            <td class="date">{end}</td>
        </tr>""")
    return "\n".join(rows)


def role_coverage_rows(eligible: list) -> str:
    role_counts = Counter(e.get("Role", "") for e in eligible)
    rows = []
    for role, desc in ROLE_DESCRIPTIONS.items():
        count = role_counts.get(role, 0)
        colour = "#10b981" if count > 0 else "#f59e0b"
        bar_w  = min(100, count * 10)
        rows.append(f"""
        <tr>
            <td class="role">{role}</td>
            <td class="desc">{desc}</td>
            <td>
                <div style="display:flex;align-items:center;gap:10px;">
                    <div style="background:var(--surface2);border-radius:4px;width:100px;height:8px;overflow:hidden;">
                        <div style="background:{colour};width:{bar_w}%;height:100%;border-radius:4px;"></div>
                    </div>
                    <span style="color:{colour};font-weight:700;">{count}</span>
                </div>
            </td>
        </tr>""")
    return "\n".join(rows)


def build_html(data: dict) -> str:
    s        = data.get("Summary", {})
    eligible = data.get("Eligible", []) or []
    active   = data.get("Active",   []) or []
    posture  = s.get("Posture", "PARTIAL")
    p_colour = POSTURE_COLOUR.get(posture, "#6b7280")
    audit_date = data.get("AuditDate", "unknown")

    cards = (
        stat_card("Eligible",         s.get("TotalEligible", 0),      "#3b82f6", "JIT role assignments") +
        stat_card("Active Now",        s.get("ActiveNow", 0),          "#f59e0b", "Currently elevated") +
        stat_card("Activations (30d)", s.get("ActivationsLast30", 0),  "#8b5cf6", "Last 30 days") +
        stat_card("Unassigned Roles",  s.get("UnassignedRoles", 0),    "#ef4444" if s.get("UnassignedRoles", 0) > 0 else "#10b981", "Roles with no eligible users")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MediZuva — PIM Dashboard</title>
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
        text-transform: uppercase; color: var(--muted); margin: 0 0 16px; }}
  .section {{ margin-bottom: 36px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 16px; }}
  .stat-card {{ background: var(--surface); border-radius: 10px; padding: 20px 18px; }}
  .stat-value {{ font-size: 32px; font-weight: 800; margin-bottom: 4px; }}
  .stat-label {{ font-size: 13px; font-weight: 600; }}
  .stat-sub {{ font-size: 11px; color: var(--muted); margin-top: 2px; }}
  .table-wrap {{ background: var(--surface); border-radius: 10px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{ background: var(--surface2); padding: 12px 16px; text-align: left;
              font-size: 12px; font-weight: 600; letter-spacing: .06em;
              text-transform: uppercase; color: var(--muted); }}
  tbody tr {{ border-top: 1px solid var(--border); }}
  tbody tr:hover {{ background: var(--surface2); }}
  tbody td {{ padding: 13px 16px; vertical-align: top; }}
  .mono {{ font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 12px; color: #93c5fd; }}
  .role {{ font-size: 13px; font-weight: 600; white-space: nowrap; color: #c4b5fd; }}
  .desc {{ color: var(--muted); font-size: 13px; max-width: 380px; }}
  .date {{ color: var(--muted); font-size: 12px; white-space: nowrap; }}
  .active-dot {{ display:inline-block; width:8px; height:8px; border-radius:50%;
                 background:#f59e0b; margin-right:6px; animation: pulse 1.5s infinite; }}
  @keyframes pulse {{ 0%,100%{{opacity:1}} 50%{{opacity:.4}} }}
  footer {{ text-align: center; padding: 28px; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>

<header>
  <div>
    <h1>MediZuva — PIM Dashboard</h1>
    <div class="sub">Pillar 3: Privileged Identity Management &nbsp;|&nbsp; Tenant: {data.get('Tenant', '—')} &nbsp;|&nbsp; Audited: {audit_date}</div>
  </div>
  <div class="posture-badge">Zero-Trust Posture: {posture}</div>
</header>

<main>

  <div class="section">
    <h2>Coverage Metrics</h2>
    <div class="stats">{cards}</div>
  </div>

  <div class="section">
    <h2>Role Coverage</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>Role</th><th>Purpose</th><th>Eligible Users</th></tr>
        </thead>
        <tbody>
          {role_coverage_rows(eligible)}
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2>Eligible Assignments (JIT — must activate to use)</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>User</th><th>Role</th><th>Justification</th><th>Expiry</th></tr>
        </thead>
        <tbody>
          {eligible_rows(eligible)}
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <h2><span class="active-dot"></span>Active Elevations Right Now</h2>
    <div class="table-wrap">
      <table>
        <thead>
          <tr><th>User</th><th>Role</th><th>Expires</th></tr>
        </thead>
        <tbody>
          {active_rows(active)}
        </tbody>
      </table>
    </div>
  </div>

</main>

<footer>
  MediZuva Zero-Trust Framework &mdash; Pillar 3: Privileged Identity Management &mdash; Generated {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
</footer>

</body>
</html>"""


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Generate MediZuva PIM dashboard")
    parser.add_argument("--audit", default=str(AUDIT_JSON), help="Path to pim_audit.json")
    parser.add_argument("--out",   default=str(OUT_HTML),   help="Output HTML path")
    args = parser.parse_args()

    audit_path = Path(args.audit)
    if not audit_path.exists():
        print(f"[ERROR] Audit file not found: {audit_path}")
        print("        Run audit_pim_roles.ps1 first to generate it.")
        sys.exit(1)

    with open(audit_path, encoding="utf-8-sig") as f:
        data = json.load(f)

    html = build_html(data)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    print(f"[OK] Dashboard written to: {out_path}")
    print(f"     Open in browser: file:///{out_path.as_posix()}")


if __name__ == "__main__":
    main()
