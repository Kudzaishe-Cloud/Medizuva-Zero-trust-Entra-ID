"""
dashboard/generate_central_dashboard.py
============================================================
MediZuva Zero-Trust — Single Central Security Dashboard.
Aggregates ALL four pillars plus OSINT intelligence, threat
predictions, recommendations, and audit logs into one HTML file.

Sections:
  Overview    — posture summary, KPIs, alert banner, predictions
  P1 Identity — provisioning stats, dept/location charts
  P2 Access   — CA policies, enforcement state
  P3 PIM      — JIT roles, eligible users
  P4 Threat   — risk tiers, signal breakdown, high-risk users
  OSINT Intel — multi-source breach data, dept exposure, recs
  Audit Logs  — embedded osint_run.log viewer

Usage:  python dashboard/generate_central_dashboard.py
Output: data/central_dashboard.html
============================================================
"""

import json
import html as _html
from collections import Counter
from datetime import datetime
from pathlib import Path

import pandas as pd

REPO_ROOT     = Path(__file__).resolve().parents[1]
PERSONAS_CSV  = REPO_ROOT / "data" / "personas" / "medizuva_500_personas.csv"
PROV_LOG      = REPO_ROOT / "data" / "personas" / "provisioning_log.csv"
CA_AUDIT      = REPO_ROOT / "data" / "ca_audit.json"
PIM_AUDIT     = REPO_ROOT / "data" / "pim_audit.json"
THREAT_AUDIT  = REPO_ROOT / "data" / "threat_audit.json"
OSINT_COMBINED= REPO_ROOT / "data" / "osint_results" / "osint_combined_results.json"
OSINT_LOG     = REPO_ROOT / "data" / "osint_results" / "osint_run.log"
NIST_REPORT   = REPO_ROOT / "data" / "nist_compliance_report.json"
OUT_HTML      = REPO_ROOT / "data" / "central_dashboard.html"


# ── Loaders ───────────────────────────────────────────────────

def load_json(path):
    if not path.exists():
        return None
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f)

def load_all():
    df  = pd.read_csv(PERSONAS_CSV)
    log = pd.read_csv(PROV_LOG) if PROV_LOG.exists() else None
    p1  = {
        "total":       len(df),
        "provisioned": int(log["Status"].eq("Success").sum()) if log is not None else len(df),
        "mfa_reg":     int((df["MFARegistered"] == True).sum() or (df["MFARegistered"].astype(str) == "True").sum()),
        "compliant":   int((df["DeviceCompliant"] == True).sum() or (df["DeviceCompliant"].astype(str) == "True").sum()),
        "dept_counts": df["Department"].value_counts().to_dict(),
        "loc_counts":  df["Location"].value_counts().to_dict(),
    }
    p2    = load_json(CA_AUDIT)
    p3    = load_json(PIM_AUDIT)
    p4    = load_json(THREAT_AUDIT)
    osint = load_json(OSINT_COMBINED)
    nist  = load_json(NIST_REPORT)
    log_txt = OSINT_LOG.read_text(encoding="utf-8") if OSINT_LOG.exists() else "No log file found."
    return p1, p2, p3, p4, osint, nist, log_txt


# ── Helpers ───────────────────────────────────────────────────

def jl(lst):  return json.dumps(lst)
def jd(d):    return json.dumps(d)

def pcol(p):
    return {
        "COMPLIANT":    "#10b981",
        "PARTIAL":      "#f59e0b",
        "AT RISK":      "#ef4444",
        "IN PROGRESS":  "#3b82f6",
        "NOT STARTED":  "#6b7280",
    }.get(str(p), "#6b7280")

def overall_posture(p1_ok, p2, p3, p4):
    p2p = (p2 or {}).get("Summary", {}).get("Posture", "NOT STARTED")
    p3p = (p3 or {}).get("Summary", {}).get("Posture", "NOT STARTED")
    p4p = (p4 or {}).get("Summary", {}).get("Posture", "NOT STARTED")
    all_p = ["COMPLIANT", p2p, p3p, p4p]
    if any(p == "AT RISK" for p in all_p): return "AT RISK"
    if all(p == "COMPLIANT" for p in all_p): return "COMPLIANT"
    return "IN PROGRESS"


# ── HTML builder ──────────────────────────────────────────────

def build_html(p1, p2, p3, p4, osint, nist, log_txt):
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Pillar summaries ──────────────────────────────────────
    p2s  = (p2 or {}).get("Summary", {})
    p3s  = (p3 or {}).get("Summary", {})
    p4s  = (p4 or {}).get("Summary", {})
    oi   = (osint or {}).get("ThreatIntelligence", {}).get("Overview", {})

    p2_posture = p2s.get("Posture", "NOT STARTED")
    p3_posture = p3s.get("Posture", "NOT STARTED")
    p4_posture = p4s.get("Posture", "NOT STARTED")
    overall    = overall_posture(True, p2, p3, p4)
    oc         = pcol(overall)

    # ── P1 stats ──────────────────────────────────────────────
    total       = p1["total"]
    mfa_pct     = round(p1["mfa_reg"] / total * 100, 1) if total else 0
    dev_pct     = round(p1["compliant"] / total * 100, 1) if total else 0
    dept_labels = list(p1["dept_counts"].keys())
    dept_vals   = list(p1["dept_counts"].values())
    loc_labels  = list(p1["loc_counts"].keys())
    loc_vals    = list(p1["loc_counts"].values())

    # ── P2 charts ─────────────────────────────────────────────
    p2_policies = (p2 or {}).get("Policies", []) or []
    p2_states   = {
        "ENFORCED":    p2s.get("Enforced",   0),
        "REPORT-ONLY": p2s.get("ReportOnly", 0),
        "DISABLED":    p2s.get("Disabled",   0),
        "MISSING":     p2s.get("Missing",    0),
    }
    p2_pol_names  = [p.get("PolicyName", "").replace("MZV-","") for p in p2_policies[:8]]
    p2_pol_states = []
    state_num     = {"ENFORCED": 3, "REPORT-ONLY": 2, "DISABLED": 1, "MISSING": 0}
    for p in p2_policies[:8]:
        p2_pol_states.append(state_num.get(p.get("State","MISSING"), 0))

    # ── P3 charts ─────────────────────────────────────────────
    PIM_ROLES = [
        "User Administrator", "Privileged Role Administrator",
        "Helpdesk Administrator", "Security Administrator",
        "Security Reader", "Reports Reader",
    ]
    p3_eligible    = (p3 or {}).get("Eligible", []) or []
    p3_role_counts = Counter(e.get("Role", "") for e in p3_eligible)
    p3_role_vals   = [p3_role_counts.get(r, 0) for r in PIM_ROLES]
    p3_role_abbr   = ["User Admin","Priv Role Admin","Helpdesk","Sec Admin","Sec Reader","Reports Reader"]

    # ── P4 charts ─────────────────────────────────────────────
    p4_users   = (p4 or {}).get("UserRisks", []) or []
    dept_tiers: dict = {}
    for u in p4_users:
        d = u.get("Department", "Unknown")
        t = u.get("Tier", "LOW")
        if d not in dept_tiers:
            dept_tiers[d] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        dept_tiers[d][t] += 1
    depts             = list(dept_tiers.keys())
    p4_dept_critical  = [dept_tiers[d]["CRITICAL"] for d in depts]
    p4_dept_high      = [dept_tiers[d]["HIGH"]     for d in depts]
    p4_dept_medium    = [dept_tiers[d]["MEDIUM"]   for d in depts]
    p4_tiers = {
        "CRITICAL": p4s.get("Critical", 0),
        "HIGH":     p4s.get("High",     0),
        "MEDIUM":   p4s.get("Medium",   0),
        "LOW":      p4s.get("Low",      0),
    }

    # ── OSINT charts ──────────────────────────────────────────
    ti          = (osint or {}).get("ThreatIntelligence", {})
    osint_recs  = ti.get("Recommendations", [])
    dept_bk     = ti.get("DepartmentBreakdown", {})
    top_sources = ti.get("TopBreachSources", [])[:8]
    cat_freq    = ti.get("BreachCategories", {})
    top_indiv   = ti.get("HighestRiskIndividuals", [])[:10]
    src_tools   = ti.get("SourceToolCounts", {})
    top_titles  = ti.get("MostExposedTitles", [])[:5]

    osint_dept_labels    = list(dept_bk.keys())
    osint_dept_exp_rate  = [dept_bk[d].get("ExposureRatePct", 0) for d in osint_dept_labels]
    osint_dept_darkweb   = [dept_bk[d].get("DarkWebUsers", 0) for d in osint_dept_labels]
    osint_src_labels     = [s["Source"] for s in top_sources]
    osint_src_vals       = [s["AffectedUsers"] for s in top_sources]
    osint_cat_labels     = list(cat_freq.keys())
    osint_cat_vals       = list(cat_freq.values())
    tool_labels          = list(src_tools.keys())
    tool_vals            = list(src_tools.values())

    # ── Tables HTML ───────────────────────────────────────────
    STATE_BADGE = {
        "ENFORCED":    '<span class="badge b-green">ENFORCED</span>',
        "REPORT-ONLY": '<span class="badge b-amber">REPORT ONLY</span>',
        "DISABLED":    '<span class="badge b-red">DISABLED</span>',
        "MISSING":     '<span class="badge b-gray">MISSING</span>',
    }
    p2_rows = ""
    for pol in p2_policies:
        badge = STATE_BADGE.get(pol.get("State", "MISSING"), STATE_BADGE["MISSING"])
        p2_rows += (
            f"<tr><td class='mono'>{pol.get('PolicyName','—')}</td>"
            f"<td>{badge}</td>"
            f"<td class='muted'>{pol.get('ModifiedAt','—') or '—'}</td></tr>\n"
        )

    p3_rows = ""
    for e in p3_eligible[:30]:
        p3_rows += (
            f"<tr><td class='mono'>{e.get('User','—')}</td>"
            f"<td><span class='pill pill-purple'>{e.get('Role','—')}</span></td>"
            f"<td class='muted'>{e.get('EndDate') or 'No expiry'}</td></tr>\n"
        )

    TIER_BADGE = {
        "CRITICAL": '<span class="badge b-red">CRITICAL</span>',
        "HIGH":     '<span class="badge b-amber">HIGH</span>',
        "MEDIUM":   '<span class="badge b-blue">MEDIUM</span>',
        "LOW":      '<span class="badge b-green">LOW</span>',
    }
    p4_rows = ""
    count = 0
    for u in p4_users:
        if u.get("Tier") not in ("CRITICAL", "HIGH"):
            continue
        p4_rows += (
            f"<tr><td class='mono'>{u.get('Name','—')}</td>"
            f"<td class='muted'>{u.get('Department','—')}</td>"
            f"<td class='muted'>{u.get('JobTitle','—')}</td>"
            f"<td>{TIER_BADGE.get(u.get('Tier','LOW'),'')}</td>"
            f"<td class='muted sig'>{u.get('Signals','—')}</td></tr>\n"
        )
        count += 1
        if count >= 40: break

    osint_rows = ""
    for ind in top_indiv:
        dw_badge = '<span class="badge b-red">DARK WEB</span>' if ind.get("DarkWeb") else '<span class="badge b-gray">Surface</span>'
        score    = ind.get("ExposureScore", 0)
        bar_col  = "#ef4444" if score >= 70 else "#f59e0b" if score >= 40 else "#3b82f6"
        osint_rows += (
            f"<tr><td class='mono'>{ind.get('Name','—')}</td>"
            f"<td class='muted'>{ind.get('Department','—')}</td>"
            f"<td class='muted'>{ind.get('JobTitle','—')}</td>"
            f"<td>{dw_badge}</td>"
            f"<td><div style='display:flex;align-items:center;gap:8px'>"
            f"<div style='flex:1;background:#1a3050;border-radius:999px;height:6px'>"
            f"<div style='width:{score}%;background:{bar_col};border-radius:999px;height:6px'></div></div>"
            f"<span style='color:{bar_col};font-weight:700;font-size:12px'>{score}</span>"
            f"</div></td>"
            f"<td class='muted'>{ind.get('TotalFindings',0)}</td></tr>\n"
        )

    # ── Recommendations HTML ──────────────────────────────────
    rec_html = ""
    pri_style = {
        "CRITICAL": ("b-red",   "🔴"),
        "HIGH":     ("b-amber", "🟠"),
        "MEDIUM":   ("b-blue",  "🟡"),
        "LOW":      ("b-gray",  "⚪"),
    }
    for rec in osint_recs:
        pri   = rec.get("Priority", "LOW")
        cls, dot = pri_style.get(pri, ("b-gray", "⚪"))
        affected = f" — <strong>{rec['AffectedCount']} users</strong>" if rec.get("AffectedCount") else ""
        rec_html += f"""
        <div class="rec-card rec-{pri.lower()}">
          <div class="rec-header">
            <span class="badge {cls}">{pri}</span>
            <span class="rec-action">{_html.escape(rec.get('Action',''))}{affected}</span>
          </div>
          <div class="rec-rationale">{_html.escape(rec.get('Rationale',''))}</div>
        </div>"""

    # ── Log content (escaped) ────────────────────────────────
    log_escaped = _html.escape(log_txt)

    # ── NIST compliance data ──────────────────────────────────
    nist_score    = (nist or {}).get("ComplianceScore", 0)
    nist_status   = (nist or {}).get("OverallStatus", "NOT EVALUATED")
    nist_pass     = (nist or {}).get("Summary", {}).get("PASS",    0)
    nist_partial  = (nist or {}).get("Summary", {}).get("PARTIAL", 0)
    nist_fail     = (nist or {}).get("Summary", {}).get("FAIL",    0)
    nist_controls = (nist or {}).get("Controls", [])
    nist_score_col= "#10b981" if nist_score >= 80 else "#f59e0b" if nist_score >= 60 else "#ef4444"

    NIST_STATUS_BADGE = {
        "PASS":           '<span class="badge b-green">PASS</span>',
        "PARTIAL":        '<span class="badge b-amber">PARTIAL</span>',
        "FAIL":           '<span class="badge b-red">FAIL</span>',
        "NOT_APPLICABLE": '<span class="badge b-gray">N/A</span>',
    }
    NIST_FRAMEWORK_COLOUR = {
        "NIST SP 800-207": "#00d4ff",
        "NIST SP 800-53":  "#a855f7",
        "NIST SP 800-63B": "#3b82f6",
        "NIST SP 800-137": "#10b981",
    }
    nist_rows = ""
    for ctrl in nist_controls:
        badge   = NIST_STATUS_BADGE.get(ctrl.get("Status", "FAIL"), NIST_STATUS_BADGE["FAIL"])
        # JSON uses: ControlID, Title, Standard, Finding, Recommendation
        ctrl_id = ctrl.get("ControlID", ctrl.get("ControlId", ""))
        title   = ctrl.get("Title",     ctrl.get("Name", ""))
        std     = ctrl.get("Standard",  ctrl.get("Framework", ""))
        finding = ctrl.get("Finding",   ctrl.get("Details", ""))
        reco    = ctrl.get("Recommendation", ctrl.get("Remediation", ""))
        # Derive framework label from Standard string
        fw = "NIST SP 800-207" if "800-207" in std else \
             "NIST SP 800-53"  if "800-53"  in std else \
             "NIST SP 800-63B" if "800-63B" in std else \
             "NIST SP 800-137" if "800-137" in std else std
        fw_col  = NIST_FRAMEWORK_COLOUR.get(fw, "#6b7280")
        fix     = _html.escape(reco) if ctrl.get("Status") in ("PARTIAL", "FAIL") and reco else ""
        fix_html= f'<div class="nist-fix">Fix: {fix}</div>' if fix else ""
        nist_rows += (
            f"<tr>"
            f"<td class='mono' style='color:{fw_col}'>{_html.escape(ctrl_id)}</td>"
            f"<td style='font-weight:500'>{_html.escape(title)}</td>"
            f"<td><span style='color:{fw_col};font-size:11px;font-weight:600'>{_html.escape(fw)}</span></td>"
            f"<td>{badge}</td>"
            f"<td class='muted' style='max-width:340px;font-size:12px'>{_html.escape(finding)}{fix_html}</td>"
            f"</tr>\n"
        )

    # ── Prediction data (derived from existing signals) ───────
    # Simple linear projection: if 40.8% exposed now, and dark web = 23.2%,
    # project that without remediation, dark web exposure grows ~3%/month
    dw_rate    = oi.get("DarkWebRatePct", 23.2)
    exp_rate   = oi.get("ExposureRatePct", 40.8)
    pred_months = [f"Month {i}" for i in range(1, 7)]
    pred_dw     = [round(min(100, dw_rate + i * 2.8), 1)  for i in range(1, 7)]
    pred_exp    = [round(min(100, exp_rate + i * 1.4), 1) for i in range(1, 7)]

    # ── Alert banner content ──────────────────────────────────
    alert_html = ""
    if overall == "AT RISK":
        alert_html = (
            f'<div class="alert-banner">'
            f'<div class="alert-dot"></div>'
            f'<div class="alert-text"><strong>ACTIVE THREAT DETECTED</strong> — '
            f'{p4s.get("Critical",0)} CRITICAL · {p4s.get("High",0)} HIGH risk users · '
            f'{oi.get("DarkWebExposed",0)} dark web credential exposures. '
            f'Immediate action required.</div></div>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MediZuva — Zero-Trust Security Operations Centre</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#030b16;--surface:#071220;--surface2:#0c1a2e;--surface3:#102038;
  --border:#1a3050;--text:#ddeeff;--muted:#5a7a9a;
  --cyan:#00d4ff;--purple:#a855f7;--green:#10b981;
  --amber:#f59e0b;--red:#ef4444;--blue:#3b82f6;--sidebar:225px;
}}
html,body{{height:100%;overflow:hidden}}
body{{
  background:var(--bg);color:var(--text);
  font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;display:flex;
  background-image:
    radial-gradient(ellipse 80% 50% at 50% -20%,rgba(0,212,255,.06),transparent),
    radial-gradient(circle at 1px 1px,rgba(0,212,255,.03) 1px,transparent 0);
  background-size:100% 100%,28px 28px;
}}
.sidebar{{
  width:var(--sidebar);min-width:var(--sidebar);height:100vh;
  background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;z-index:100;position:relative;flex-shrink:0;
}}
.sidebar::after{{
  content:'';position:absolute;right:0;top:0;bottom:0;width:1px;
  background:linear-gradient(180deg,transparent,var(--cyan),transparent);opacity:.3;
}}
.brand{{padding:22px 20px 18px;border-bottom:1px solid var(--border)}}
.brand-logo{{font-size:19px;font-weight:800;letter-spacing:-.3px;
  background:linear-gradient(135deg,var(--cyan),var(--purple));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.brand-sub{{font-size:10px;color:var(--muted);margin-top:3px;letter-spacing:.05em;text-transform:uppercase}}
.nav{{flex:1;padding:12px 0;overflow-y:auto}}
.nav-item{{
  display:flex;align-items:center;gap:12px;padding:11px 20px;
  cursor:pointer;color:var(--muted);transition:.2s;position:relative;
  font-size:13px;font-weight:500;border-left:3px solid transparent;
}}
.nav-item:hover{{color:var(--text);background:var(--surface2)}}
.nav-item.active{{color:var(--cyan);background:rgba(0,212,255,.06);border-left-color:var(--cyan)}}
.nav-item.active .nav-icon{{filter:drop-shadow(0 0 6px var(--cyan))}}
.nav-icon{{width:18px;height:18px;flex-shrink:0;opacity:.8}}
.nav-dot{{width:8px;height:8px;border-radius:50%;flex-shrink:0;box-shadow:0 0 6px currentColor}}
.sidebar-footer{{padding:16px 20px;border-top:1px solid var(--border)}}
.tenant-info{{font-size:11px;color:var(--muted)}}
.tenant-name{{color:var(--text);font-weight:600;margin-bottom:2px}}
.overall-badge{{
  display:inline-flex;align-items:center;gap:6px;margin-top:10px;
  padding:5px 12px;border-radius:6px;font-size:11px;font-weight:700;
  background:{oc}18;color:{oc};border:1px solid {oc}44;
}}
.overall-badge .pulse{{
  width:6px;height:6px;border-radius:50%;background:{oc};
  {"animation:pulse 1.5s infinite;" if overall == "AT RISK" else ""}
}}
.main{{flex:1;display:flex;flex-direction:column;height:100vh;overflow:hidden}}
.topbar{{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:0 28px;height:56px;display:flex;align-items:center;gap:28px;flex-shrink:0;
}}
.topbar-title{{font-weight:700;font-size:15px}}
.topbar-meta{{color:var(--muted);font-size:12px}}
.topbar-kpis{{display:flex;gap:24px;margin-left:auto}}
.kpi{{text-align:right}}
.kpi-val{{font-size:18px;font-weight:800;line-height:1;color:var(--cyan)}}
.kpi-label{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
.clock{{font-size:13px;font-weight:600;color:var(--cyan);font-variant-numeric:tabular-nums;
  padding:4px 10px;border:1px solid var(--border);border-radius:6px;background:rgba(0,212,255,.05)}}
.content{{flex:1;overflow-y:auto;padding:24px 28px}}
.content::-webkit-scrollbar{{width:6px}}
.content::-webkit-scrollbar-track{{background:var(--surface)}}
.content::-webkit-scrollbar-thumb{{background:var(--border);border-radius:3px}}
.panel{{display:none}}
.panel.active{{display:block}}
.panel-header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:20px}}
.panel-title{{font-size:16px;font-weight:700}}
.panel-sub{{color:var(--muted);font-size:12px;margin-top:2px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:14px;margin-bottom:24px}}
.card{{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:18px 16px;position:relative;overflow:hidden;transition:.25s;
}}
.card::before{{
  content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:var(--accent-color,var(--cyan));box-shadow:0 0 12px var(--accent-color,var(--cyan));
}}
.card:hover{{border-color:var(--accent-color,var(--cyan));box-shadow:0 0 20px rgba(0,212,255,.1);transform:translateY(-1px)}}
.card-val{{font-size:28px;font-weight:800;line-height:1;margin-bottom:4px;color:var(--accent-color,var(--cyan))}}
.card-label{{font-size:12px;font-weight:600;color:var(--text)}}
.card-sub{{font-size:11px;color:var(--muted);margin-top:3px}}
.card-glow{{position:absolute;bottom:-20px;right:-20px;width:80px;height:80px;
  border-radius:50%;background:var(--accent-color,var(--cyan));opacity:.04;filter:blur(20px)}}
.charts{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
.charts.three{{grid-template-columns:1fr 1fr 1fr}}
.chart-box{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px}}
.chart-box.wide{{grid-column:span 2}}
.chart-title{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;
  color:var(--muted);margin-bottom:16px}}
.chart-wrap{{position:relative;height:220px}}
.tbl-box{{background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;margin-bottom:24px}}
.tbl-head{{
  display:flex;align-items:center;justify-content:space-between;
  padding:14px 18px;border-bottom:1px solid var(--border);
  font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);
}}
table{{width:100%;border-collapse:collapse}}
thead th{{background:var(--surface2);padding:10px 16px;text-align:left;
  font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}}
tbody tr{{border-top:1px solid var(--border);transition:.15s}}
tbody tr:hover{{background:var(--surface2)}}
tbody td{{padding:11px 16px;vertical-align:middle}}
.mono{{font-family:'Cascadia Code',Consolas,monospace;font-size:12px;color:#7dd3fc}}
.muted{{color:var(--muted)}}
.sig{{font-size:11px;max-width:260px}}
.badge{{display:inline-block;padding:2px 9px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:.03em}}
.b-green{{background:#10b98120;color:#10b981;border:1px solid #10b98140}}
.b-amber{{background:#f59e0b20;color:#f59e0b;border:1px solid #f59e0b40}}
.b-red{{background:#ef444420;color:#ef4444;border:1px solid #ef444440}}
.b-gray{{background:#6b728020;color:#94a3b8;border:1px solid #6b728040}}
.b-blue{{background:#3b82f620;color:#3b82f6;border:1px solid #3b82f640}}
.pill{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:500}}
.pill-purple{{background:#a855f720;color:#c084fc;border:1px solid #a855f740}}
.pillar-grid{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}}
.pillar-card{{
  background:var(--surface);border:1px solid var(--border);border-radius:12px;
  padding:22px;cursor:pointer;transition:.25s;position:relative;overflow:hidden;
}}
.pillar-card:hover{{border-color:var(--cyan);box-shadow:0 0 24px rgba(0,212,255,.1);transform:translateY(-2px)}}
.pillar-card-num{{font-size:11px;font-weight:700;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:8px}}
.pillar-card-title{{font-size:15px;font-weight:700;margin-bottom:12px}}
.pillar-card-stats{{display:flex;gap:20px}}
.pcs{{text-align:center}}
.pcs-val{{font-size:22px;font-weight:800}}
.pcs-label{{font-size:10px;color:var(--muted);text-transform:uppercase}}
.pillar-posture{{position:absolute;top:16px;right:16px;padding:3px 10px;border-radius:999px;font-size:10px;font-weight:700}}
.pc-bg{{position:absolute;bottom:-30px;left:-30px;width:120px;height:120px;border-radius:50%;opacity:.04;filter:blur(30px)}}
.alert-banner{{
  background:rgba(239,68,68,.08);border:1px solid rgba(239,68,68,.3);
  border-radius:8px;padding:12px 18px;margin-bottom:20px;display:flex;align-items:center;gap:12px;
}}
.alert-dot{{width:10px;height:10px;border-radius:50%;background:#ef4444;flex-shrink:0;animation:pulse 1.2s infinite}}
.alert-text{{font-size:13px;color:#fca5a5;font-weight:500}}
.rec-card{{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:16px 18px;margin-bottom:12px;transition:.2s;
}}
.rec-card:hover{{border-color:var(--cyan)}}
.rec-critical{{border-left:3px solid #ef4444}}
.rec-high{{border-left:3px solid #f59e0b}}
.rec-medium{{border-left:3px solid #3b82f6}}
.rec-low{{border-left:3px solid #6b7280}}
.rec-header{{display:flex;align-items:center;gap:12px;margin-bottom:8px}}
.rec-action{{font-weight:600;font-size:13px;flex:1}}
.rec-rationale{{font-size:12px;color:var(--muted);line-height:1.6}}
.log-viewer{{
  background:#020a14;border:1px solid var(--border);border-radius:10px;
  padding:20px;font-family:'Cascadia Code',Consolas,monospace;font-size:11.5px;
  line-height:1.7;overflow-y:auto;max-height:600px;margin-bottom:24px;
  color:#94a3b8;white-space:pre-wrap;
}}
.nist-fix{{color:#f59e0b;font-size:11px;margin-top:3px;font-style:italic}}
.log-viewer .log-info{{color:#7dd3fc}}
.log-viewer .log-warn{{color:#fbbf24}}
.log-viewer .log-error{{color:#f87171}}
.log-viewer .log-exposed{{color:#c084fc}}
.log-toolbar{{
  display:flex;align-items:center;gap:12px;margin-bottom:12px;
}}
.log-filter{{
  background:var(--surface2);border:1px solid var(--border);border-radius:6px;
  padding:6px 12px;color:var(--text);font-size:12px;outline:none;
}}
.log-filter:focus{{border-color:var(--cyan)}}
@keyframes pulse{{0%,100%{{opacity:1;transform:scale(1)}}50%{{opacity:.5;transform:scale(1.3)}}}}
@keyframes fadeUp{{from{{opacity:0;transform:translateY(12px)}}to{{opacity:1;transform:none}}}}
.panel.active .card{{animation:fadeUp .35s ease both}}
.panel.active .card:nth-child(2){{animation-delay:.05s}}
.panel.active .card:nth-child(3){{animation-delay:.10s}}
.panel.active .card:nth-child(4){{animation-delay:.15s}}
.panel.active .card:nth-child(5){{animation-delay:.20s}}
.panel.active .card:nth-child(6){{animation-delay:.25s}}
</style>
</head>
<body>

<!-- ── Sidebar ───────────────────────────────────────────── -->
<aside class="sidebar">
  <div class="brand">
    <div class="brand-logo">MediZuva</div>
    <div class="brand-sub">Zero-Trust Security Operations</div>
  </div>
  <nav class="nav">
    <div class="nav-item active" onclick="show('overview')" id="nav-overview">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
        <rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/>
      </svg>
      <span class="nav-label">Overview</span>
    </div>
    <div class="nav-item" onclick="show('p1')" id="nav-p1">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
        <circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
      </svg>
      <span class="nav-label">P1 · Identity</span>
      <div class="nav-dot" style="color:var(--green)"></div>
    </div>
    <div class="nav-item" onclick="show('p2')" id="nav-p2">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
      <span class="nav-label">P2 · Access</span>
      <div class="nav-dot" style="color:{pcol(p2_posture)}"></div>
    </div>
    <div class="nav-item" onclick="show('p3')" id="nav-p3">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
      <span class="nav-label">P3 · PIM</span>
      <div class="nav-dot" style="color:{pcol(p3_posture)}"></div>
    </div>
    <div class="nav-item" onclick="show('p4')" id="nav-p4">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
        <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
      </svg>
      <span class="nav-label">P4 · Threat</span>
      <div class="nav-dot" style="color:{pcol(p4_posture)};{"animation:pulse 1.2s infinite;" if p4_posture=="AT RISK" else ""}"></div>
    </div>
    <div class="nav-item" onclick="show('osint')" id="nav-osint">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
        <line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
      </svg>
      <span class="nav-label">OSINT · Intel</span>
      <div class="nav-dot" style="color:var(--purple);animation:pulse 2s infinite"></div>
    </div>
    <div class="nav-item" onclick="show('nist')" id="nav-nist">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
      </svg>
      <span class="nav-label">NIST SP 800</span>
      <div class="nav-dot" style="color:{nist_score_col}"></div>
    </div>
    <div class="nav-item" onclick="show('logs')" id="nav-logs">
      <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
        <polyline points="14 2 14 8 20 8"/>
        <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
        <polyline points="10 9 9 9 8 9"/>
      </svg>
      <span class="nav-label">Audit Logs</span>
    </div>
  </nav>
  <div class="sidebar-footer">
    <div class="tenant-info">
      <div class="tenant-name">micrlabs.onmicrosoft.com</div>
      <div>500 users · 5 locations · {generated[:10]}</div>
    </div>
    <div class="overall-badge">
      <div class="pulse"></div>
      {overall}
    </div>
  </div>
</aside>

<!-- ── Main ──────────────────────────────────────────────── -->
<div class="main">

  <!-- Topbar -->
  <header class="topbar">
    <div>
      <div class="topbar-title">Security Operations Centre</div>
      <div class="topbar-meta">Generated {generated}</div>
    </div>
    <div class="topbar-kpis">
      <div class="kpi">
        <div class="kpi-val" id="kpi-users">0</div>
        <div class="kpi-label">Total Users</div>
      </div>
      <div class="kpi">
        <div class="kpi-val" id="kpi-critical" style="color:var(--red)">0</div>
        <div class="kpi-label">Critical Risks</div>
      </div>
      <div class="kpi">
        <div class="kpi-val" id="kpi-darkweb" style="color:var(--purple)">0</div>
        <div class="kpi-label">Dark Web</div>
      </div>
      <div class="kpi">
        <div class="kpi-val" id="kpi-exposed" style="color:var(--amber)">0</div>
        <div class="kpi-label">OSINT Exposed</div>
      </div>
      <div class="kpi">
        <div class="kpi-val" id="kpi-mfa" style="color:var(--cyan)">0</div>
        <div class="kpi-label">MFA Gaps</div>
      </div>
    </div>
    <div class="clock" id="clock">--:--:--</div>
  </header>

  <div class="content">

    <!-- ══════════════════════════════════════════════════════
         OVERVIEW
    ═══════════════════════════════════════════════════════ -->
    <section class="panel active" id="panel-overview">
      <div class="panel-header">
        <div>
          <div class="panel-title">Security Overview</div>
          <div class="panel-sub">All pillars · OSINT · Predictions at a glance</div>
        </div>
        <span class="badge" style="background:{oc}20;color:{oc};border:1px solid {oc}40">{overall}</span>
      </div>

      {alert_html}

      <!-- Pillar summary grid -->
      <div class="pillar-grid">
        <div class="pillar-card" onclick="show('p1')">
          <div class="pc-bg" style="background:var(--green)"></div>
          <div class="pillar-posture" style="background:#10b98120;color:#10b981;border:1px solid #10b98140">COMPLIANT</div>
          <div class="pillar-card-num">Pillar 01</div>
          <div class="pillar-card-title">Identity &amp; Provisioning</div>
          <div class="pillar-card-stats">
            <div class="pcs"><div class="pcs-val" style="color:var(--green)">{p1['total']}</div><div class="pcs-label">Provisioned</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--cyan)">{mfa_pct}%</div><div class="pcs-label">MFA Ready</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--amber)">{dev_pct}%</div><div class="pcs-label">Compliant Dev.</div></div>
          </div>
        </div>
        <div class="pillar-card" onclick="show('p2')">
          <div class="pc-bg" style="background:{pcol(p2_posture)}"></div>
          <div class="pillar-posture" style="background:{pcol(p2_posture)}20;color:{pcol(p2_posture)};border:1px solid {pcol(p2_posture)}40">{p2_posture}</div>
          <div class="pillar-card-num">Pillar 02</div>
          <div class="pillar-card-title">Conditional Access</div>
          <div class="pillar-card-stats">
            <div class="pcs"><div class="pcs-val" style="color:var(--green)">{p2s.get('Enforced',0)}</div><div class="pcs-label">Enforced</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--amber)">{p2s.get('ReportOnly',0)}</div><div class="pcs-label">Report-Only</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--cyan)">{p2s.get('Total',0)}</div><div class="pcs-label">Policies</div></div>
          </div>
        </div>
        <div class="pillar-card" onclick="show('p3')">
          <div class="pc-bg" style="background:{pcol(p3_posture)}"></div>
          <div class="pillar-posture" style="background:{pcol(p3_posture)}20;color:{pcol(p3_posture)};border:1px solid {pcol(p3_posture)}40">{p3_posture}</div>
          <div class="pillar-card-num">Pillar 03</div>
          <div class="pillar-card-title">Privileged Identity (PIM)</div>
          <div class="pillar-card-stats">
            <div class="pcs"><div class="pcs-val" style="color:var(--blue)">{p3s.get('TotalEligible',0)}</div><div class="pcs-label">Eligible JIT</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--amber)">{p3s.get('ActiveNow',0)}</div><div class="pcs-label">Active Now</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--green)">6</div><div class="pcs-label">Roles Covered</div></div>
          </div>
        </div>
        <div class="pillar-card" onclick="show('p4')">
          <div class="pc-bg" style="background:{pcol(p4_posture)}"></div>
          <div class="pillar-posture" style="background:{pcol(p4_posture)}20;color:{pcol(p4_posture)};border:1px solid {pcol(p4_posture)}40">{p4_posture}</div>
          <div class="pillar-card-num">Pillar 04</div>
          <div class="pillar-card-title">Threat Detection</div>
          <div class="pillar-card-stats">
            <div class="pcs"><div class="pcs-val" style="color:var(--red)">{p4s.get('Critical',0)}</div><div class="pcs-label">Critical</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--amber)">{p4s.get('High',0)}</div><div class="pcs-label">High</div></div>
            <div class="pcs"><div class="pcs-val" style="color:var(--purple)">{oi.get('DarkWebExposed',0)}</div><div class="pcs-label">Dark Web</div></div>
          </div>
        </div>
      </div>

      <!-- Overview charts row 1 -->
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Risk Tier Distribution</div>
          <div class="chart-wrap"><canvas id="ov-donut"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Threats by Department</div>
          <div class="chart-wrap"><canvas id="ov-dept"></canvas></div>
        </div>
      </div>

      <!-- Prediction chart -->
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Predicted Exposure Trend (Next 6 Months — No Remediation)</div>
          <div class="chart-wrap"><canvas id="ov-predict"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">OSINT Source Coverage</div>
          <div class="chart-wrap"><canvas id="ov-tools"></canvas></div>
        </div>
      </div>
    </section>

    <!-- ══════════════════════════════════════════════════════
         P1 · IDENTITY
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-p1">
      <div class="panel-header">
        <div>
          <div class="panel-title">Pillar 1 — Identity &amp; Provisioning</div>
          <div class="panel-sub">500 personas · 6 departments · 5 locations · Validated 2026-03-29</div>
        </div>
        <span class="badge b-green">COMPLIANT</span>
      </div>
      <div class="cards">
        <div class="card" style="--accent-color:var(--green)">
          <div class="card-val counter" data-target="{p1['total']}">0</div>
          <div class="card-label">Total Users</div><div class="card-sub">Provisioned in Entra ID</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--green)">
          <div class="card-val counter" data-target="{p1['provisioned']}">0</div>
          <div class="card-label">Provisioned OK</div><div class="card-sub">100% success rate</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--cyan)">
          <div class="card-val">{mfa_pct}%</div>
          <div class="card-label">MFA Registered</div><div class="card-sub">{p1['mfa_reg']} of {p1['total']} users</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--amber)">
          <div class="card-val">{dev_pct}%</div>
          <div class="card-label">Device Compliant</div><div class="card-sub">{p1['compliant']} of {p1['total']} devices</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--purple)">
          <div class="card-val">6</div>
          <div class="card-label">Departments</div><div class="card-sub">Clinical · IT · Billing · Ops</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--blue)">
          <div class="card-val">5</div>
          <div class="card-label">Locations</div><div class="card-sub">Harare · Bulawayo · 3 more</div>
          <div class="card-glow"></div>
        </div>
      </div>
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Users by Department</div>
          <div class="chart-wrap"><canvas id="p1-dept"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Users by Location</div>
          <div class="chart-wrap"><canvas id="p1-loc"></canvas></div>
        </div>
      </div>
    </section>

    <!-- ══════════════════════════════════════════════════════
         P2 · ACCESS
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-p2">
      <div class="panel-header">
        <div>
          <div class="panel-title">Pillar 2 — Conditional Access</div>
          <div class="panel-sub">6 CA policies · Tenant: micrlabs.onmicrosoft.com · Audited: {(p2 or {{}}).get('AuditDate','—')}</div>
        </div>
        <span class="badge" style="background:{pcol(p2_posture)}20;color:{pcol(p2_posture)};border:1px solid {pcol(p2_posture)}40">{p2_posture}</span>
      </div>
      <div class="cards">
        <div class="card" style="--accent-color:var(--green)">
          <div class="card-val counter" data-target="{p2s.get('Enforced',0)}">0</div>
          <div class="card-label">Enforced</div><div class="card-sub">Active policies</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--amber)">
          <div class="card-val counter" data-target="{p2s.get('ReportOnly',0)}">0</div>
          <div class="card-label">Report-Only</div><div class="card-sub">Monitoring mode</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--red)">
          <div class="card-val counter" data-target="{p2s.get('Disabled',0)}">0</div>
          <div class="card-label">Disabled</div><div class="card-sub">Not active</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:#6b7280">
          <div class="card-val counter" data-target="{p2s.get('Missing',0)}">0</div>
          <div class="card-label">Missing</div><div class="card-sub">Not deployed</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--cyan)">
          <div class="card-val">{p2s.get('Coverage',0)}%</div>
          <div class="card-label">Coverage</div><div class="card-sub">Enforced policies</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--blue)">
          <div class="card-val counter" data-target="{(p2 or {{}}).get('TotalUsers',500)}">0</div>
          <div class="card-label">Users in Scope</div><div class="card-sub">Under CA policy</div><div class="card-glow"></div>
        </div>
      </div>
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Policy State Breakdown</div>
          <div class="chart-wrap"><canvas id="p2-donut"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Per-Policy Enforcement Score</div>
          <div class="chart-wrap"><canvas id="p2-bar"></canvas></div>
        </div>
      </div>
      <div class="tbl-box">
        <div class="tbl-head"><span>All Conditional Access Policies</span><span>{len(p2_policies)} policies</span></div>
        <table>
          <thead><tr><th>Policy Name</th><th>State</th><th>Last Modified</th></tr></thead>
          <tbody>{p2_rows}</tbody>
        </table>
      </div>
    </section>

    <!-- ══════════════════════════════════════════════════════
         P3 · PIM
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-p3">
      <div class="panel-header">
        <div>
          <div class="panel-title">Pillar 3 — Privileged Identity Management</div>
          <div class="panel-sub">Just-in-time access · Tenant: micrlabs.onmicrosoft.com · Audited: {(p3 or {{}}).get('AuditDate','—')}</div>
        </div>
        <span class="badge" style="background:{pcol(p3_posture)}20;color:{pcol(p3_posture)};border:1px solid {pcol(p3_posture)}40">{p3_posture}</span>
      </div>
      <div class="cards">
        <div class="card" style="--accent-color:var(--blue)">
          <div class="card-val counter" data-target="{p3s.get('TotalEligible',0)}">0</div>
          <div class="card-label">Eligible (JIT)</div><div class="card-sub">Awaiting activation</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--amber)">
          <div class="card-val counter" data-target="{p3s.get('ActiveNow',0)}">0</div>
          <div class="card-label">Active Now</div><div class="card-sub">Elevated sessions</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--green)">
          <div class="card-val">6</div>
          <div class="card-label">Roles Managed</div><div class="card-sub">PIM-controlled roles</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--cyan)">
          <div class="card-val counter" data-target="{p3s.get('ActivationsLast30',0)}">0</div>
          <div class="card-label">Activations (30d)</div><div class="card-sub">Recent elevation events</div><div class="card-glow"></div>
        </div>
      </div>
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Eligible Users by Role</div>
          <div class="chart-wrap"><canvas id="p3-bar"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Role Distribution</div>
          <div class="chart-wrap"><canvas id="p3-donut"></canvas></div>
        </div>
      </div>
      <div class="tbl-box">
        <div class="tbl-head"><span>Eligible PIM Assignments</span><span>{len(p3_eligible)} assignments</span></div>
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Expiry</th></tr></thead>
          <tbody>{p3_rows}</tbody>
        </table>
      </div>
    </section>

    <!-- ══════════════════════════════════════════════════════
         P4 · THREAT
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-p4">
      <div class="panel-header">
        <div>
          <div class="panel-title">Pillar 4 — Threat Detection</div>
          <div class="panel-sub">Risk classification · Signal aggregation · Audited: {(p4 or {{}}).get('AuditDate','—')}</div>
        </div>
        <span class="badge" style="background:{pcol(p4_posture)}20;color:{pcol(p4_posture)};border:1px solid {pcol(p4_posture)}40">{p4_posture}</span>
      </div>
      <div class="cards">
        <div class="card" style="--accent-color:var(--red)">
          <div class="card-val counter" data-target="{p4s.get('Critical',0)}">0</div>
          <div class="card-label">Critical</div><div class="card-sub">Immediate action needed</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--amber)">
          <div class="card-val counter" data-target="{p4s.get('High',0)}">0</div>
          <div class="card-label">High</div><div class="card-sub">Priority remediation</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--blue)">
          <div class="card-val counter" data-target="{p4s.get('Medium',0)}">0</div>
          <div class="card-label">Medium</div><div class="card-sub">Monitor closely</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--green)">
          <div class="card-val counter" data-target="{p4s.get('Low',0)}">0</div>
          <div class="card-label">Low</div><div class="card-sub">No active signals</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--amber)">
          <div class="card-val counter" data-target="{p4s.get('MFAGaps',0)}">0</div>
          <div class="card-label">MFA Gaps</div><div class="card-sub">Unregistered users</div><div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--red)">
          <div class="card-val counter" data-target="{p4s.get('DeviceGaps',0)}">0</div>
          <div class="card-label">Device Gaps</div><div class="card-sub">Non-compliant devices</div><div class="card-glow"></div>
        </div>
      </div>
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Risk Tier Distribution</div>
          <div class="chart-wrap"><canvas id="p4-donut"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Critical &amp; High Risks by Department</div>
          <div class="chart-wrap"><canvas id="p4-dept"></canvas></div>
        </div>
      </div>
      <div class="tbl-box">
        <div class="tbl-head">
          <span>Critical &amp; High Risk Users</span>
          <span>{p4s.get('Critical',0) + p4s.get('High',0)} users flagged</span>
        </div>
        <table>
          <thead><tr><th>Name</th><th>Department</th><th>Job Title</th><th>Tier</th><th>Signals</th></tr></thead>
          <tbody>{p4_rows}</tbody>
        </table>
      </div>
    </section>

    <!-- ══════════════════════════════════════════════════════
         OSINT · INTELLIGENCE
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-osint">
      <div class="panel-header">
        <div>
          <div class="panel-title">OSINT Threat Intelligence</div>
          <div class="panel-sub">
            Multi-source credential exposure · HIBP · DeHashed · LeakCheck · Intelligence X ·
            Scanned: {(osint or {{}}).get('ScanDate','—')}
          </div>
        </div>
        <span class="badge" style="background:#a855f720;color:#c084fc;border:1px solid #a855f740">
          {(osint or {{}}).get('Mode','simulated').upper()}
        </span>
      </div>

      <!-- OSINT KPI cards -->
      <div class="cards">
        <div class="card" style="--accent-color:var(--amber)">
          <div class="card-val counter" data-target="{oi.get('TotalExposed',0)}">0</div>
          <div class="card-label">Total Exposed</div>
          <div class="card-sub">{oi.get('ExposureRatePct',0)}% of {oi.get('TotalPersonas',500)} users</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--red)">
          <div class="card-val counter" data-target="{oi.get('DarkWebExposed',0)}">0</div>
          <div class="card-label">Dark Web Hits</div>
          <div class="card-sub">{oi.get('DarkWebRatePct',0)}% dark web exposure</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--cyan)">
          <div class="card-val">{oi.get('AvgExposureScore',0)}</div>
          <div class="card-label">Avg Exposure Score</div>
          <div class="card-sub">Out of 100 (across exposed)</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--blue)">
          <div class="card-val counter" data-target="{src_tools.get('HIBP',0)}">0</div>
          <div class="card-label">HIBP Hits</div>
          <div class="card-sub">haveibeenpwned.com</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--purple)">
          <div class="card-val counter" data-target="{src_tools.get('DeHashed',0)}">0</div>
          <div class="card-label">DeHashed Hits</div>
          <div class="card-sub">Credential records</div>
          <div class="card-glow"></div>
        </div>
        <div class="card" style="--accent-color:var(--green)">
          <div class="card-val counter" data-target="{src_tools.get('IntelX',0)}">0</div>
          <div class="card-label">IntelX Hits</div>
          <div class="card-sub">Dark web / paste sites</div>
          <div class="card-glow"></div>
        </div>
      </div>

      <!-- OSINT charts row 1 -->
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Department Exposure Rate (%)</div>
          <div class="chart-wrap"><canvas id="osint-dept"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Top Breach Sources</div>
          <div class="chart-wrap"><canvas id="osint-sources"></canvas></div>
        </div>
      </div>

      <!-- OSINT charts row 2 -->
      <div class="charts">
        <div class="chart-box">
          <div class="chart-title">Breach Categories</div>
          <div class="chart-wrap"><canvas id="osint-cats"></canvas></div>
        </div>
        <div class="chart-box">
          <div class="chart-title">Dark Web Exposure by Department</div>
          <div class="chart-wrap"><canvas id="osint-dw"></canvas></div>
        </div>
      </div>

      <!-- Top individuals table -->
      <div class="tbl-box">
        <div class="tbl-head">
          <span>Highest Exposure Individuals</span>
          <span>Top 10 by ExposureScore</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th><th>Department</th><th>Job Title</th>
              <th>Dark Web</th><th>Exposure Score</th><th>Findings</th>
            </tr>
          </thead>
          <tbody>{osint_rows}</tbody>
        </table>
      </div>

      <!-- Recommendations -->
      <div class="panel-header" style="margin-top:8px">
        <div>
          <div class="panel-title" style="font-size:14px">Threat Intelligence Recommendations</div>
          <div class="panel-sub">Derived from OSINT scan — {len(osint_recs)} action items</div>
        </div>
      </div>
      {rec_html}
    </section>

    <!-- ══════════════════════════════════════════════════════
         NIST SP 800 COMPLIANCE
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-nist">
      <div class="panel-header">
        <div>
          <div class="panel-title">NIST SP 800 Compliance</div>
          <div class="panel-sub">SP 800-207 Zero Trust · SP 800-53 Rev5 · SP 800-63B · SP 800-137</div>
        </div>
        <span class="badge" style="background:{nist_score_col}20;color:{nist_score_col};border:1px solid {nist_score_col}40;font-size:15px;padding:6px 14px">{nist_score:.1f}% {nist_status}</span>
      </div>
      <div class="grid-4" style="margin-bottom:20px">
        <div class="stat-card">
          <div class="stat-val" style="color:#10b981">{nist_pass}</div>
          <div class="stat-lbl">PASS</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" style="color:#f59e0b">{nist_partial}</div>
          <div class="stat-lbl">PARTIAL</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" style="color:#ef4444">{nist_fail}</div>
          <div class="stat-lbl">FAIL</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" style="color:{nist_score_col}">{nist_score:.0f}%</div>
          <div class="stat-lbl">Score</div>
        </div>
      </div>
      <div style="margin-bottom:12px;padding:10px 14px;background:#0a1f35;border-radius:8px;border-left:3px solid {nist_score_col}">
        <span style="color:{nist_score_col};font-weight:700;font-size:13px">COMPLIANCE SCORE GAUGE</span>
        <div style="margin-top:8px;background:#1a3050;border-radius:999px;height:10px">
          <div style="width:{min(100,nist_score):.0f}%;background:{nist_score_col};border-radius:999px;height:10px;transition:width 1s ease"></div>
        </div>
        <div style="display:flex;justify-content:space-between;margin-top:4px">
          <span style="color:#5a7a9a;font-size:11px">0%</span>
          <span style="color:#5a7a9a;font-size:11px">60% Acceptable</span>
          <span style="color:#5a7a9a;font-size:11px">80% Substantially Compliant</span>
          <span style="color:#5a7a9a;font-size:11px">100%</span>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Control ID</th><th>Control Name</th><th>Framework</th>
            <th>Status</th><th>Details / Remediation</th>
          </tr></thead>
          <tbody>{nist_rows}</tbody>
        </table>
      </div>
    </section>

    <!-- ══════════════════════════════════════════════════════
         AUDIT LOGS
    ═══════════════════════════════════════════════════════ -->
    <section class="panel" id="panel-logs">
      <div class="panel-header">
        <div>
          <div class="panel-title">Audit Logs</div>
          <div class="panel-sub">OSINT scan run log · data/osint_results/osint_run.log</div>
        </div>
        <span class="badge b-gray">{log_txt.count(chr(10))} lines</span>
      </div>
      <div class="log-toolbar">
        <input class="log-filter" id="log-search" type="text" placeholder="Filter log lines..."
               oninput="filterLog(this.value)">
        <span class="badge b-red" style="cursor:pointer" onclick="filterLog('[EXPOSED')">[EXPOSED]</span>
        <span class="badge b-amber" style="cursor:pointer" onclick="filterLog('[WARNING')">[WARNING]</span>
        <span class="badge b-blue" style="cursor:pointer" onclick="filterLog('[INFO')">[INFO]</span>
        <span class="badge b-gray" style="cursor:pointer" onclick="filterLog('')">ALL</span>
      </div>
      <div class="log-viewer" id="log-viewer">{log_escaped}</div>
    </section>

  </div><!-- /content -->
</div><!-- /main -->

<script>
// ── Data ─────────────────────────────────────────────────────
const KPI_USERS    = {p1['total']};
const KPI_CRITICAL = {p4s.get('Critical',0)};
const KPI_DARKWEB  = {oi.get('DarkWebExposed',0)};
const KPI_EXPOSED  = {oi.get('TotalExposed',0)};
const KPI_MFA      = {p4s.get('MFAGaps',0)};

// ── Navigation ───────────────────────────────────────────────
const PANELS = ['overview','p1','p2','p3','p4','osint','nist','logs'];
function show(id) {{
  PANELS.forEach(p => {{
    document.getElementById('panel-'+p).classList.toggle('active', p===id);
    document.getElementById('nav-'+p).classList.toggle('active', p===id);
  }});
  if (!window._chartsBuilt) {{ buildCharts(); window._chartsBuilt=true; }}
}}

// ── Clock ────────────────────────────────────────────────────
function tick() {{
  const now = new Date();
  document.getElementById('clock').textContent =
    now.toTimeString().slice(0,8);
}}
setInterval(tick,1000); tick();

// ── Counters ─────────────────────────────────────────────────
function animateCounters() {{
  document.querySelectorAll('.counter').forEach(el => {{
    const target = parseInt(el.dataset.target)||0;
    let current = 0;
    const step = Math.max(1, Math.round(target/60));
    const iv = setInterval(()=>{{
      current = Math.min(current+step, target);
      el.textContent = current.toLocaleString();
      if(current>=target) clearInterval(iv);
    }},16);
  }});
}}

// KPI counters
function animateKPI(id, target) {{
  let c=0; const step=Math.max(1,Math.round(target/50));
  const el=document.getElementById(id);
  const iv=setInterval(()=>{{
    c=Math.min(c+step,target);
    el.textContent=c.toLocaleString();
    if(c>=target) clearInterval(iv);
  }},20);
}}

// ── Log filter ───────────────────────────────────────────────
const RAW_LOG = document.getElementById('log-viewer').textContent;
function filterLog(term) {{
  const el = document.getElementById('log-viewer');
  document.getElementById('log-search').value = term;
  if (!term) {{ el.textContent = RAW_LOG; colourLog(); return; }}
  const lines = RAW_LOG.split('\\n').filter(l => l.toLowerCase().includes(term.toLowerCase()));
  el.textContent = lines.join('\\n');
  colourLog();
}}
function colourLog() {{
  const el = document.getElementById('log-viewer');
  el.innerHTML = el.innerHTML
    .replace(/(\[INFO\s*\])/g,'<span class="log-info">$1</span>')
    .replace(/(\[WARNING\s*\])/g,'<span class="log-warn">$1</span>')
    .replace(/(\[ERROR\s*\])/g,'<span class="log-error">$1</span>')
    .replace(/(\[EXPOSED[^\]]*\])/g,'<span class="log-exposed">$1</span>');
}}
colourLog();

// ── Chart.js defaults ────────────────────────────────────────
Chart.defaults.color='#5a7a9a';
Chart.defaults.borderColor='#1a3050';
Chart.defaults.plugins.legend.labels.boxWidth=12;
Chart.defaults.plugins.legend.labels.padding=16;

const COLOURS={{
  red:'#ef4444',amber:'#f59e0b',green:'#10b981',cyan:'#00d4ff',
  blue:'#3b82f6',purple:'#a855f7',
  redA:'rgba(239,68,68,.7)',amberA:'rgba(245,158,11,.7)',
  greenA:'rgba(16,185,129,.7)',blueA:'rgba(59,130,246,.7)',purpleA:'rgba(168,85,247,.7)',
}};

function donut(id,labels,data,colors){{
  new Chart(document.getElementById(id),{{
    type:'doughnut',
    data:{{labels,datasets:[{{data,backgroundColor:colors,borderWidth:2,borderColor:'#071220',hoverOffset:6}}]}},
    options:{{cutout:'65%',plugins:{{legend:{{position:'right'}},tooltip:{{callbacks:{{label:c=>` ${{c.label}}: ${{c.raw}}`}}}}}}}}
  }});
}}
function hbar(id,labels,data,color,label){{
  new Chart(document.getElementById(id),{{
    type:'bar',
    data:{{labels,datasets:[{{label,data,backgroundColor:color,borderRadius:4,borderSkipped:false}}]}},
    options:{{indexAxis:'y',plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{color:'#1a3050'}}}},y:{{grid:{{display:false}}}}}}}}
  }});
}}
function vbar(id,labels,datasets){{
  new Chart(document.getElementById(id),{{
    type:'bar',
    data:{{labels,datasets}},
    options:{{plugins:{{legend:{{position:'top'}}}},scales:{{x:{{stacked:true,grid:{{display:false}}}},y:{{stacked:true,grid:{{color:'#1a3050'}}}}}}}}
  }});
}}
function line(id,labels,datasets){{
  new Chart(document.getElementById(id),{{
    type:'line',
    data:{{labels,datasets}},
    options:{{
      plugins:{{legend:{{position:'top'}}}},
      scales:{{x:{{grid:{{color:'#1a3050'}}}},y:{{grid:{{color:'#1a3050'}},min:0,max:100,ticks:{{callback:v=>v+'%'}}}}}},
      elements:{{line:{{tension:.4}},point:{{radius:4}}}}
    }}
  }});
}}

// ── Build all charts ──────────────────────────────────────────
function buildCharts(){{

  // Overview — risk donut
  donut('ov-donut',
    ['Critical','High','Medium','Low'],
    [{p4s.get('Critical',0)},{p4s.get('High',0)},{p4s.get('Medium',0)},{p4s.get('Low',0)}],
    [COLOURS.red,COLOURS.amber,COLOURS.blue,COLOURS.green]
  );

  // Overview — dept threats stacked
  vbar('ov-dept',{jl(depts)},[
    {{label:'Critical',data:{jl(p4_dept_critical)},backgroundColor:COLOURS.red,borderRadius:3}},
    {{label:'High',    data:{jl(p4_dept_high)},    backgroundColor:COLOURS.amber,borderRadius:3}},
    {{label:'Medium',  data:{jl(p4_dept_medium)},  backgroundColor:COLOURS.blue,borderRadius:3}},
  ]);

  // Overview — prediction line
  line('ov-predict',{jl(pred_months)},[
    {{label:'Credential Exposure %',data:{jl(pred_exp)},borderColor:COLOURS.amber,backgroundColor:'rgba(245,158,11,.08)',fill:true}},
    {{label:'Dark Web Exposure %',  data:{jl(pred_dw)}, borderColor:COLOURS.red,  backgroundColor:'rgba(239,68,68,.08)',  fill:true}},
  ]);

  // Overview — tool coverage bar
  hbar('ov-tools',{jl(tool_labels)},{jl(tool_vals)},
    [COLOURS.cyan,COLOURS.blue,COLOURS.green,COLOURS.purple],'Users Found');

  // P1 — dept
  new Chart(document.getElementById('p1-dept'),{{
    type:'bar',
    data:{{labels:{jl(dept_labels)},datasets:[{{label:'Users',data:{jl(dept_vals)},
      backgroundColor:['#00d4ff','#a855f7','#10b981','#f59e0b','#3b82f6','#ef4444'],borderRadius:5}}]}},
    options:{{plugins:{{legend:{{display:false}}}},scales:{{x:{{grid:{{display:false}}}},y:{{grid:{{color:'#1a3050'}}}}}}}}
  }});

  // P1 — location donut
  donut('p1-loc',{jl(loc_labels)},{jl(loc_vals)},
    [COLOURS.cyan,COLOURS.purple,COLOURS.green,COLOURS.amber,COLOURS.blue]);

  // P2 — state donut
  donut('p2-donut',
    ['Enforced','Report-Only','Disabled','Missing'],
    [{p2_states['ENFORCED']},{p2_states['REPORT-ONLY']},{p2_states['DISABLED']},{p2_states['MISSING']}],
    [COLOURS.green,COLOURS.amber,COLOURS.red,'#6b7280']
  );

  // P2 — per policy bar
  const stateColors={jl(p2_pol_states)}.map(v=>
    v===3?COLOURS.green:v===2?COLOURS.amber:v===1?COLOURS.red:'#6b7280');
  new Chart(document.getElementById('p2-bar'),{{
    type:'bar',
    data:{{labels:{jl(p2_pol_names)},datasets:[{{data:{jl(p2_pol_states)},backgroundColor:stateColors,borderRadius:4}}]}},
    options:{{
      indexAxis:'y',plugins:{{legend:{{display:false}},
        tooltip:{{callbacks:{{label:c=>['Missing','Disabled','Report-Only','Enforced'][c.raw]||c.raw}}}}}},
      scales:{{x:{{min:0,max:3,grid:{{color:'#1a3050'}},ticks:{{stepSize:1,callback:v=>['','Disabled','Report','Enforced'][v]||''}}}},y:{{grid:{{display:false}}}}}}
    }}
  }});

  // P3 — role bar
  hbar('p3-bar',{jl(p3_role_abbr)},{jl(p3_role_vals)},COLOURS.purple,'Eligible Users');

  // P3 — role donut
  donut('p3-donut',{jl(p3_role_abbr)},{jl(p3_role_vals)},
    [COLOURS.cyan,COLOURS.purple,COLOURS.blue,COLOURS.amber,COLOURS.green,COLOURS.red]);

  // P4 — tier donut
  donut('p4-donut',
    ['Critical','High','Medium','Low'],
    [{p4s.get('Critical',0)},{p4s.get('High',0)},{p4s.get('Medium',0)},{p4s.get('Low',0)}],
    [COLOURS.red,COLOURS.amber,COLOURS.blue,COLOURS.green]
  );

  // P4 — dept stacked
  vbar('p4-dept',{jl(depts)},[
    {{label:'Critical',data:{jl(p4_dept_critical)},backgroundColor:COLOURS.red}},
    {{label:'High',    data:{jl(p4_dept_high)},    backgroundColor:COLOURS.amber}},
    {{label:'Medium',  data:{jl(p4_dept_medium)},  backgroundColor:COLOURS.blue}},
  ]);

  // OSINT — dept exposure rate
  hbar('osint-dept',{jl(osint_dept_labels)},{jl(osint_dept_exp_rate)},
    COLOURS.amber,'Exposure Rate (%)');

  // OSINT — top sources
  hbar('osint-sources',{jl(osint_src_labels)},{jl(osint_src_vals)},
    COLOURS.purple,'Affected Users');

  // OSINT — categories donut
  donut('osint-cats',{jl(osint_cat_labels)},{jl(osint_cat_vals)},
    [COLOURS.red,COLOURS.amber,COLOURS.blue,COLOURS.purple,COLOURS.cyan,COLOURS.green,'#e879f9','#22d3ee']);

  // OSINT — dark web by dept
  hbar('osint-dw',{jl(osint_dept_labels)},{jl(osint_dept_darkweb)},
    COLOURS.red,'Dark Web Users');
}}

// ── Init ─────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', ()=>{{
  animateKPI('kpi-users',   KPI_USERS);
  animateKPI('kpi-critical',KPI_CRITICAL);
  animateKPI('kpi-darkweb', KPI_DARKWEB);
  animateKPI('kpi-exposed', KPI_EXPOSED);
  animateKPI('kpi-mfa',     KPI_MFA);
  animateCounters();
  buildCharts();
  window._chartsBuilt = true;
}});
</script>
</body>
</html>"""


# ── Main ──────────────────────────────────────────────────────

def main():
    print("\n=========================================")
    print(" MediZuva — Central Dashboard Generator")
    print("=========================================")

    p1, p2, p3, p4, osint, nist, log_txt = load_all()
    print(f"  P1 personas   : {p1['total']}")
    p2_policies_n = len((p2 or {}).get('Policies', []))
    p3_eligible_n = (p3 or {}).get('Summary', {}).get('TotalEligible', 0)
    p4_critical_n = (p4 or {}).get('Summary', {}).get('Critical', 0)
    osint_exp_n   = (osint or {}).get('ExposedCount', 0)
    nist_score_n  = (nist or {}).get('ComplianceScore', 0)
    print(f"  P2 CA policies: {p2_policies_n}")
    print(f"  P3 PIM roles  : {p3_eligible_n} eligible")
    print(f"  P4 threat     : {p4_critical_n} critical")
    print(f"  OSINT exposed : {osint_exp_n} users")
    print(f"  NIST score    : {nist_score_n:.1f}%")
    print(f"  Log lines     : {log_txt.count(chr(10))}")

    html = build_html(p1, p2, p3, p4, osint, nist, log_txt)
    OUT_HTML.write_text(html, encoding="utf-8")
    print(f"\n[OK] Dashboard written: {OUT_HTML}")
    print("     Open in browser or serve with: python -m http.server 8080 (in data/)\n")


if __name__ == "__main__":
    main()
