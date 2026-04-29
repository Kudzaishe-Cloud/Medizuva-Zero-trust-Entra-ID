"""
pillar4_threat/seed_osint_data.py
============================================================
Generates realistic simulated OSINT data for all 500 MediZuva
personas, seeded from the existing threat_audit.json exposure
flags (HIBPExp = True/False).

Outputs:
  data/osint_results/osint_combined_results.json
  data/osint_results/osint_run.log
  data/osint_results/hibp_results.json

Run:
  python pillar4_threat/seed_osint_data.py
============================================================
"""

import json
import random
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT  = Path(__file__).resolve().parents[1]
THREAT_OUT = REPO_ROOT / "data" / "threat_audit.json"
OUT_DIR    = REPO_ROOT / "data" / "osint_results"
SCAN_DATE  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# Deterministic seed — reproducible on every run
rng = random.Random(42)

# ── Realistic breach source pool ──────────────────────────────
# Weighted by frequency in real healthcare-sector credential dumps
BREACH_SOURCES = [
    ("Collection-1",          0.38, "data_breach"),
    ("RaidForums-Archive",    0.35, "dark_web"),
    ("LinkedIn-2021",         0.28, "data_breach"),
    ("Exploit.in",            0.22, "dark_web"),
    ("Adobe-2013",            0.20, "data_breach"),
    ("Dropbox-2012",          0.17, "data_breach"),
    ("MySpace-2008",          0.15, "data_breach"),
    ("Canva-2019",            0.13, "data_breach"),
    ("Chegg-2018",            0.12, "data_breach"),
    ("Zynga-2019",            0.11, "data_breach"),
    ("Verifications.io",      0.10, "dark_web"),
    ("AntiPublic-Combo",      0.09, "dark_web"),
    ("Math-Way-2014",         0.08, "data_breach"),
    ("000webhost-2015",       0.08, "data_breach"),
    ("DataBreach.net",        0.07, "dark_web"),
    ("Paste-Site-Combo-2024", 0.06, "paste_site"),
]

# Tool assignment probability per exposure tier
# (prob_hibp, prob_dehashed, prob_leakcheck, prob_intelx)
TOOL_PROBS = {
    "CRITICAL": (0.85, 0.95, 0.80, 0.75),
    "HIGH":     (0.55, 0.80, 0.55, 0.40),
    "not_exposed": (0.0,  0.0,  0.0,  0.0),
}


def fake_bcrypt(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"$2b$12${h[:22]}{h[22:53]}"


def pick_sources(tier: str, n: int) -> list[tuple[str, str]]:
    if n == 0:
        return []
    pool = [(s, cat) for s, prob, cat in BREACH_SOURCES if rng.random() < prob]
    if not pool:
        pool = [(BREACH_SOURCES[0][0], BREACH_SOURCES[0][2])]
    rng.shuffle(pool)
    return pool[:n]


def build_user_result(u: dict) -> dict:
    upn       = u["UPN"]
    name      = u["Name"]
    dept      = u["Department"]
    title     = u["JobTitle"]
    loc       = u["Location"]
    tier      = u["Tier"]
    exposed   = u["HIBPExp"]
    mfa_gap   = u["MFAGap"]
    dev_gap   = u["DeviceGap"]
    risk_score= u["RiskScore"]

    # Number of breach findings based on tier
    if not exposed:
        n_findings = 0
    elif tier == "CRITICAL":
        n_findings = rng.randint(3, 6)
    elif tier == "HIGH":
        n_findings = rng.randint(1, 3)
    else:
        n_findings = 1

    sources = pick_sources(tier if exposed else "not_exposed", n_findings)
    # CRITICAL users must have at least one dark-web source
    if exposed and tier == "CRITICAL" and not any(cat == "dark_web" for _, cat in sources):
        sources[0] = ("RaidForums-Archive", "dark_web")
    breach_source_names = [s for s, _ in sources]
    categories          = list({cat for _, cat in sources})

    # Exposure score: weighted by tier + findings + risk_score
    if not exposed:
        exp_score = 0
    elif tier == "CRITICAL":
        exp_score = min(100, 60 + n_findings * 8 + rng.randint(0, 10))
    elif tier == "HIGH":
        exp_score = min(59, 25 + n_findings * 10 + rng.randint(0, 8))
    else:
        exp_score = rng.randint(10, 24)

    dark_web = any(cat == "dark_web" for _, cat in sources) and exposed

    # Tool hit assignment
    t_probs  = TOOL_PROBS.get(tier if exposed else "not_exposed", TOOL_PROBS["not_exposed"])
    use_hibp = exposed and rng.random() < t_probs[0]
    use_dh   = exposed and rng.random() < t_probs[1]
    use_lc   = exposed and rng.random() < t_probs[2]
    use_ix   = exposed and rng.random() < t_probs[3]

    # At least one tool must have a hit if exposed
    if exposed and not any([use_hibp, use_dh, use_lc, use_ix]):
        use_dh = True

    # Distribute sources across tools
    hibp_breaches, dh_records, lc_srcs, ix_hits = [], [], [], []
    for i, (src, cat) in enumerate(sources):
        tool_pick = rng.choice(
            ([0] if use_hibp else []) +
            ([1] if use_dh   else []) +
            ([2] if use_lc   else []) +
            ([3] if use_ix   else []) or [1]
        )
        uname = upn.split("@")[0]
        if tool_pick == 0:
            hibp_breaches.append({"Name": src, "BreachDate": f"20{rng.randint(8,23):02d}-{rng.randint(1,12):02d}-01",
                                   "DataClasses": ["Email addresses", "Passwords"]})
        elif tool_pick == 1:
            dh_records.append({"database_name": src, "username": uname, "password": "",
                                "hashed_password": fake_bcrypt(f"{upn}{src}"), "ip_address": ""})
        elif tool_pick == 2:
            lc_srcs.append(src)
        elif tool_pick == 3:
            ix_hits.append({"name": src, "systemid": rng.randint(10000, 99999),
                             "date": f"20{rng.randint(20,25):02d}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"})

    return {
        "Email":           upn,
        "Name":            name,
        "Department":      dept,
        "JobTitle":        title,
        "Location":        loc,
        "RiskScore":       risk_score,
        "Exposed":         exposed,
        "ExposureScore":   exp_score,
        "DarkWebExposure": dark_web,
        "TotalFindings":   n_findings,
        "BreachSources":   breach_source_names,
        "Categories":      categories,
        "HIBP":     {"source": "hibp",      "found": bool(hibp_breaches), "breaches":  hibp_breaches, "count": len(hibp_breaches)},
        "DeHashed": {"source": "dehashed",  "found": bool(dh_records),   "records":   dh_records,   "count": len(dh_records)},
        "LeakCheck":{"source": "leakcheck", "found": bool(lc_srcs),      "sources":   lc_srcs,      "count": len(lc_srcs)},
        "IntelX":   {"source": "intelx",    "found": bool(ix_hits),      "hits":      ix_hits,      "count": len(ix_hits)},
    }


def build_threat_intel(results: list[dict], total_users: int) -> dict:
    exposed   = [r for r in results if r["Exposed"]]
    dark_web  = [r for r in results if r["DarkWebExposure"]]
    exp_count = len(exposed)
    dw_count  = len(dark_web)
    avg_score = round(sum(r["ExposureScore"] for r in exposed) / exp_count, 1) if exposed else 0

    # Dept breakdown
    dept_map: dict = defaultdict(lambda: {"TotalUsers": 0, "ExposedUsers": 0, "DarkWebUsers": 0,
                                           "AvgExposureScore": 0, "_scores": []})
    for r in results:
        d = r["Department"]
        dept_map[d]["TotalUsers"] += 1
        if r["Exposed"]:
            dept_map[d]["ExposedUsers"] += 1
            dept_map[d]["_scores"].append(r["ExposureScore"])
        if r["DarkWebExposure"]:
            dept_map[d]["DarkWebUsers"] += 1
    dept_bk = {}
    for d, v in dept_map.items():
        scores = v.pop("_scores")
        v["ExposureRatePct"] = round(v["ExposedUsers"] / v["TotalUsers"] * 100, 1) if v["TotalUsers"] else 0
        v["DarkWebRatePct"]  = round(v["DarkWebUsers"] / v["TotalUsers"] * 100, 1) if v["TotalUsers"] else 0
        v["AvgExposureScore"]= round(sum(scores) / len(scores), 1) if scores else 0
        dept_bk[d] = v

    # Top breach sources
    src_counter: Counter = Counter()
    for r in exposed:
        for s in r["BreachSources"]:
            src_counter[s] += 1
    top_sources = [{"Source": s, "AffectedUsers": c} for s, c in src_counter.most_common(10)]

    # Breach categories
    cat_counter: Counter = Counter()
    for r in exposed:
        for c in r["Categories"]:
            cat_counter[c] += 1

    # Tool counts
    tool_counts = {
        "HIBP":      sum(1 for r in results if r["HIBP"]["found"]),
        "DeHashed":  sum(1 for r in results if r["DeHashed"]["found"]),
        "LeakCheck": sum(1 for r in results if r["LeakCheck"]["found"]),
        "IntelX":    sum(1 for r in results if r["IntelX"]["found"]),
    }

    # Top job titles by exposure count
    title_counter: Counter = Counter(r["JobTitle"] for r in exposed)
    top_titles = [{"Title": t, "Count": c} for t, c in title_counter.most_common(8)]

    # Highest risk individuals
    top_indiv = sorted(exposed, key=lambda r: (r["ExposureScore"], r["TotalFindings"]), reverse=True)[:15]
    highest_risk = [{"Name": r["Name"], "Email": r["Email"], "Department": r["Department"],
                     "JobTitle": r["JobTitle"], "Location": r["Location"],
                     "ExposureScore": r["ExposureScore"], "DarkWeb": r["DarkWebExposure"],
                     "TotalFindings": r["TotalFindings"], "Sources": r["BreachSources"]} for r in top_indiv]

    # Recommendations
    recs = []
    dw_count_val = dw_count
    if dw_count_val > 0:
        recs.append({"Priority": "CRITICAL",
                     "Action": f"Immediate forced password reset for all {dw_count_val} users with dark web / paste site credential exposure",
                     "AffectedCount": dw_count_val,
                     "Rationale": f"{dw_count_val} user credentials are actively circulating on dark web forums and paste sites. Treat as confirmed account compromise."})
    recs.append({"Priority": "CRITICAL",
                 "Action": "Enable Entra ID Identity Protection Risky User remediation to auto-block on confirmed breach",
                 "AffectedCount": exp_count,
                 "Rationale": f"{exp_count} accounts ({round(exp_count/total_users*100,1)}%) are confirmed in external breach databases. Manual remediation at this scale is not sustainable."})
    top_dept = max(dept_bk, key=lambda d: dept_bk[d]["ExposureRatePct"]) if dept_bk else "Unknown"
    top_rate  = dept_bk.get(top_dept, {}).get("ExposureRatePct", 0)
    recs.append({"Priority": "HIGH",
                 "Action": f"Priority MFA enforcement and Conditional Access tightening for {top_dept} department",
                 "AffectedCount": dept_bk.get(top_dept, {}).get("ExposedUsers", 0),
                 "Rationale": f"{top_dept} has a {top_rate}% credential exposure rate — the highest across all departments. CA003 device compliance and CA001 MFA must be enforced immediately."})
    recs.append({"Priority": "HIGH",
                 "Action": "Enable Entra ID Password Protection with custom banned-password list seeded from breach dumps",
                 "AffectedCount": exp_count,
                 "Rationale": "Credential dump exposure means plaintext or crackable hashes are in the wild. Password Protection blocks re-use of known compromised passwords at authentication time."})
    recs.append({"Priority": "HIGH",
                 "Action": "Audit for username/password reuse across personal and work accounts",
                 "AffectedCount": tool_counts["DeHashed"],
                 "Rationale": f"DeHashed records ({tool_counts['DeHashed']} users) include usernames and bcrypt hashes. Credential stuffing against Microsoft 365 login is a real risk."})
    recs.append({"Priority": "HIGH",
                 "Action": "Deploy Microsoft Sentinel UEBA to correlate OSINT exposure with sign-in anomalies",
                 "AffectedCount": None,
                 "Rationale": "Cross-referencing dark web exposure with unusual sign-in patterns (new location, device, time) allows early detection of account takeover in progress."})
    recs.append({"Priority": "MEDIUM",
                 "Action": "Integrate OSINT checks into the joiner provisioning workflow (pre-hire screening)",
                 "AffectedCount": None,
                 "Rationale": "Proactive breach screening at onboarding prevents new hires from bringing compromised credentials into the MediZuva environment."})
    recs.append({"Priority": "MEDIUM",
                 "Action": f"Notify {tool_counts['HIBP']} users found in HIBP to change passwords immediately",
                 "AffectedCount": tool_counts["HIBP"],
                 "Rationale": "HIBP exposes breach membership publicly. Targeted user notifications with mandatory password reset prevent further compromise."})
    recs.append({"Priority": "LOW",
                 "Action": "Schedule automated monthly OSINT re-scans — CI pipeline already supports this via osint.yml",
                 "AffectedCount": None,
                 "Rationale": "Breach exposure is dynamic. New leaks surface continuously. Monthly re-scans ensure newly compromised accounts are caught within 30 days."})
    recs.append({"Priority": "LOW",
                 "Action": "Enrol all MediZuva domains in HIBP domain monitoring for real-time breach alerts",
                 "AffectedCount": None,
                 "Rationale": "HIBP domain monitoring notifies the security team within hours of a breach affecting @micrlabs.onmicrosoft.com — no manual re-scan needed."})

    return {
        "GeneratedAt": SCAN_DATE,
        "Overview": {
            "TotalPersonas":    total_users,
            "TotalExposed":     exp_count,
            "ExposureRatePct":  round(exp_count / total_users * 100, 1),
            "DarkWebExposed":   dw_count,
            "DarkWebRatePct":   round(dw_count / total_users * 100, 1),
            "AvgExposureScore": avg_score,
        },
        "SourceToolCounts":     tool_counts,
        "DepartmentBreakdown":  dept_bk,
        "TopBreachSources":     top_sources,
        "BreachCategories":     dict(cat_counter),
        "MostExposedTitles":    top_titles,
        "HighestRiskIndividuals": highest_risk,
        "Recommendations":      recs,
    }


def build_log(results: list[dict]) -> str:
    exposed = [r for r in results if r["Exposed"]]
    lines = [
        f"{SCAN_DATE} [INFO    ] ============================================================",
        f"{SCAN_DATE} [INFO    ]  MediZuva — Multi-Source OSINT Check (Pillar 4)",
        f"{SCAN_DATE} [INFO    ]  Mode      : SIMULATE",
        f"{SCAN_DATE} [INFO    ]  HIBP      : SIMULATE",
        f"{SCAN_DATE} [INFO    ]  DeHashed  : SIMULATE",
        f"{SCAN_DATE} [INFO    ]  LeakCheck : SIMULATE",
        f"{SCAN_DATE} [INFO    ]  IntelX    : SIMULATE",
        f"{SCAN_DATE} [INFO    ] ============================================================",
        f"{SCAN_DATE} [INFO    ] Loaded {len(results)} personas from medizuva_500_personas.csv",
    ]
    for r in results:
        if not r["Exposed"]:
            lines.append(f"{SCAN_DATE} [INFO    ] [CLEAN   ] {r['Name']:<35} | {r['JobTitle']:<25} | score=  0 | findings=0")
            continue
        dw_tag = "[DARK WEB]" if r["DarkWebExposure"] else "[BREACH  ]"
        srcs   = ", ".join(r["BreachSources"])
        tier   = "CRITICAL" if r["ExposureScore"] >= 60 else "HIGH" if r["ExposureScore"] >= 25 else "MEDIUM"
        lines.append(
            f"{SCAN_DATE} [INFO    ] [EXPOSED {dw_tag}] {r['Name']:<35} | {r['JobTitle']:<25}"
            f" | score={r['ExposureScore']:3d} | findings={r['TotalFindings']} | sources={srcs}"
        )
        for src in r["BreachSources"]:
            lines.append(f"{SCAN_DATE} [DEBUG   ]   -> DeHashed SIM [{r['Email']}] — ['{src}']")
    lines += [
        f"{SCAN_DATE} [INFO    ] ",
        f"{SCAN_DATE} [INFO    ] ============================================================",
        f"{SCAN_DATE} [INFO    ] SCAN COMPLETE",
        f"{SCAN_DATE} [INFO    ]   Total personas   : {len(results)}",
        f"{SCAN_DATE} [INFO    ]   Exposed          : {len(exposed)} ({round(len(exposed)/len(results)*100,1)}%)",
        f"{SCAN_DATE} [INFO    ]   Dark web hits    : {sum(1 for r in results if r['DarkWebExposure'])}",
        f"{SCAN_DATE} [INFO    ]   Avg exp score    : {round(sum(r['ExposureScore'] for r in exposed)/len(exposed),1) if exposed else 0}/100",
        f"{SCAN_DATE} [INFO    ] ============================================================",
    ]
    return "\n".join(lines)


def main():
    print("\n==============================================")
    print(" MediZuva — OSINT Data Seeder (All 500 Users)")
    print("==============================================\n")

    p4 = json.loads(THREAT_OUT.read_text("utf-8"))
    users = p4["UserRisks"]
    print(f"  Loaded {len(users)} users from threat_audit.json")

    results = []
    for u in users:
        results.append(build_user_result(u))

    exposed    = [r for r in results if r["Exposed"]]
    dark_web   = [r for r in results if r["DarkWebExposure"]]
    print(f"  Exposed      : {len(exposed)} / {len(results)}")
    print(f"  Dark web     : {len(dark_web)}")
    print(f"  Avg score    : {round(sum(r['ExposureScore'] for r in exposed)/len(exposed),1) if exposed else 0}")

    ti = build_threat_intel(results, len(results))
    print(f"  Top dept     : {max(ti['DepartmentBreakdown'], key=lambda d: ti['DepartmentBreakdown'][d]['ExposureRatePct'])}")
    print(f"  Top source   : {ti['TopBreachSources'][0]['Source']} ({ti['TopBreachSources'][0]['AffectedUsers']} users)")

    combined = {
        "ScanDate":          SCAN_DATE,
        "Mode":              "simulate",
        "Sources":           {"HIBP": "simulate", "DeHashed": "simulate", "LeakCheck": "simulate", "IntelX": "simulate"},
        "TotalChecked":      len(results),
        "ExposedCount":      len(exposed),
        "ThreatIntelligence": ti,
        "Results":           results,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    (OUT_DIR / "osint_combined_results.json").write_text(
        json.dumps(combined, indent=2), encoding="utf-8"
    )
    (OUT_DIR / "osint_run.log").write_text(build_log(results), encoding="utf-8")

    hibp_exposed = [r for r in results if r["HIBP"]["found"]]
    hibp_out = {"ScanDate": SCAN_DATE, "TotalChecked": len(results),
                "ExposedCount": len(hibp_exposed), "Results": hibp_exposed}
    (OUT_DIR / "hibp_results.json").write_text(
        json.dumps(hibp_out, indent=2), encoding="utf-8"
    )

    print(f"\n[OK] osint_combined_results.json — {len(results)} users, {len(exposed)} exposed")
    print(f"[OK] osint_run.log")
    print(f"[OK] hibp_results.json — {len(hibp_exposed)} HIBP hits")
    print("\nNext: python dashboard/generate_central_dashboard.py\n")


if __name__ == "__main__":
    main()
