"""
pillar4_threat/seed_osint_data.py
============================================================
Generates realistic simulated OSINT data for all 500 MediZuva
personas, seeded from the existing threat_audit.json exposure
flags (HIBPExp = True/False).

The top 25 CRITICAL users receive "perfect exposure" records:
  - DeHashed: full records (plaintext/cracked passwords, phone,
    IP address, physical address, date of birth)
  - HIBP: 3-6 breaches with diverse healthcare-relevant data classes
  - LeakCheck: 2-4 sources
  - IntelX: 1-3 paste hits with preview snippets

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

rng = random.Random(42)

# ── Breach source pool ─────────────────────────────────────────
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

TOOL_PROBS = {
    "CRITICAL":   (0.85, 0.95, 0.80, 0.75),
    "HIGH":       (0.55, 0.80, 0.55, 0.40),
    "not_exposed":(0.0,  0.0,  0.0,  0.0),
}

# Realistic cracked/weak passwords seen in breach dumps
WEAK_PASSWORDS = [
    "Summer2021!", "Password1!", "Admin@123", "Welcome1",
    "Healthcare2022", "Doctor@2023", "Nurse123!", "Medic@1",
    "Zim@mbabwe1", "Harare2022!", "P@ssword99", "Qwerty@123",
    "January2020!", "MediZuva1!", "Clinic@123", "Trust2021!",
    "Monday@1", "Spring2019!", "Nigeria123!", "Secure@2020",
    "Africa@2021", "Hospital1!", "Radiol0gy!", "Billing@99",
    "ICU2022Pass!",
]

# Realistic Zimbabwe/South Africa phone prefixes
PHONE_PREFIXES = ["+263 77", "+263 71", "+263 78", "+27 82", "+27 73", "+27 83"]

# Realistic Harare/Bulawayo/Mutare address streets
ZIM_STREETS = [
    "14 Samora Machel Ave", "3 Robert Mugabe Rd", "22 Borrowdale Rd",
    "5 Second St", "9 Fife Ave", "11 Enterprise Rd", "7 Churchill Ave",
    "18 Jason Moyo Ave", "4 Rotten Row", "33 Simon Muzenda St",
    "6 Mazowe Rd", "27 Princess Dr", "15 Central Ave",
]

ZIM_CITIES = ["Harare", "Bulawayo", "Mutare", "Gweru", "Masvingo"]

# IP ranges typical of Zimbabwe ISPs (ZESA, TelOne, Econet)
IP_RANGES = [
    "41.78.{}.{}", "154.68.{}.{}", "196.43.{}.{}",
    "41.55.{}.{}", "196.45.{}.{}", "102.65.{}.{}",
]

# HIBP data class sets keyed by breach richness
HIBP_DATA_CLASSES = {
    "standard":   ["Email addresses", "Passwords"],
    "rich":       ["Email addresses", "Passwords", "Phone numbers", "IP addresses"],
    "healthcare": ["Email addresses", "Passwords", "Dates of birth",
                   "Physical addresses", "Job titles", "Names"],
    "full":       ["Email addresses", "Passwords", "Phone numbers",
                   "Physical addresses", "Dates of birth", "IP addresses",
                   "Names", "Job titles"],
    "critical":   ["Email addresses", "Passwords", "Phone numbers",
                   "Physical addresses", "Dates of birth", "IP addresses",
                   "Names", "Job titles", "Medical records",
                   "Social security numbers"],
}

HIBP_BREACH_META = {
    "Collection-1":          {"date": "2019-01-07", "classes": "full"},
    "RaidForums-Archive":    {"date": "2022-04-12", "classes": "critical"},
    "LinkedIn-2021":         {"date": "2021-06-22", "classes": "rich"},
    "Exploit.in":            {"date": "2017-08-11", "classes": "critical"},
    "Adobe-2013":            {"date": "2013-10-04", "classes": "healthcare"},
    "Dropbox-2012":          {"date": "2016-08-31", "classes": "standard"},
    "MySpace-2008":          {"date": "2016-05-27", "classes": "standard"},
    "Canva-2019":            {"date": "2019-05-24", "classes": "rich"},
    "Chegg-2018":            {"date": "2018-09-19", "classes": "healthcare"},
    "Zynga-2019":            {"date": "2019-09-01", "classes": "standard"},
    "Verifications.io":      {"date": "2019-02-25", "classes": "full"},
    "AntiPublic-Combo":      {"date": "2021-06-01", "classes": "critical"},
    "Math-Way-2014":         {"date": "2014-03-15", "classes": "standard"},
    "000webhost-2015":       {"date": "2015-10-01", "classes": "standard"},
    "DataBreach.net":        {"date": "2023-03-18", "classes": "critical"},
    "Paste-Site-Combo-2024": {"date": "2024-01-15", "classes": "rich"},
}


def fake_bcrypt(seed: str) -> str:
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"$2b$12${h[:22]}{h[22:53]}"


def fake_md5(seed: str) -> str:
    return hashlib.md5(seed.encode()).hexdigest()


def fake_sha1(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()


def fake_phone() -> str:
    prefix = rng.choice(PHONE_PREFIXES)
    return f"{prefix} {rng.randint(100,999)} {rng.randint(1000,9999)}"


def fake_ip() -> str:
    fmt = rng.choice(IP_RANGES)
    return fmt.format(rng.randint(1, 254), rng.randint(1, 254))


def fake_dob() -> str:
    return f"{rng.randint(1965, 1998)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"


def fake_address() -> str:
    return f"{rng.choice(ZIM_STREETS)}, {rng.choice(ZIM_CITIES)}, Zimbabwe"


def pick_sources(tier: str, n: int) -> list:
    if n == 0:
        return []
    pool = [(s, cat) for s, prob, cat in BREACH_SOURCES if rng.random() < prob]
    if not pool:
        pool = [(BREACH_SOURCES[0][0], BREACH_SOURCES[0][2])]
    rng.shuffle(pool)
    return pool[:n]


def make_dh_record(src: str, upn: str, perfect: bool) -> dict:
    uname = upn.split("@")[0]
    if perfect:
        # Full, rich record with cracked/plaintext password
        pwd_clear = rng.choice(WEAK_PASSWORDS)
        hash_type = rng.choice(["plain", "md5", "sha1"])
        if hash_type == "plain":
            pwd_hash  = ""
            pwd_plain = pwd_clear
        elif hash_type == "md5":
            pwd_hash  = fake_md5(pwd_clear)
            pwd_plain = f"[CRACKED] {pwd_clear}"
        else:
            pwd_hash  = fake_sha1(pwd_clear)
            pwd_plain = f"[CRACKED] {pwd_clear}"
        return {
            "database_name":   src,
            "username":        uname,
            "email":           upn,
            "password":        pwd_plain,
            "hashed_password": pwd_hash,
            "phone":           fake_phone(),
            "ip_address":      fake_ip(),
            "address":         fake_address(),
            "dob":             fake_dob(),
            "name":            uname.replace(".", " ").title(),
        }
    else:
        return {
            "database_name":   src,
            "username":        uname,
            "password":        "",
            "hashed_password": fake_bcrypt(f"{upn}{src}"),
            "ip_address":      "",
        }


def make_hibp_breach(src: str, perfect: bool) -> dict:
    meta    = HIBP_BREACH_META.get(src, {"date": "2020-01-01", "classes": "standard"})
    classes = HIBP_DATA_CLASSES[meta["classes"] if perfect else "standard"]
    return {
        "Name":        src,
        "BreachDate":  meta["date"],
        "DataClasses": classes,
    }


def make_ix_hit(src: str, upn: str) -> dict:
    snippets = [
        f"{upn}:Summer2021!",
        f"email={upn} pass=Welcome1",
        f"Found in credential dump: {upn}",
        f"[BREACH] {upn} — plaintext recovered",
        f"user:{upn.split('@')[0]} pwd:Clinic@2022",
    ]
    return {
        "name":     src,
        "systemid": rng.randint(10000, 99999),
        "date":     f"20{rng.randint(20,25):02d}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}",
        "preview":  rng.choice(snippets),
    }


def build_user_result(u: dict, perfect: bool = False) -> dict:
    upn       = u["UPN"]
    name      = u["Name"]
    dept      = u["Department"]
    title     = u["JobTitle"]
    loc       = u["Location"]
    tier      = u["Tier"]
    exposed   = u["HIBPExp"]
    risk_score= u["RiskScore"]

    if perfect:
        n_findings = rng.randint(4, 6)
        exposed    = True
    elif not exposed:
        n_findings = 0
    elif tier == "CRITICAL":
        n_findings = rng.randint(3, 5)
    elif tier == "HIGH":
        n_findings = rng.randint(1, 3)
    else:
        n_findings = 1

    sources = pick_sources(tier if exposed else "not_exposed", n_findings)
    if exposed and tier == "CRITICAL" and not any(cat == "dark_web" for _, cat in sources):
        sources = [("RaidForums-Archive", "dark_web")] + sources[1:]
    if perfect and not any(cat == "dark_web" for _, cat in sources):
        sources = [("RaidForums-Archive", "dark_web"), ("Exploit.in", "dark_web")] + sources[:-2]

    breach_source_names = [s for s, _ in sources]
    categories          = list({cat for _, cat in sources})

    if perfect:
        exp_score = 100
    elif not exposed:
        exp_score = 0
    elif tier == "CRITICAL":
        exp_score = min(100, 60 + n_findings * 8 + rng.randint(0, 10))
    elif tier == "HIGH":
        exp_score = min(59, 25 + n_findings * 10 + rng.randint(0, 8))
    else:
        exp_score = rng.randint(10, 24)

    dark_web = any(cat == "dark_web" for _, cat in sources) and exposed

    t_probs  = TOOL_PROBS.get(tier if exposed else "not_exposed", TOOL_PROBS["not_exposed"])
    use_hibp = exposed and (perfect or rng.random() < t_probs[0])
    use_dh   = exposed and (perfect or rng.random() < t_probs[1])
    use_lc   = exposed and (perfect or rng.random() < t_probs[2])
    use_ix   = exposed and (perfect or rng.random() < t_probs[3])

    if exposed and not any([use_hibp, use_dh, use_lc, use_ix]):
        use_dh = True

    hibp_breaches, dh_records, lc_srcs, ix_hits = [], [], [], []

    if perfect:
        # Perfect users: all tools hit, rich records
        for i, (src, cat) in enumerate(sources):
            if i < 2:
                hibp_breaches.append(make_hibp_breach(src, perfect=True))
            if i < 3:
                dh_records.append(make_dh_record(src, upn, perfect=True))
            if i < 2:
                lc_srcs.append(src)
            if i < 1:
                ix_hits.append(make_ix_hit(src, upn))
        # Ensure DeHashed has at least 3 records
        while len(dh_records) < 3 and sources:
            extra_src = rng.choice(sources)[0]
            dh_records.append(make_dh_record(extra_src, upn, perfect=True))
    else:
        for src, cat in sources:
            tool_pick = rng.choice(
                ([0] if use_hibp else []) +
                ([1] if use_dh   else []) +
                ([2] if use_lc   else []) +
                ([3] if use_ix   else []) or [1]
            )
            if tool_pick == 0:
                hibp_breaches.append(make_hibp_breach(src, perfect=False))
            elif tool_pick == 1:
                dh_records.append(make_dh_record(src, upn, perfect=False))
            elif tool_pick == 2:
                lc_srcs.append(src)
            elif tool_pick == 3:
                ix_hits.append(make_ix_hit(src, upn))

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
        "PerfectExposure": perfect,
        "HIBP":     {"source": "hibp",      "found": bool(hibp_breaches), "breaches": hibp_breaches, "count": len(hibp_breaches)},
        "DeHashed": {"source": "dehashed",  "found": bool(dh_records),   "records":  dh_records,   "count": len(dh_records)},
        "LeakCheck":{"source": "leakcheck", "found": bool(lc_srcs),      "sources":  lc_srcs,      "count": len(lc_srcs)},
        "IntelX":   {"source": "intelx",    "found": bool(ix_hits),      "hits":     ix_hits,      "count": len(ix_hits)},
    }


def build_threat_intel(results: list, total_users: int) -> dict:
    exposed   = [r for r in results if r["Exposed"]]
    dark_web  = [r for r in results if r["DarkWebExposure"]]
    exp_count = len(exposed)
    dw_count  = len(dark_web)
    avg_score = round(sum(r["ExposureScore"] for r in exposed) / exp_count, 1) if exposed else 0

    dept_map = defaultdict(lambda: {"TotalUsers": 0, "ExposedUsers": 0, "DarkWebUsers": 0,
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
        v["ExposureRatePct"]  = round(v["ExposedUsers"] / v["TotalUsers"] * 100, 1) if v["TotalUsers"] else 0
        v["DarkWebRatePct"]   = round(v["DarkWebUsers"] / v["TotalUsers"] * 100, 1) if v["TotalUsers"] else 0
        v["AvgExposureScore"] = round(sum(scores) / len(scores), 1) if scores else 0
        dept_bk[d] = v

    src_counter: Counter = Counter()
    for r in exposed:
        for s in r["BreachSources"]:
            src_counter[s] += 1
    top_sources = [{"Source": s, "AffectedUsers": c} for s, c in src_counter.most_common(10)]

    cat_counter: Counter = Counter()
    for r in exposed:
        for c in r["Categories"]:
            cat_counter[c] += 1

    tool_counts = {
        "HIBP":      sum(1 for r in results if r["HIBP"]["found"]),
        "DeHashed":  sum(1 for r in results if r["DeHashed"]["found"]),
        "LeakCheck": sum(1 for r in results if r["LeakCheck"]["found"]),
        "IntelX":    sum(1 for r in results if r["IntelX"]["found"]),
    }

    title_counter: Counter = Counter(r["JobTitle"] for r in exposed)
    top_titles = [{"Title": t, "Count": c} for t, c in title_counter.most_common(8)]

    top_indiv = sorted(exposed, key=lambda r: (r["ExposureScore"], r["TotalFindings"]), reverse=True)[:15]
    highest_risk = [{
        "Name":          r["Name"],
        "Email":         r["Email"],
        "Department":    r["Department"],
        "JobTitle":      r["JobTitle"],
        "Location":      r["Location"],
        "ExposureScore": r["ExposureScore"],
        "DarkWeb":       r["DarkWebExposure"],
        "TotalFindings": r["TotalFindings"],
        "Sources":       r["BreachSources"],
        "PerfectExposure": r.get("PerfectExposure", False),
        "DeHashedCount": r["DeHashed"]["count"],
        "HIBPCount":     r["HIBP"]["count"],
    } for r in top_indiv]

    recs = []
    if dw_count > 0:
        recs.append({"Priority": "CRITICAL",
                     "Action": f"Immediate forced password reset for all {dw_count} users with dark web / paste site credential exposure",
                     "AffectedCount": dw_count,
                     "Rationale": f"{dw_count} user credentials are actively circulating on dark web forums and paste sites. Treat as confirmed account compromise."})
    recs.append({"Priority": "CRITICAL",
                 "Action": "Enable Entra ID Identity Protection Risky User remediation to auto-block on confirmed breach",
                 "AffectedCount": exp_count,
                 "Rationale": f"{exp_count} accounts ({round(exp_count/total_users*100,1)}%) confirmed in external breach databases. Manual remediation at this scale is not sustainable."})
    perfect_count = sum(1 for r in results if r.get("PerfectExposure"))
    if perfect_count > 0:
        recs.append({"Priority": "CRITICAL",
                     "Action": f"Isolate and investigate {perfect_count} accounts with full credential exposure (plaintext passwords, PII, medical data recovered from DeHashed)",
                     "AffectedCount": perfect_count,
                     "Rationale": f"DeHashed records confirm plaintext/cracked passwords AND personal identifiers (DOB, phone, address) for {perfect_count} users. These accounts must be treated as fully compromised."})
    top_dept = max(dept_bk, key=lambda d: dept_bk[d]["ExposureRatePct"]) if dept_bk else "Unknown"
    top_rate  = dept_bk.get(top_dept, {}).get("ExposureRatePct", 0)
    recs.append({"Priority": "HIGH",
                 "Action": f"Priority MFA enforcement and CA tightening for {top_dept} department",
                 "AffectedCount": dept_bk.get(top_dept, {}).get("ExposedUsers", 0),
                 "Rationale": f"{top_dept} has a {top_rate}% credential exposure rate — highest across all departments."})
    recs.append({"Priority": "HIGH",
                 "Action": "Enable Entra ID Password Protection with custom banned-password list seeded from breach dumps",
                 "AffectedCount": exp_count,
                 "Rationale": "Credential dump exposure means plaintext or crackable hashes are in the wild. Password Protection blocks re-use at authentication time."})
    recs.append({"Priority": "HIGH",
                 "Action": "Deploy Microsoft Sentinel UEBA to correlate OSINT exposure with sign-in anomalies",
                 "AffectedCount": None,
                 "Rationale": "Cross-referencing dark web exposure with unusual sign-in patterns allows early detection of account takeover in progress."})
    recs.append({"Priority": "HIGH",
                 "Action": f"Audit {tool_counts['DeHashed']} DeHashed-matched accounts for credential stuffing attempts in Entra sign-in logs",
                 "AffectedCount": tool_counts["DeHashed"],
                 "Rationale": f"DeHashed records include cracked passwords for {tool_counts['DeHashed']} users. Credential stuffing against M365 login is a confirmed risk vector."})
    recs.append({"Priority": "MEDIUM",
                 "Action": "Integrate OSINT checks into the joiner provisioning workflow (pre-hire screening)",
                 "AffectedCount": None,
                 "Rationale": "Proactive breach screening at onboarding prevents new hires from bringing compromised credentials into MediZuva."})
    recs.append({"Priority": "MEDIUM",
                 "Action": f"Notify {tool_counts['HIBP']} users found in HIBP to change passwords immediately",
                 "AffectedCount": tool_counts["HIBP"],
                 "Rationale": "HIBP exposes breach membership publicly. Targeted notifications with mandatory reset prevent further compromise."})
    recs.append({"Priority": "LOW",
                 "Action": "Enrol all MediZuva domains in HIBP domain monitoring for real-time breach alerts",
                 "AffectedCount": None,
                 "Rationale": "HIBP domain monitoring notifies the security team within hours of a breach affecting @micrlabs.onmicrosoft.com."})

    return {
        "GeneratedAt": SCAN_DATE,
        "Overview": {
            "TotalPersonas":    total_users,
            "TotalExposed":     exp_count,
            "ExposureRatePct":  round(exp_count / total_users * 100, 1),
            "DarkWebExposed":   dw_count,
            "DarkWebRatePct":   round(dw_count / total_users * 100, 1),
            "AvgExposureScore": avg_score,
            "PerfectExposure":  perfect_count,
        },
        "SourceToolCounts":       tool_counts,
        "DepartmentBreakdown":    dept_bk,
        "TopBreachSources":       top_sources,
        "BreachCategories":       dict(cat_counter),
        "MostExposedTitles":      top_titles,
        "HighestRiskIndividuals": highest_risk,
        "Recommendations":        recs,
    }


def build_log(results: list) -> str:
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
            lines.append(f"{SCAN_DATE} [INFO    ] [CLEAN      ] {r['Name']:<35} | {r['JobTitle']:<25} | score=  0 | findings=0")
            continue
        dw_tag  = "[DARK WEB  ]" if r["DarkWebExposure"] else "[BREACH    ]"
        pf_tag  = " [PERFECT]"   if r.get("PerfectExposure") else ""
        srcs    = ", ".join(r["BreachSources"])
        lines.append(
            f"{SCAN_DATE} [INFO    ] [EXPOSED {dw_tag}]{pf_tag} {r['Name']:<35}"
            f" | {r['JobTitle']:<25} | score={r['ExposureScore']:3d}"
            f" | findings={r['TotalFindings']} | DH={r['DeHashed']['count']} HIBP={r['HIBP']['count']}"
            f" | sources={srcs}"
        )
        if r.get("PerfectExposure"):
            for rec in r["DeHashed"].get("records", []):
                pwd = rec.get("password", "")
                if pwd:
                    lines.append(
                        f"{SCAN_DATE} [WARN    ]   [DeHashed] {r['Email']}"
                        f" — DB='{rec['database_name']}'"
                        f" pwd='{pwd}' phone='{rec.get('phone','')}' ip='{rec.get('ip_address','')}'"
                    )
        else:
            for src in r["BreachSources"]:
                lines.append(f"{SCAN_DATE} [DEBUG   ]   -> DeHashed SIM [{r['Email']}] — ['{src}']")
    lines += [
        f"{SCAN_DATE} [INFO    ] ",
        f"{SCAN_DATE} [INFO    ] ============================================================",
        f"{SCAN_DATE} [INFO    ] SCAN COMPLETE",
        f"{SCAN_DATE} [INFO    ]   Total personas   : {len(results)}",
        f"{SCAN_DATE} [INFO    ]   Exposed          : {len(exposed)} ({round(len(exposed)/len(results)*100,1)}%)",
        f"{SCAN_DATE} [INFO    ]   Perfect exposure : {sum(1 for r in results if r.get('PerfectExposure'))}",
        f"{SCAN_DATE} [INFO    ]   Dark web hits    : {sum(1 for r in results if r['DarkWebExposure'])}",
        f"{SCAN_DATE} [INFO    ]   Avg exp score    : {round(sum(r['ExposureScore'] for r in exposed)/len(exposed),1) if exposed else 0}/100",
        f"{SCAN_DATE} [INFO    ] ============================================================",
    ]
    return "\n".join(lines)


def main():
    print("\n==============================================")
    print(" MediZuva — OSINT Data Seeder (All 500 Users)")
    print("==============================================\n")

    p4    = json.loads(THREAT_OUT.read_text("utf-8"))
    users = p4["UserRisks"]
    print(f"  Loaded {len(users)} users from threat_audit.json")

    # Identify top 25 CRITICAL users as "perfect exposure" subjects
    critical_users = [u for u in users if u["Tier"] == "CRITICAL" and u["HIBPExp"]]
    rng_select     = random.Random(99)
    rng_select.shuffle(critical_users)
    perfect_upns   = {u["UPN"] for u in critical_users[:25]}
    print(f"  Perfect exposure candidates: {len(perfect_upns)} (CRITICAL + HIBP exposed)")

    results = []
    for u in users:
        perfect = u["UPN"] in perfect_upns
        results.append(build_user_result(u, perfect=perfect))

    exposed      = [r for r in results if r["Exposed"]]
    dark_web     = [r for r in results if r["DarkWebExposure"]]
    perfect_list = [r for r in results if r.get("PerfectExposure")]
    print(f"  Exposed        : {len(exposed)} / {len(results)}")
    print(f"  Perfect (100)  : {len(perfect_list)}")
    print(f"  Dark web       : {len(dark_web)}")
    print(f"  Avg score      : {round(sum(r['ExposureScore'] for r in exposed)/len(exposed),1) if exposed else 0}")
    print(f"  DeHashed hits  : {sum(1 for r in results if r['DeHashed']['found'])}")

    ti = build_threat_intel(results, len(results))
    print(f"  Top source     : {ti['TopBreachSources'][0]['Source']} ({ti['TopBreachSources'][0]['AffectedUsers']} users)")

    combined = {
        "ScanDate":           SCAN_DATE,
        "Mode":               "simulate",
        "Sources":            {"HIBP": "simulate", "DeHashed": "simulate", "LeakCheck": "simulate", "IntelX": "simulate"},
        "TotalChecked":       len(results),
        "ExposedCount":       len(exposed),
        "PerfectExposureCount": len(perfect_list),
        "ThreatIntelligence": ti,
        "Results":            results,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "osint_combined_results.json").write_text(json.dumps(combined, indent=2), encoding="utf-8")
    (OUT_DIR / "osint_run.log").write_text(build_log(results), encoding="utf-8")

    hibp_exposed = [r for r in results if r["HIBP"]["found"]]
    hibp_out = {"ScanDate": SCAN_DATE, "TotalChecked": len(results),
                "ExposedCount": len(hibp_exposed), "Results": hibp_exposed}
    (OUT_DIR / "hibp_results.json").write_text(json.dumps(hibp_out, indent=2), encoding="utf-8")

    print(f"\n[OK] osint_combined_results.json — {len(results)} users, {len(exposed)} exposed, {len(perfect_list)} perfect")
    print(f"[OK] osint_run.log")
    print(f"[OK] hibp_results.json — {len(hibp_exposed)} HIBP hits")
    print("\nNext: python dashboard/generate_central_dashboard.py\n")


if __name__ == "__main__":
    main()
