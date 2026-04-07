"""
pillar4_threat/osint_exposure_check.py
============================================================
Multi-source OSINT credential and identity exposure check.
Queries 4 tools against all 500 MediZuva personas and
derives threat intelligence from the aggregated results.

Tools integrated:
  1. Have I Been Pwned (HIBP)  — breach database (email)
  2. DeHashed                  — leaked credentials DB (email)
  3. LeakCheck                 — breach lookup (email)
  4. Intelligence X (IntelX)   — dark web / paste site scan

Modes:
  LIVE     — supply API keys via CLI args (see Usage below)
  SIMULATE — omit all keys; deterministic from RiskScore

Outputs:
  data/osint_results/osint_combined_results.json   <- rich multi-source
  data/osint_results/hibp_results.json             <- legacy (threat_audit.ps1)
  data/osint_results/osint_run.log                 <- full run log

Usage:
  python osint_exposure_check.py

  python osint_exposure_check.py \
      --hibp-key YOUR_HIBP_KEY \
      --dehashed-email you@email.com --dehashed-key YOUR_DEHASHED_KEY \
      --leakcheck-key YOUR_LEAKCHECK_KEY \
      --intelx-key YOUR_INTELX_KEY

  # Test with first 10 personas only:
  python osint_exposure_check.py --limit 10
============================================================
"""

import argparse
import base64
import json
import logging
import random
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path

import pandas as pd

# ── Paths ─────────────────────────────────────────────────────
REPO_ROOT    = Path(__file__).resolve().parents[1]
PERSONAS_CSV = REPO_ROOT / "data" / "personas" / "medizuva_500_personas.csv"
OUT_DIR      = REPO_ROOT / "data" / "osint_results"
OUT_COMBINED = OUT_DIR / "osint_combined_results.json"
OUT_HIBP     = OUT_DIR / "hibp_results.json"   # keeps threat_audit.ps1 working
OUT_LOG      = OUT_DIR / "osint_run.log"

# ── API Endpoints ─────────────────────────────────────────────
HIBP_BASE      = "https://haveibeenpwned.com/api/v3/breachedaccount"
DEHASHED_BASE  = "https://api.dehashed.com/search"
LEAKCHECK_BASE = "https://leakcheck.io/api/v2/query"
INTELX_SEARCH  = "https://2.intelx.io/intelligent/search"
INTELX_RESULTS = "https://2.intelx.io/intelligent/search/result"
USER_AGENT     = "MediZuva-ZeroTrust-OSINT/2.0"

# ── Simulation breach data ────────────────────────────────────
SIM_BREACHES = {
    "hibp":      ["LinkedIn", "Adobe", "Dropbox", "MyFitnessPal", "Canva", "Evite", "Chegg", "Zynga"],
    "dehashed":  ["Collection#1", "AntiPublic", "Exploit.in", "LinkedIn2021", "Deezer"],
    "leakcheck": ["Wattpad", "Tokopedia", "Gravatar", "MathWay", "Wishbone"],
    "intelx":    ["PasteBin-2023", "DarkForum-Health", "TelegramLeaks-2024", "RaidForums-Archive"],
}

BREACH_CATEGORIES = {
    "LinkedIn":             "social_media",
    "LinkedIn2021":         "social_media",
    "Adobe":                "software",
    "Dropbox":              "cloud_storage",
    "Canva":                "design_tool",
    "MyFitnessPal":         "health_app",
    "Chegg":                "education",
    "Evite":                "social_media",
    "Zynga":                "gaming",
    "Collection#1":         "credential_dump",
    "AntiPublic":           "credential_dump",
    "Exploit.in":           "dark_web",
    "Deezer":               "media_streaming",
    "Wattpad":              "social_media",
    "Tokopedia":            "ecommerce",
    "Gravatar":             "identity_service",
    "MathWay":              "education",
    "Wishbone":             "social_media",
    "PasteBin-2023":        "paste_site",
    "DarkForum-Health":     "dark_web",
    "TelegramLeaks-2024":   "messaging_platform",
    "RaidForums-Archive":   "dark_web",
}


# ══════════════════════════════════════════════════════════════
# LOGGER
# ══════════════════════════════════════════════════════════════

def setup_logger() -> logging.Logger:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("osint")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s [%(levelname)-8s] %(message)s", "%Y-%m-%d %H:%M:%S")

    # File handler — DEBUG level (full detail)
    fh = logging.FileHandler(OUT_LOG, encoding="utf-8", mode="w")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # Console handler — INFO level (clean output)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger


# ══════════════════════════════════════════════════════════════
# TOOL 1 — Have I Been Pwned (HIBP)
# Docs: haveibeenpwned.com/API/v3
# Free password check; email breach lookup requires ~$3.50/mo key
# ══════════════════════════════════════════════════════════════

def check_hibp_live(email: str, api_key: str, log: logging.Logger) -> dict:
    """
    Query HIBP API v3 for all breaches associated with an email.
    Returns full breach metadata including data classes exposed.
    Rate limit: 1 request per 1.5 seconds.
    """
    url = f"{HIBP_BASE}/{urllib.parse.quote(email)}?truncateResponse=false"
    req = urllib.request.Request(url, headers={
        "hibp-api-key": api_key,
        "User-Agent":   USER_AGENT,
    })
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
                breaches = [
                    {
                        "Name":        b["Name"],
                        "BreachDate":  b.get("BreachDate", ""),
                        "DataClasses": b.get("DataClasses", []),
                        "IsVerified":  b.get("IsVerified", False),
                        "IsSensitive": b.get("IsSensitive", False),
                    }
                    for b in data
                ]
                log.debug(f"HIBP LIVE [{email}] — {len(breaches)} breach(es)")
                return {"source": "hibp", "found": True, "breaches": breaches, "count": len(breaches)}

        except urllib.error.HTTPError as e:
            if e.code == 404:
                log.debug(f"HIBP [{email}] — clean (404)")
                return {"source": "hibp", "found": False, "breaches": [], "count": 0}
            if e.code == 429:
                wait = 5 * (attempt + 1)
                log.warning(f"HIBP rate limit — waiting {wait}s (attempt {attempt + 1}/3)")
                time.sleep(wait)
            else:
                log.error(f"HIBP [{email}] — HTTP {e.code}: {e.reason}")
                return {"source": "hibp", "found": False, "breaches": [], "count": 0, "error": str(e.code)}

    return {"source": "hibp", "found": False, "breaches": [], "count": 0, "error": "max_retries"}


def _emp_seed(row) -> int:
    """Extract numeric part of EmployeeID (e.g. 'MZ0001' → 1) for RNG seeding."""
    emp_id = str(row["EmployeeID"])
    digits = "".join(c for c in emp_id if c.isdigit())
    return int(digits) if digits else abs(hash(emp_id))


def simulate_hibp(row, log: logging.Logger) -> dict:
    """
    Deterministic simulation: users with RiskScore > 14 are marked
    as exposed. Uses EmployeeID seed for reproducibility.
    """
    rng = random.Random(_emp_seed(row) * 7)
    if row["RiskScore"] <= 14:
        return {"source": "hibp", "found": False, "breaches": [], "count": 0}
    count = rng.randint(1, 3)
    names = rng.sample(SIM_BREACHES["hibp"], min(count, len(SIM_BREACHES["hibp"])))
    breaches = [
        {
            "Name":        n,
            "BreachDate":  f"202{rng.randint(0, 4)}-{rng.randint(1,12):02d}-01",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified":  True,
            "IsSensitive": False,
        }
        for n in names
    ]
    log.debug(f"HIBP SIM [{row['Email']}] — {names}")
    return {"source": "hibp", "found": True, "breaches": breaches, "count": len(breaches)}


# ══════════════════════════════════════════════════════════════
# TOOL 2 — DeHashed
# Docs: dehashed.com/api
# Returns leaked credential records including usernames, hashed passwords
# Requires: account email + API key; Basic auth
# ══════════════════════════════════════════════════════════════

def check_dehashed_live(email: str, dh_email: str, dh_key: str, log: logging.Logger) -> dict:
    """
    Query DeHashed for leaked records associated with an email.
    Returns database name, username, and password hash if available.
    """
    creds = base64.b64encode(f"{dh_email}:{dh_key}".encode()).decode()
    url   = f"{DEHASHED_BASE}?query=email%3A{urllib.parse.quote(email)}&size=10"
    req   = urllib.request.Request(url, headers={
        "Authorization": f"Basic {creds}",
        "Accept":        "application/json",
        "User-Agent":    USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req) as resp:
            data    = json.loads(resp.read())
            entries = data.get("entries") or []
            records = [
                {
                    "database_name":   e.get("database_name", "Unknown"),
                    "username":        e.get("username", ""),
                    "password":        e.get("password", "") if e.get("password") else "",
                    "hashed_password": e.get("hashed_password", ""),
                    "ip_address":      e.get("ip_address", ""),
                }
                for e in entries
            ]
            log.debug(f"DeHashed LIVE [{email}] — {len(records)} record(s), total={data.get('total', 0)}")
            return {
                "source":        "dehashed",
                "found":         len(records) > 0,
                "records":       records,
                "count":         len(records),
                "total_results": data.get("total", 0),
            }
    except urllib.error.HTTPError as e:
        log.error(f"DeHashed [{email}] — HTTP {e.code}: {e.reason}")
        return {"source": "dehashed", "found": False, "records": [], "count": 0, "error": str(e.code)}


def simulate_dehashed(row, log: logging.Logger) -> dict:
    """
    Simulation: users with RiskScore > 16 appear in credential dumps.
    DeHashed tends to surface older large-scale aggregated leaks.
    """
    rng = random.Random(_emp_seed(row) * 13)
    if row["RiskScore"] <= 16:
        return {"source": "dehashed", "found": False, "records": [], "count": 0}
    count = rng.randint(1, 2)
    dbs   = rng.sample(SIM_BREACHES["dehashed"], min(count, len(SIM_BREACHES["dehashed"])))
    records = [
        {
            "database_name":   d,
            "username":        row["Email"].split("@")[0],
            "password":        "",
            "hashed_password": f"$2a$10{rng.randint(1000,9999)}simhash",
            "ip_address":      "",
        }
        for d in dbs
    ]
    log.debug(f"DeHashed SIM [{row['Email']}] — {dbs}")
    return {"source": "dehashed", "found": True, "records": records, "count": count, "total_results": count}


# ══════════════════════════════════════════════════════════════
# TOOL 3 — LeakCheck
# Docs: leakcheck.io/api
# Checks email against 7+ billion records, returns source names
# Free public endpoint limited; full access requires API key
# ══════════════════════════════════════════════════════════════

def check_leakcheck_live(email: str, lc_key: str, log: logging.Logger) -> dict:
    """
    Query LeakCheck v2 API for breach sources linked to an email.
    Returns list of breach source names with dates and entry types.
    """
    url = f"{LEAKCHECK_BASE}/{urllib.parse.quote(email)}"
    req = urllib.request.Request(url, headers={
        "X-API-Key":  lc_key,
        "User-Agent": USER_AGENT,
    })
    try:
        with urllib.request.urlopen(req) as resp:
            data    = json.loads(resp.read())
            success = data.get("success", False)
            sources = data.get("sources", [])
            hits = [
                {
                    "source_name": s.get("name", ""),
                    "date":        s.get("date", ""),
                    "entries":     s.get("entries", []),
                }
                for s in sources
            ]
            log.debug(f"LeakCheck LIVE [{email}] — {len(hits)} source(s), success={success}")
            return {"source": "leakcheck", "found": len(hits) > 0, "sources": hits, "count": len(hits)}
    except urllib.error.HTTPError as e:
        log.error(f"LeakCheck [{email}] — HTTP {e.code}: {e.reason}")
        return {"source": "leakcheck", "found": False, "sources": [], "count": 0, "error": str(e.code)}


def simulate_leakcheck(row, log: logging.Logger) -> dict:
    """
    Simulation: users with RiskScore > 15 appear in LeakCheck results.
    LeakCheck catches a slightly different subset than HIBP.
    """
    rng = random.Random(_emp_seed(row) * 17)
    if row["RiskScore"] <= 15:
        return {"source": "leakcheck", "found": False, "sources": [], "count": 0}
    count   = rng.randint(1, 2)
    names   = rng.sample(SIM_BREACHES["leakcheck"], min(count, len(SIM_BREACHES["leakcheck"])))
    sources = [
        {
            "source_name": n,
            "date":        f"202{rng.randint(0, 4)}-{rng.randint(1,12):02d}",
            "entries":     ["email", "password"],
        }
        for n in names
    ]
    log.debug(f"LeakCheck SIM [{row['Email']}] — {names}")
    return {"source": "leakcheck", "found": True, "sources": sources, "count": count}


# ══════════════════════════════════════════════════════════════
# TOOL 4 — Intelligence X (IntelX)
# Docs: intelx.io/?did=4
# Dark web, paste sites, public leak indexes
# Two-step: POST search → wait → GET results
# Free tier: limited monthly queries with free API key
# ══════════════════════════════════════════════════════════════

def check_intelx_live(email: str, ix_key: str, log: logging.Logger) -> dict:
    """
    IntelX two-step search:
      1. POST to /intelligent/search to get a search ID
      2. Wait 3s then GET /intelligent/search/result?id=...
    Returns paste site, dark web forum, and leak index hits.
    """
    # Step 1 — submit search job
    try:
        payload = json.dumps({
            "term":        email,
            "buckets":     [],
            "lookuplevel": 0,
            "maxresults":  10,
            "timeout":     5,
            "datefrom":    "",
            "dateto":      "",
            "sort":        2,
            "media":       0,
            "terminate":   [],
        }).encode()

        req = urllib.request.Request(
            INTELX_SEARCH,
            data=payload,
            headers={
                "x-key":        ix_key,
                "Content-Type": "application/json",
                "User-Agent":   USER_AGENT,
            },
        )
        with urllib.request.urlopen(req) as resp:
            search_resp = json.loads(resp.read())

        search_id = search_resp.get("id")
        if not search_id:
            log.error(f"IntelX [{email}] — no search ID returned")
            return {"source": "intelx", "found": False, "hits": [], "count": 0, "error": "no_search_id"}

        log.debug(f"IntelX [{email}] — search ID: {search_id}, polling in 3s...")
        time.sleep(3)

        # Step 2 — retrieve results
        result_url = f"{INTELX_RESULTS}?id={search_id}&limit=10&format=1"
        req2 = urllib.request.Request(
            result_url,
            headers={"x-key": ix_key, "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(req2) as resp2:
            result_data = json.loads(resp2.read())

        records = result_data.get("records", [])
        hits = [
            {
                "name":   r.get("name", ""),
                "date":   r.get("date", ""),
                "bucket": r.get("bucket", ""),
                "media":  r.get("media", 0),
            }
            for r in records
        ]
        log.debug(f"IntelX LIVE [{email}] — {len(hits)} hit(s)")
        return {"source": "intelx", "found": len(hits) > 0, "hits": hits, "count": len(hits)}

    except urllib.error.HTTPError as e:
        log.error(f"IntelX [{email}] — HTTP {e.code}: {e.reason}")
        return {"source": "intelx", "found": False, "hits": [], "count": 0, "error": str(e.code)}


def simulate_intelx(row, log: logging.Logger) -> dict:
    """
    Simulation: only the highest-risk users (RiskScore > 18) appear
    on dark web / paste sites — reflecting realistic rarity of this exposure.
    """
    rng = random.Random(_emp_seed(row) * 19)
    if row["RiskScore"] <= 18:
        return {"source": "intelx", "found": False, "hits": [], "count": 0}
    names = rng.sample(SIM_BREACHES["intelx"], 1)
    hits = [
        {
            "name":   n,
            "date":   f"202{rng.randint(2, 4)}-{rng.randint(1,12):02d}-01",
            "bucket": "pastes",
            "media":  1,
        }
        for n in names
    ]
    log.debug(f"IntelX SIM [{row['Email']}] — {names}")
    return {"source": "intelx", "found": True, "hits": hits, "count": len(hits)}


# ══════════════════════════════════════════════════════════════
# AGGREGATOR — merge all 4 sources into one user record
# ══════════════════════════════════════════════════════════════

def aggregate_user(row, hibp: dict, dehashed: dict, leakcheck: dict, intelx: dict) -> dict:
    """
    Combines results from all 4 OSINT tools into a single user risk record.

    ExposureScore (0–100):
      HIBP hit:      +10 per breach
      DeHashed hit:  +15 per record (credential dumps weight higher)
      LeakCheck hit: +10 per source
      IntelX hit:    +25 per hit (dark web is highest severity)
    """
    # Collect all source/breach names for deduplication
    all_sources: list[str] = []
    if hibp["found"]:
        all_sources += [b["Name"] for b in hibp["breaches"]]
    if dehashed["found"]:
        all_sources += [r["database_name"] for r in dehashed["records"]]
    if leakcheck["found"]:
        all_sources += [s["source_name"] for s in leakcheck["sources"]]
    if intelx["found"]:
        all_sources += [h["name"] for h in intelx["hits"]]

    unique_sources = list(set(all_sources))
    categories     = list({BREACH_CATEGORIES.get(s, "unknown") for s in unique_sources})
    dark_web       = any(c in ("dark_web", "credential_dump", "paste_site") for c in categories)

    total_findings = hibp["count"] + dehashed["count"] + leakcheck["count"] + intelx["count"]
    exposure_score = min(100, (
        hibp["count"]      * 10 +
        dehashed["count"]  * 15 +
        leakcheck["count"] * 10 +
        intelx["count"]    * 25
    ))

    return {
        "Email":           row["Email"],
        "Name":            f"{row['FirstName']} {row['LastName']}",
        "Department":      row["Department"],
        "JobTitle":        row["JobTitle"],
        "Location":        row["Location"],
        "RiskScore":       int(row["RiskScore"]),
        "Exposed":         total_findings > 0,
        "ExposureScore":   exposure_score,
        "DarkWebExposure": dark_web,
        "TotalFindings":   total_findings,
        "BreachSources":   unique_sources,
        "Categories":      categories,
        "HIBP":            hibp,
        "DeHashed":        dehashed,
        "LeakCheck":       leakcheck,
        "IntelX":          intelx,
    }


# ══════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE ENGINE
# Analyses aggregated scan results to produce actionable findings
# ══════════════════════════════════════════════════════════════

def derive_threat_intelligence(results: list, log: logging.Logger) -> dict:
    """
    Derives threat intelligence from aggregated OSINT scan results.

    Produces:
      - Overview metrics (exposure rate, dark web rate)
      - Department-level breakdown with exposure rates
      - Top breach sources and categories
      - Most exposed job titles
      - Highest-risk individuals
      - Prioritised recommendations
    """
    log.info("Deriving threat intelligence...")

    exposed   = [r for r in results if r["Exposed"]]
    dark_web  = [r for r in results if r["DarkWebExposure"]]
    total     = len(results)

    # ── Department breakdown ──────────────────────────────────
    dept_stats: dict[str, dict] = {}
    for r in results:
        d = r["Department"]
        if d not in dept_stats:
            dept_stats[d] = {"total": 0, "exposed": 0, "dark_web": 0, "scores": []}
        dept_stats[d]["total"]   += 1
        dept_stats[d]["scores"].append(r["ExposureScore"])
        if r["Exposed"]:
            dept_stats[d]["exposed"] += 1
        if r["DarkWebExposure"]:
            dept_stats[d]["dark_web"] += 1

    dept_breakdown = {}
    for d, s in dept_stats.items():
        dept_breakdown[d] = {
            "TotalUsers":         s["total"],
            "ExposedUsers":       s["exposed"],
            "DarkWebUsers":       s["dark_web"],
            "ExposureRatePct":    round(s["exposed"] / s["total"] * 100, 1),
            "AvgExposureScore":   round(sum(s["scores"]) / len(s["scores"]), 1),
        }

    # ── Breach source frequency ───────────────────────────────
    source_freq: dict[str, int] = {}
    for r in exposed:
        for src in r["BreachSources"]:
            source_freq[src] = source_freq.get(src, 0) + 1
    top_sources = sorted(source_freq.items(), key=lambda x: x[1], reverse=True)[:10]

    # ── Breach category frequency ─────────────────────────────
    cat_freq: dict[str, int] = {}
    for r in exposed:
        for c in r["Categories"]:
            cat_freq[c] = cat_freq.get(c, 0) + 1

    # ── Most exposed job titles ───────────────────────────────
    title_exp: dict[str, int] = {}
    for r in exposed:
        t = r["JobTitle"]
        title_exp[t] = title_exp.get(t, 0) + 1
    top_titles = sorted(title_exp.items(), key=lambda x: x[1], reverse=True)[:5]

    # ── Highest individual exposure ───────────────────────────
    top_individuals = sorted(exposed, key=lambda x: x["ExposureScore"], reverse=True)[:10]

    # ── Source-tool breakdown ─────────────────────────────────
    source_tool_counts = {
        "HIBP":      sum(1 for r in results if r["HIBP"]["found"]),
        "DeHashed":  sum(1 for r in results if r["DeHashed"]["found"]),
        "LeakCheck": sum(1 for r in results if r["LeakCheck"]["found"]),
        "IntelX":    sum(1 for r in results if r["IntelX"]["found"]),
    }

    # ── Prioritised recommendations ───────────────────────────
    recommendations = []

    if dark_web:
        recommendations.append({
            "Priority":      "CRITICAL",
            "Action":        "Immediate forced password reset for all users with dark web / paste site exposure",
            "AffectedCount": len(dark_web),
            "Rationale":     (
                f"{len(dark_web)} user(s) found on dark web forums or paste sites. "
                "This indicates credentials are actively circulating among threat actors."
            ),
        })

    # Most exposed department
    most_exp_dept = max(dept_breakdown, key=lambda d: dept_breakdown[d]["ExposureRatePct"])
    if dept_breakdown[most_exp_dept]["ExposureRatePct"] > 20:
        recommendations.append({
            "Priority":      "HIGH",
            "Action":        f"Priority MFA enforcement and CA policy tightening for {most_exp_dept}",
            "AffectedCount": dept_breakdown[most_exp_dept]["ExposedUsers"],
            "Rationale":     (
                f"{most_exp_dept} has a {dept_breakdown[most_exp_dept]['ExposureRatePct']}% "
                "credential exposure rate — the highest of all departments."
            ),
        })

    if cat_freq.get("credential_dump", 0) > 0 or cat_freq.get("dark_web", 0) > 0:
        affected = cat_freq.get("credential_dump", 0) + cat_freq.get("dark_web", 0)
        recommendations.append({
            "Priority":      "HIGH",
            "Action":        "Enable Entra ID Password Protection with banned-password list",
            "AffectedCount": affected,
            "Rationale":     (
                "Credential dump exposure means plaintext or crackable passwords are "
                "in the wild. Password Protection blocks reuse of known compromised passwords."
            ),
        })

    if source_tool_counts["DeHashed"] > 0:
        recommendations.append({
            "Priority":      "HIGH",
            "Action":        "Audit for username/password reuse across personal and work accounts",
            "AffectedCount": source_tool_counts["DeHashed"],
            "Rationale":     (
                "DeHashed records include usernames and hashed passwords. If work usernames "
                "match personal accounts, attackers can attempt credential stuffing."
            ),
        })

    if len(exposed) > 50:
        recommendations.append({
            "Priority":      "MEDIUM",
            "Action":        "Enrol all exposed users in Identity Protection risky-user remediation workflow",
            "AffectedCount": len(exposed),
            "Rationale":     (
                f"{len(exposed)} users are exposed across external breach databases. "
                "Systematic remediation via Entra ID risk-based policies is required."
            ),
        })

    recommendations.append({
        "Priority":      "MEDIUM",
        "Action":        "Integrate OSINT checks into the joiner provisioning workflow",
        "AffectedCount": None,
        "Rationale":     (
            "Proactive breach screening at onboarding prevents new hires from "
            "bringing compromised credentials into the MediZuva environment."
        ),
    })

    recommendations.append({
        "Priority":      "LOW",
        "Action":        "Schedule monthly OSINT re-scans and feed results into the threat dashboard",
        "AffectedCount": None,
        "Rationale":     "Breach exposure is dynamic — new leaks surface regularly and require continuous monitoring.",
    })

    # ── Log key findings ──────────────────────────────────────
    log.info(f"  Exposure rate : {round(len(exposed)/total*100, 1)}% ({len(exposed)}/{total})")
    log.info(f"  Dark web hits : {len(dark_web)}")
    log.info(f"  Top dept      : {most_exp_dept} ({dept_breakdown[most_exp_dept]['ExposureRatePct']}%)")
    log.info(f"  Tool hits — HIBP:{source_tool_counts['HIBP']} "
             f"DeHashed:{source_tool_counts['DeHashed']} "
             f"LeakCheck:{source_tool_counts['LeakCheck']} "
             f"IntelX:{source_tool_counts['IntelX']}")
    for rec in recommendations:
        log.info(f"  [{rec['Priority']}] {rec['Action']}")

    return {
        "GeneratedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Overview": {
            "TotalPersonas":     total,
            "TotalExposed":      len(exposed),
            "ExposureRatePct":   round(len(exposed) / total * 100, 1) if total else 0,
            "DarkWebExposed":    len(dark_web),
            "DarkWebRatePct":    round(len(dark_web) / total * 100, 1) if total else 0,
            "AvgExposureScore":  round(sum(r["ExposureScore"] for r in exposed) / len(exposed), 1) if exposed else 0,
        },
        "SourceToolCounts":     source_tool_counts,
        "DepartmentBreakdown":  dept_breakdown,
        "TopBreachSources":     [{"Source": s, "AffectedUsers": c} for s, c in top_sources],
        "BreachCategories":     cat_freq,
        "MostExposedTitles":    [{"Title": t, "Count": c} for t, c in top_titles],
        "HighestRiskIndividuals": [
            {
                "Name":          r["Name"],
                "Email":         r["Email"],
                "Department":    r["Department"],
                "JobTitle":      r["JobTitle"],
                "ExposureScore": r["ExposureScore"],
                "DarkWeb":       r["DarkWebExposure"],
                "TotalFindings": r["TotalFindings"],
                "Sources":       r["BreachSources"],
            }
            for r in top_individuals
        ],
        "Recommendations": recommendations,
    }


# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="MediZuva Multi-Source OSINT Exposure Check (Pillar 4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--hibp-key",       default="", help="HIBP v3 API key")
    parser.add_argument("--dehashed-email", default="", help="DeHashed account email")
    parser.add_argument("--dehashed-key",   default="", help="DeHashed API key")
    parser.add_argument("--leakcheck-key",  default="", help="LeakCheck v2 API key")
    parser.add_argument("--intelx-key",     default="", help="Intelligence X API key")
    parser.add_argument("--limit",          type=int, default=0,
                        help="Only check first N personas (0 = all 500)")
    args = parser.parse_args()

    live_hibp      = bool(args.hibp_key)
    live_dehashed  = bool(args.dehashed_email and args.dehashed_key)
    live_leakcheck = bool(args.leakcheck_key)
    live_intelx    = bool(args.intelx_key)
    any_live       = any([live_hibp, live_dehashed, live_leakcheck, live_intelx])

    log = setup_logger()
    log.info("=" * 60)
    log.info(" MediZuva — Multi-Source OSINT Check (Pillar 4 v2)")
    log.info(f" HIBP      : {'LIVE' if live_hibp      else 'SIMULATE'}")
    log.info(f" DeHashed  : {'LIVE' if live_dehashed  else 'SIMULATE'}")
    log.info(f" LeakCheck : {'LIVE' if live_leakcheck else 'SIMULATE'}")
    log.info(f" IntelX    : {'LIVE' if live_intelx    else 'SIMULATE'}")
    log.info("=" * 60)

    df = pd.read_csv(PERSONAS_CSV)
    if args.limit:
        df = df.head(args.limit)
        log.info(f"Limiting to first {args.limit} personas (--limit flag)")
    total = len(df)
    log.info(f"Loaded {total} personas from {PERSONAS_CSV.name}")

    results: list[dict] = []
    exposed_count = 0

    for idx, (_, row) in enumerate(df.iterrows()):
        email = row["Email"]

        # ── HIBP ──────────────────────────────────────────────
        hibp = check_hibp_live(email, args.hibp_key, log) if live_hibp else simulate_hibp(row, log)
        if live_hibp:
            time.sleep(1.6)   # HIBP enforces 1 req/1.5s

        # ── DeHashed ──────────────────────────────────────────
        dehashed = check_dehashed_live(email, args.dehashed_email, args.dehashed_key, log) if live_dehashed else simulate_dehashed(row, log)
        if live_dehashed:
            time.sleep(1.0)

        # ── LeakCheck ─────────────────────────────────────────
        leakcheck = check_leakcheck_live(email, args.leakcheck_key, log) if live_leakcheck else simulate_leakcheck(row, log)
        if live_leakcheck:
            time.sleep(1.0)

        # ── IntelX ────────────────────────────────────────────
        intelx = check_intelx_live(email, args.intelx_key, log) if live_intelx else simulate_intelx(row, log)
        # IntelX has its own 3s internal wait in the live function

        user = aggregate_user(row, hibp, dehashed, leakcheck, intelx)
        results.append(user)

        if user["Exposed"]:
            exposed_count += 1
            dark_tag = " [DARK WEB]" if user["DarkWebExposure"] else ""
            log.info(
                f"[EXPOSED{dark_tag}] {user['Name']:30s} | {row['JobTitle']:25s} | "
                f"score={user['ExposureScore']:3d} | findings={user['TotalFindings']} | "
                f"sources={', '.join(user['BreachSources'])}"
            )

        if (idx + 1) % 50 == 0:
            log.info(f"--- Progress: {idx+1}/{total} checked | Exposed so far: {exposed_count} ---")

    # ── Derive threat intelligence ─────────────────────────────
    log.info("")
    log.info("=" * 60)
    log.info("THREAT INTELLIGENCE ANALYSIS")
    log.info("=" * 60)
    intelligence = derive_threat_intelligence(results, log)

    # ── Final summary ──────────────────────────────────────────
    ov = intelligence["Overview"]
    log.info("")
    log.info("=" * 60)
    log.info("SCAN COMPLETE")
    log.info(f"  Total personas   : {ov['TotalPersonas']}")
    log.info(f"  Exposed          : {ov['TotalExposed']} ({ov['ExposureRatePct']}%)")
    log.info(f"  Dark web hits    : {ov['DarkWebExposed']} ({ov['DarkWebRatePct']}%)")
    log.info(f"  Avg exp score    : {ov['AvgExposureScore']}/100")
    log.info("=" * 60)

    # ── Export combined results ────────────────────────────────
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    combined = {
        "ScanDate":           datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Mode":               "live" if any_live else "simulated",
        "Sources": {
            "HIBP":      "live" if live_hibp      else "simulated",
            "DeHashed":  "live" if live_dehashed  else "simulated",
            "LeakCheck": "live" if live_leakcheck else "simulated",
            "IntelX":    "live" if live_intelx    else "simulated",
        },
        "TotalChecked":       total,
        "ExposedCount":       exposed_count,
        "ThreatIntelligence": intelligence,
        "Results":            results,
    }
    OUT_COMBINED.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    log.info(f"Combined results  -> {OUT_COMBINED}")

    # ── Legacy hibp_results.json (keeps threat_audit.ps1 working) ──
    legacy = {
        "CheckDate":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Mode":         "live" if live_hibp else "simulated",
        "TotalChecked": total,
        "ExposedCount": exposed_count,
        "CleanCount":   total - exposed_count,
        "Results": [
            {
                "Email":      r["Email"],
                "Name":       r["Name"],
                "Department": r["Department"],
                "JobTitle":   r["JobTitle"],
                "Exposed":    r["Exposed"],
                "Breaches":   r["BreachSources"],
                "BreachCount":r["TotalFindings"],
            }
            for r in results
        ],
    }
    OUT_HIBP.write_text(json.dumps(legacy, indent=2), encoding="utf-8")
    log.info(f"Legacy HIBP file  -> {OUT_HIBP}")
    log.info(f"Run log           -> {OUT_LOG}")
    log.info("Next: run pillar4_threat/threat_audit.ps1")


if __name__ == "__main__":
    main()
