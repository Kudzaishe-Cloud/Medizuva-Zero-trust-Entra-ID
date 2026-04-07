"""
refresh.py
============================================================
Single command to run the full MediZuva pipeline locally
and open the dashboard in your browser.

Usage:
    python refresh.py           # all data from CSV (no API keys needed)
    python refresh.py --osint   # also run OSINT tools (needs API keys)
    python refresh.py --serve   # serve on http://localhost:8080 after build
============================================================
"""

import argparse
import os
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

REPO = Path(__file__).resolve().parent

STEPS_BASE = [
    ("Entra ID sync   (MFA/device gaps from CSV)",  ["python", "shared/entra_sync.py"]),
    ("Threat audit    (risk tier classification)",   ["python", "pillar4_threat/threat_audit.py"]),
    ("Central dashboard (rebuild HTML)",             ["python", "dashboard/generate_central_dashboard.py"]),
]

STEPS_OSINT = [
    ("OSINT check     (HIBP · DeHashed · LeakCheck · IntelX)", ["python", "pillar4_threat/osint_exposure_check.py"]),
]


def run(label: str, cmd: list):
    print("\n" + "-"*56)
    print(f"  >> {label}")
    print("-"*56)
    result = subprocess.run(cmd, cwd=REPO)
    if result.returncode != 0:
        print(f"\n[ERROR] Step failed: {label}")
        sys.exit(result.returncode)


def serve():
    import threading, http.server, os

    data_dir = REPO / "data"
    os.chdir(data_dir)

    handler = http.server.SimpleHTTPRequestHandler
    handler.log_message = lambda *a: None   # silence request logs
    server  = http.server.HTTPServer(("", 8080), handler)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    url = "http://localhost:8080/central_dashboard.html"
    print(f"\n  Dashboard live at: {url}")
    print("  Press Ctrl+C to stop\n")
    time.sleep(0.5)
    webbrowser.open(url)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Server stopped.")
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(description="MediZuva full pipeline refresh")
    parser.add_argument("--osint",  action="store_true", help="Run OSINT tools (requires API keys for live mode)")
    parser.add_argument("--serve",  action="store_true", help="Serve dashboard after build")
    args = parser.parse_args()

    print("\n" + "="*56)
    print("  MediZuva Zero-Trust -- Full Pipeline Refresh")
    print("="*56)

    steps = STEPS_BASE.copy()
    if args.osint:
        # Insert OSINT before threat audit so threat_audit picks up fresh results
        steps.insert(0, STEPS_OSINT[0])

    for label, cmd in steps:
        run(label, cmd)

    # Copy to docs/ for GitHub Pages consistency
    src = REPO / "data" / "central_dashboard.html"
    dst = REPO / "docs" / "index.html"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())
    print(f"\n  [OK] docs/index.html updated")

    print("\n" + "="*56)
    print("  Pipeline complete -- dashboard is ready")
    print(f"  File: {src}")
    print("="*56)

    if args.serve:
        serve()
    else:
        print("\n  To view:  python refresh.py --serve")
        print("  To push:  git add -A && git commit -m 'refresh' && git push\n")


if __name__ == "__main__":
    main()
