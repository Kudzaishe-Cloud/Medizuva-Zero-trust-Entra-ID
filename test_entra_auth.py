#!/usr/bin/env python3
"""Test Entra ID authentication"""

import json
import os
import sys
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# Load .env file
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

tenant_id = os.getenv("ENTRA_TENANT_ID", "").strip()
client_id = os.getenv("ENTRA_CLIENT_ID", "").strip()
client_secret = os.getenv("ENTRA_CLIENT_SECRET", "").strip()

print("=" * 60)
print("TESTING ENTRA ID AUTHENTICATION")
print("=" * 60)
print()

# Validate credentials are loaded
if not tenant_id:
    print("[FAIL] ENTRA_TENANT_ID is empty")
    sys.exit(1)
if not client_id:
    print("[FAIL] ENTRA_CLIENT_ID is empty")
    sys.exit(1)
if not client_secret:
    print("[FAIL] ENTRA_CLIENT_SECRET is empty")
    sys.exit(1)

print(f"[OK] Tenant ID loaded: {tenant_id}")
print(f"[OK] Client ID loaded: {client_id}")
print(f"[OK] Client Secret loaded: {client_secret[:20]}..." if len(client_secret) > 20 else "[OK] Client Secret loaded")
print()

# Try to get a token
print("Attempting to get access token...")
url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
print(f"URL: {url}")
print()

body = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": "https://graph.microsoft.com/.default",
}).encode()

try:
    req = urllib.request.Request(url, data=body, method="POST")
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())
        token = data.get("access_token")

    print("[SUCCESS] Got access token!")
    print(f"   Token: {token[:50]}...")
    print()

    # Try a Graph API call
    print("Testing Graph API access...")
    graph_url = "https://graph.microsoft.com/v1.0/me"
    headers = {"Authorization": f"Bearer {token}"}

    req = urllib.request.Request(graph_url, headers=headers)
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read())

    print("[SUCCESS] Graph API is accessible!")
    print(f"   User: {data.get('displayName', 'N/A')}")
    print()
    print("[PASS] All checks passed! Your credentials are working correctly.")

except urllib.error.HTTPError as e:
    print(f"[HTTP ERROR {e.code}] {e.reason}")
    print()

    # Read error response
    try:
        error_body = e.read().decode()
        error_data = json.loads(error_body)
        print("Error details:")
        print(f"  Code: {error_data.get('error')}")
        print(f"  Description: {error_data.get('error_description')}")
    except:
        print(f"Response: {e.read().decode()}")

    print()
    print("TROUBLESHOOTING:")
    print("1. Verify credentials in .env are correct")
    print("2. Check if client secret is expired (go to Azure Portal)")
    print("3. Confirm API permissions are granted in Azure")
    print("4. Wait 5-10 minutes after granting permissions")
    sys.exit(1)

except Exception as e:
    print(f"[ERROR] {e}")
    sys.exit(1)
