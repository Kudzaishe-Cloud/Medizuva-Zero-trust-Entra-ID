#!/usr/bin/env python3
"""Test actual Graph API endpoints that the scripts use"""

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
print("TESTING GRAPH API ENDPOINTS")
print("=" * 60)
print()

# Get token
url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
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
    print("[OK] Got access token\n")
except Exception as e:
    print(f"[FAIL] Could not get token: {e}")
    sys.exit(1)

headers = {"Authorization": f"Bearer {token}"}

# Test endpoints
endpoints = {
    "Users": "https://graph.microsoft.com/v1.0/users?$top=1",
    "Identity Protection (Risky Users)": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top=1",
    "Credential Registration": "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails?$top=1",
    "Devices": "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$top=1",
}

print("Testing endpoints:\n")

for name, endpoint_url in endpoints.items():
    try:
        req = urllib.request.Request(endpoint_url, headers=headers)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        count = len(data.get("value", []))
        print(f"[OK] {name}")
        print(f"     Returned {count} item(s)")
    except urllib.error.HTTPError as e:
        print(f"[FAIL] {name}")
        print(f"     HTTP {e.code}: {e.reason}")
        try:
            error_body = e.read().decode()
            error_data = json.loads(error_body)
            if 'error' in error_data:
                err = error_data['error']
                if isinstance(err, dict):
                    print(f"     Code: {err.get('code')}")
                    print(f"     Message: {err.get('message')}")
                else:
                    print(f"     Error: {err}")
        except:
            pass
    except Exception as e:
        print(f"[ERROR] {name}: {e}")
    print()

print("=" * 60)
print("If any endpoint shows [OK], your permissions are working.")
print("If all show [FAIL], the permissions haven't propagated yet.")
print("Wait 5-10 minutes and try again.")
print("=" * 60)
