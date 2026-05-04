#!/usr/bin/env python3
"""Test risky users endpoint directly"""

import json
import os
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# Load .env
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

tenant_id = os.getenv("ENTRA_TENANT_ID")
client_id = os.getenv("ENTRA_CLIENT_ID")
client_secret = os.getenv("ENTRA_CLIENT_SECRET")

# Get token
url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
body = urllib.parse.urlencode({
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": "https://graph.microsoft.com/.default",
}).encode()

req = urllib.request.Request(url, data=body, method="POST")
with urllib.request.urlopen(req) as resp:
    data = json.loads(resp.read())
    token = data.get("access_token")

headers = {"Authorization": f"Bearer {token}"}

# Test risky users endpoint
print("Testing: /identityProtection/riskyUsers")
print()

endpoints = {
    "ALL risky users (no filter)": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$top=100",
    "HIGH risk only": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskLevel%20eq%20%27high%27&$top=100",
    "HIGH or MEDIUM": "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?$filter=riskLevel%20eq%20%27high%27%20or%20riskLevel%20eq%20%27medium%27&$top=100",
}

for name, endpoint_url in endpoints.items():
    print(f"Testing: {name}")
    try:
        req = urllib.request.Request(endpoint_url, headers=headers)
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            count = len(data.get("value", []))
            print(f"  Result: {count} risky users found")
            if count > 0:
                for user in data.get("value", [])[:3]:
                    print(f"    - {user.get('userDisplayName')} ({user.get('riskLevel')})")
    except urllib.error.HTTPError as e:
        print(f"  ERROR {e.code}: {e.reason}")
        try:
            error_body = e.read().decode()
            error_data = json.loads(error_body)
            if 'error' in error_data:
                err = error_data['error']
                if isinstance(err, dict):
                    print(f"    {err.get('code')}: {err.get('message')}")
        except:
            pass
    print()

print("===")
print("If all show 0 risky users, the endpoint might require:")
print("  1. Identity Protection P2 license")
print("  2. Risk events to be detected first")
print("  3. Different permission scopes")
