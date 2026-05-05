import subprocess, json
import pandas as pd
from datetime import datetime

source = pd.read_csv(r"C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\medizuva_500_personas.csv")
print(f"Loaded {len(source)} personas from CSV")
print("Fetching users from Entra ID...")

# Fetch users from Entra with all needed attributes
result = subprocess.run([
    "powershell", "-Command",
    "Connect-MgGraph -Scopes 'User.Read.All' -NoWelcome; "
    "$users = Get-MgUser -All -Property 'userPrincipalName,department,jobTitle,city'; "
    "$users | ForEach-Object { [PSCustomObject]@{ "
    "upn=$_.UserPrincipalName; dept=$_.Department; "
    "title=$_.JobTitle; city=$_.City } } | ConvertTo-Json -Depth 2"
], capture_output=True, text=True)

print("Raw output preview:", result.stdout[:200])

# Parse the JSON response
data = json.loads(result.stdout)

# Handle both single object and array responses
if isinstance(data, dict):
    data = [data]

# Build a lookup dictionary keyed by email
entra_lookup = {}
for user in data:
    upn = user.get("upn") or user.get("UserPrincipalName") or ""
    if upn:
        entra_lookup[upn.lower()] = user

print(f"Fetched {len(entra_lookup)} users from Entra ID")

issues = []
for _, row in source.iterrows():
    email = row["Email"].lower()

    if email not in entra_lookup:
        issues.append({"Email": email, "Field": "Account", "Issue": "Not found in Entra ID"})
        continue

    actual = entra_lookup[email]

    checks = [
        ("Department", "dept",  row["Department"]),
        ("JobTitle",   "title", row["JobTitle"]),
        ("Location",   "city",  row["Location"])
    ]

    for field, key, expected in checks:
        actual_val = str(actual.get(key) or "").strip()
        expected_val = str(expected).strip()
        if actual_val != expected_val:
            issues.append({
                "Email":    email,
                "Field":    field,
                "Expected": expected_val,
                "Got":      actual_val
            })

accuracy = ((len(source) - len(issues)) / len(source)) * 100

report = f"""
=== MEDIZUVA PROVISIONING VALIDATION REPORT ===
Date:           {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total personas: {len(source)}
Issues found:   {len(issues)}
Accuracy:       {accuracy:.2f}%
Target:         100.00%
Result:         {'PASS' if accuracy == 100 else 'FAIL'}
================================================
"""

print(report)

with open(r"C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\validation_report.txt", "w") as f:
    f.write(report)

if issues:
    pd.DataFrame(issues).to_csv(
        r"C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\validation_issues.csv",
        index=False
    )
    print(f"Issues found — check validation_issues.csv")
else:
    print("No issues — validation_report.txt saved as Objective 1 evidence")