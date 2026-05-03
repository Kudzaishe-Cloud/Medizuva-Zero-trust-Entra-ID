# Entra ID Integration — MS Graph API Live Data

## Overview
The MediZuva dashboard retrieves **real, live Entra ID data** directly from Microsoft Graph API every 15 minutes. No synthetic data fallback — all authentication logs, risk signals, and audit events come directly from your Entra ID tenant.

## Data Sources

### 1. Sign-In Logs
- **Endpoint:** `GET /auditLogs/signIns`
- **Frequency:** Every 15 minutes
- **Window:** Last 7 days
- **Attributes Captured:**
  - User identity (display name, UPN)
  - Application accessed
  - IP address & geolocation
  - Risk level (none/low/medium/high)
  - MFA usage
  - Conditional Access status
  - Device compliance state

### 2. Risky Users (Identity Protection)
- **Endpoint:** `GET /identityProtection/riskyUsers`
- **Frequency:** Every 15 minutes
- **Filters:** High/Medium risk users only
- **Attributes Captured:**
  - Risk level & state
  - Last update timestamp

### 3. Directory Audit Logs
- **Endpoint:** `GET /auditLogs/directoryAudits`
- **Frequency:** Every 15 minutes
- **Window:** Last 7 days
- **Attributes Captured:**
  - Activity name & category
  - Actor (who made the change)
  - Target resources
  - Operation type & result
  - Timestamp

## GitHub Actions Workflow

**File:** `.github/workflows/sync.yml`

### Step: "Entra ID log retrieval"
```yaml
- name: Entra ID log retrieval
  run: python shared/entra_logs.py
  env:
    ENTRA_TENANT_ID: ${{ secrets.ENTRA_TENANT_ID }}
    ENTRA_CLIENT_ID: ${{ secrets.ENTRA_CLIENT_ID }}
    ENTRA_CLIENT_SECRET: ${{ secrets.ENTRA_CLIENT_SECRET }}
```

**Schedule:** Runs every 15 minutes (cron: `*/15 * * * *`)

## Required Setup

### 1. Entra ID App Registration

Create an app registration in your Entra ID tenant with the following permissions:

**Application Permissions (NOT delegated):**
- `AuditLog.Read.All` — Read audit logs & sign-in logs
- `Directory.Read.All` — Read directory data (optional, for additional context)

**Do NOT use Delegated Permissions** — This is a daemon/background process that needs application-level access.

### 2. GitHub Repository Secrets

Add the following secrets to your GitHub repository:

| Secret Name | Value | Source |
|---|---|---|
| `ENTRA_TENANT_ID` | Your Azure tenant ID | Azure Portal → Entra ID → Overview |
| `ENTRA_CLIENT_ID` | App registration client ID | Azure Portal → App registration → Overview |
| `ENTRA_CLIENT_SECRET` | App registration secret value | Azure Portal → App registration → Certificates & secrets |

**⚠️ Security Note:** Never commit these secrets. GitHub encrypts them at rest.

### 3. Verify Permissions in Entra ID

```
Azure Portal → Entra ID → Enterprise Applications
→ Search for your app → API permissions
→ Verify: AuditLog.Read.All (Application)
```

## Output Files

After each workflow run, the following JSON files are generated:

```
data/signin_logs/
├── signin_logs.json       — Sign-in events (up to 500)
├── risky_signins.json     — Risky users
├── directory_audits.json  — Audit trail (up to 500)
└── log_summary.json       — Analytics summary
```

**Example:** `log_summary.json`
```json
{
  "GeneratedAt": "2026-05-02 23:30:15",
  "SignInTotal": 1247,
  "SignInFailed": 89,
  "SignInSuccessRate": 92.9,
  "MFAUsed": 1156,
  "MFARatePct": 92.7,
  "RiskyUsers": 3,
  "Countries": ["US", "UK", "Canada"],
  "TopApps": [
    {"App": "Microsoft Teams", "Count": 456},
    {"App": "Office Portal", "Count": 389}
  ],
  "AuditTotal": 234,
  "AuditFailures": 2
}
```

## Dashboard Integration

The dashboard automatically loads and displays this real data:

**Panel:** "Entra ID Logs" → Shows:
- Sign-in analytics (success rate, MFA %, risky users)
- Recent authentication events (last 20)
- High-risk users (last 10)
- Directory audit trail (last 15)

**Data Source Badge:** ✓ Real Entra ID Data (stamped in dashboard)

## Error Handling

The workflow is configured with `continue-on-error: true` for the Entra ID log retrieval step. This means:

- If credentials are missing → Logs gracefully fail, dashboard continues with cached data
- If MS Graph API is unavailable → Workflow continues, dashboard uses previous data
- If data is stale → Dashboard continues, showing last known state

**Dashboard shows:** "Last retrieved: [timestamp]" so you know how current the data is.

## Troubleshooting

### No data showing in dashboard?

1. **Check workflow run status:**
   ```
   GitHub → Actions → "Sync Dashboard" → Latest run
   ```

2. **Verify secrets are set:**
   ```
   GitHub → Settings → Secrets and variables → Repository secrets
   → Check: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET
   ```

3. **Check MS Graph permissions:**
   - Ensure app registration has `AuditLog.Read.All` application permission
   - Confirm admin consent was granted

4. **Check file outputs:**
   ```bash
   ls -la data/signin_logs/
   ```
   If empty → credentials issue or API failure

### "0 total" in dashboard?

- First run may have no data (workflow hasn't run yet)
- Manual run: `shared/entra_logs.py` with `.env` credentials
- Wait 15 minutes for next scheduled workflow run

## Local Testing

To test Entra ID integration locally:

1. **Create `.env` file:**
   ```
   ENTRA_TENANT_ID=your-tenant-id
   ENTRA_CLIENT_ID=your-client-id
   ENTRA_CLIENT_SECRET=your-secret
   ```

2. **Run log retrieval:**
   ```bash
   python shared/entra_logs.py
   ```

3. **Regenerate dashboard:**
   ```bash
   python dashboard/generate_central_dashboard.py
   ```

4. **View dashboard:**
   ```bash
   cd data && python -m http.server 8080
   # Open: http://localhost:8080/central_dashboard.html
   ```

## Data Freshness

- **Update Interval:** Every 15 minutes (GitHub Actions schedule)
- **Data Retention:** Last 7 days of logs per query
- **Storage:** JSON files in `data/signin_logs/`
- **Dashboard Refresh:** Manual (user refreshes browser) or automatic if hosted

## Security Considerations

✅ **Best Practices Implemented:**
- Application-level permissions (no user delegation)
- Secrets stored in GitHub (encrypted at rest)
- OAuth 2.0 client credentials flow
- No credentials in code or logs
- Graceful error handling (no data exposure on failure)

⚠️ **Recommendations:**
- Rotate `ENTRA_CLIENT_SECRET` every 90 days
- Review `AuditLog.Read.All` access quarterly
- Monitor workflow failures (set up GitHub Actions alerts)
- Restrict branch protection rules if sensitive environments

## Related Files

- `shared/entra_logs.py` — Log retrieval script
- `.github/workflows/sync.yml` — GitHub Actions workflow
- `dashboard/generate_central_dashboard.py` — Dashboard generator
- `data/signin_logs/` — Log data outputs

---

**Status:** ✓ Configured for live MS Graph API queries  
**Last Updated:** 2026-05-02
