@echo off
REM MediZuva Zero-Trust Framework — Complete Automation Demo
REM Run the entire automation flow in sequence

setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1

REM Colors (limited in CMD, using symbols instead)
set "SUCCESS=✓"
set "ERROR=✗"
set "WARNING=⚠"
set "INFO=>"

cls
echo.
echo ════════════════════════════════════════════════════════════════════════
echo    MediZuva Zero-Trust Framework — Complete Automation Demo
echo ════════════════════════════════════════════════════════════════════════
echo.

REM Prerequisites Check
echo [1] Checking Prerequisites...
echo.

REM Check Python
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set "PYTHON_VER=%%i"
if "%PYTHON_VER%"=="" (
    echo %ERROR% Python not found. Install Python 3.11+
    exit /b 1
)
echo %SUCCESS% Python version: %PYTHON_VER%

REM Check .env file
if not exist ".env" (
    echo %ERROR% .env file not found
    exit /b 1
)
echo %SUCCESS% .env file found

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 1: VERIFY CONNECTIVITY
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [2] Phase 1: Verify Entra ID Authentication ^& Connectivity
echo ════════════════════════════════════════════════════════════════════════
echo.

python test_entra_auth.py
if errorlevel 1 exit /b 1

python test_graph_endpoints.py
if errorlevel 1 exit /b 1

python test_risky_users.py
if errorlevel 1 exit /b 1

echo %SUCCESS% Phase 1 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 2: COMPREHENSIVE DATA COLLECTION
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [3] Phase 2: Comprehensive Entra ID Data Collection (PRIMARY)
echo ════════════════════════════════════════════════════════════════════════
echo.

python shared\entra_comprehensive.py
if errorlevel 1 exit /b 1

echo %SUCCESS% Phase 2 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 3: SUPPLEMENTARY DATA ENRICHMENT
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [4] Phase 3: Supplementary Data Collection
echo ════════════════════════════════════════════════════════════════════════
echo.

echo %INFO% Collecting risky users, MFA gaps, device compliance gaps...
python shared\entra_sync.py

echo %INFO% Auditing Conditional Access policies...
python shared\entra_ca.py

echo %INFO% Auditing PIM role assignments...
python shared\entra_pim.py

echo %INFO% Retrieving sign-in logs...
python shared\entra_logs.py

echo %SUCCESS% Phase 3 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 4: IDENTITY PROVISIONING
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [5] Phase 4: Identity Provisioning
echo ════════════════════════════════════════════════════════════════════════
echo.

python pillar1_identity\generate_personas.py
if errorlevel 1 exit /b 1

python pillar1_identity\validate_provisioning.py
if errorlevel 1 exit /b 1

echo %SUCCESS% Phase 4 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 5: THREAT INTELLIGENCE
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [6] Phase 5: Threat Intelligence
echo ════════════════════════════════════════════════════════════════════════
echo.

python pillar4_threat\threat_audit.py
if errorlevel 1 exit /b 1

python pillar4_threat\osint_exposure_check.py
if errorlevel 1 exit /b 1

echo %SUCCESS% Phase 5 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 6: COMPLIANCE AUDIT
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [7] Phase 6: NIST Compliance Audit
echo ════════════════════════════════════════════════════════════════════════
echo.

python shared\nist_compliance.py
if errorlevel 1 exit /b 1

echo %SUCCESS% Phase 6 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM PHASE 7: DASHBOARD GENERATION
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo [8] Phase 7: Central Dashboard Generation
echo ════════════════════════════════════════════════════════════════════════
echo.

python dashboard\generate_central_dashboard.py
if errorlevel 1 exit /b 1

echo %SUCCESS% Phase 7 completed successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM VERIFICATION
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo Final Verification
echo ════════════════════════════════════════════════════════════════════════
echo.

if exist "data\entra_comprehensive.json" (
    echo %SUCCESS% data\entra_comprehensive.json
) else (
    echo %ERROR% data\entra_comprehensive.json - NOT FOUND
    exit /b 1
)

if exist "data\central_dashboard.html" (
    echo %SUCCESS% data\central_dashboard.html
) else (
    echo %ERROR% data\central_dashboard.html - NOT FOUND
    exit /b 1
)

echo %SUCCESS% All data files generated successfully

REM ─────────────────────────────────────────────────────────────────────────────
REM FINAL SUMMARY
REM ─────────────────────────────────────────────────────────────────────────────

echo.
echo ════════════════════════════════════════════════════════════════════════
echo AUTOMATION COMPLETE
echo ════════════════════════════════════════════════════════════════════════
echo.
echo 📊 Next Steps:
echo.
echo   1. VIEW DASHBOARD:
echo      Command: start data\central_dashboard.html
echo      Or: Open data\central_dashboard.html manually in your browser
echo.
echo   2. LOCAL WEB SERVER (optional):
echo      cd data
echo      python -m http.server 8080
echo      Visit: http://localhost:8080/central_dashboard.html
echo.
echo   3. DEPLOY TO GITHUB:
echo      copy data\central_dashboard.html docs\index.html
echo      git add docs\index.html data\nist_compliance_report.json
echo      git commit -m "chore: update dashboard"
echo      git push
echo.
echo   4. GITHUB PAGES:
echo      https://kudzaishe-cloud.github.io/Medizuva-Zero-trust-Entra-ID/
echo.
echo   5. AUTOMATE (GitHub Actions):
echo      Workflow runs every 5 minutes automatically
echo      Manual trigger: GitHub Actions tab ^-> Run workflow
echo.
echo 📈 Data Generated:
echo   - entra_comprehensive.json  (Real Entra ID data)
echo   - central_dashboard.html    (Interactive dashboard)
echo   - nist_compliance_report.json (Compliance audit)
echo   - threat_audit.json         (Risk classification)
echo   - ca_audit.json             (CA policies)
echo   - pim_audit.json            (PIM roles)
echo   - osint_combined_results.json (Breach intelligence)
echo.
echo ✅ System Status: READY FOR PRODUCTION
echo.
echo For complete documentation, see: AUTOMATION_RUNBOOK.md
echo.

REM Open dashboard in default browser
start "" data\central_dashboard.html

endlocal
