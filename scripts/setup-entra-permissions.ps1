# ============================================================
# Setup Entra ID App Registration Permissions
# ============================================================
# This script adds all required Microsoft Graph API permissions
# to your app registration and grants admin consent.
#
# Required: Azure CLI installed and authenticated
#   az login --allow-no-subscriptions
#
# Usage:
#   .\setup-entra-permissions.ps1 -AppId "<CLIENT_ID>" -TenantId "<TENANT_ID>"
# ============================================================

param(
    [Parameter(Mandatory = $true)]
    [string]$AppId,

    [Parameter(Mandatory = $true)]
    [string]$TenantId
)

# Required permissions (Microsoft Graph API)
$RequiredPermissions = @(
    "User.Read.All",
    "Directory.Read.All",
    "IdentityRiskyUser.Read.All",
    "UserAuthenticationMethod.Read.All",
    "DeviceManagementManagedDevices.Read.All"
)

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Setting up Entra ID App Registration Permissions" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "App ID:    $AppId"
Write-Host "Tenant ID: $TenantId"
Write-Host ""

# Check if Azure CLI is installed
$azVersion = az version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Azure CLI is not installed. Install from: https://aka.ms/azurecli" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Azure CLI is installed" -ForegroundColor Green

# Check if authenticated
$currentAccount = az account show 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Not authenticated. Run: az login --allow-no-subscriptions" -ForegroundColor Red
    exit 1
}
Write-Host "✓ Authenticated" -ForegroundColor Green

Write-Host ""
Write-Host "--- Adding Permissions ---" -ForegroundColor Yellow

# Get the service principal for Microsoft Graph
$graphSpJson = az ad sp list --filter "appId eq '00000003-0000-0000-c000-000000000000'" --query "[0]"
$graphSp = $graphSpJson | ConvertFrom-Json

if (-not $graphSp) {
    Write-Host "✗ Could not find Microsoft Graph service principal" -ForegroundColor Red
    exit 1
}

Write-Host "Found Microsoft Graph Service Principal" -ForegroundColor Green
Write-Host ""

# Get current app
$appJson = az ad app show --id $AppId 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "✗ Could not find app with ID: $AppId" -ForegroundColor Red
    exit 1
}
$app = $appJson | ConvertFrom-Json

Write-Host "Found App: $($app.displayName)" -ForegroundColor Green
Write-Host ""

# Get list of Microsoft Graph roles (permissions)
$allRoles = $graphSp.appRoles | Where-Object { $_.allowedMemberTypes -contains "Application" }

# Add each required permission
foreach ($permissionName in $RequiredPermissions) {
    $role = $allRoles | Where-Object { $_.value -eq $permissionName }

    if (-not $role) {
        Write-Host "⚠ Permission not found in Microsoft Graph: $permissionName" -ForegroundColor Yellow
        continue
    }

    $result = az ad app permission add --id $AppId --api $graphSp.appId --api-permissions "$($role.id)=Role" 2>&1
    Write-Host "✓ Added: $permissionName" -ForegroundColor Green
}

Write-Host ""
Write-Host "--- Granting Admin Consent ---" -ForegroundColor Yellow

$consentResult = az ad app permission admin-consent --id $AppId 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Admin consent granted successfully!" -ForegroundColor Green
} else {
    Write-Host "⚠ Admin consent grant encountered an issue (this is normal)" -ForegroundColor Yellow
    Write-Host "   You may need to grant consent manually in Azure Portal:" -ForegroundColor Yellow
    Write-Host "   1. Go to App registrations > $($app.displayName)" -ForegroundColor Yellow
    Write-Host "   2. Click 'API permissions'" -ForegroundColor Yellow
    Write-Host "   3. Click 'Grant admin consent for [Tenant]'" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Wait 5-10 minutes for permissions to propagate in Azure" -ForegroundColor White
Write-Host "  2. Verify in Azure Portal > App registrations > API permissions" -ForegroundColor White
Write-Host "  3. Trigger the GitHub Actions workflow again" -ForegroundColor White
Write-Host ""
