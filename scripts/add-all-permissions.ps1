param(
    [string]$AppId = "092194d1-8c7a-4819-bfff-676f8b80a176",
    [string]$TenantId = "2aa3a349-78f7-4d13-b9b5-bb588852ae6d"
)

Write-Host "Installing modules..." -ForegroundColor Yellow
Install-Module -Name Az.Accounts -Force -Scope CurrentUser -AllowClobber -ErrorAction SilentlyContinue
Install-Module -Name Az.Resources -Force -Scope CurrentUser -AllowClobber -ErrorAction SilentlyContinue

Import-Module Az.Accounts -Force
Import-Module Az.Resources -Force

Write-Host "Connecting to Azure..." -ForegroundColor Yellow
Connect-AzAccount -TenantId $TenantId -ErrorAction Stop

Write-Host "Getting app..." -ForegroundColor Yellow
$app = Get-AzADApplication -ApplicationId $AppId -ErrorAction Stop
Write-Host "Found: $($app.DisplayName)" -ForegroundColor Green

Write-Host "Getting Microsoft Graph SP..." -ForegroundColor Yellow
$graphSp = Get-AzADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000" -ErrorAction Stop

$allPermissions = @(
    "User.Read.All",
    "Directory.Read.All",
    "IdentityRiskyUser.Read.All",
    "UserAuthenticationMethod.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Policy.Read.All",
    "RoleManagement.Read.All",
    "AuditLog.Read.All"
)

Write-Host "Building permissions list..." -ForegroundColor Yellow
$allRoles = $graphSp.AppRole | Where-Object { $_.AllowedMemberTypes -contains "Application" }
$resourceAccess = @()

foreach ($perm in $allPermissions) {
    $role = $allRoles | Where-Object { $_.Value -eq $perm }
    if ($role) {
        $resourceAccess += @{
            Id   = $role.Id
            Type = "Role"
        }
        Write-Host "[+] $perm" -ForegroundColor Green
    } else {
        Write-Host "[-] $perm (not found)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Updating app with all permissions..." -ForegroundColor Yellow

Update-AzADApplication -ObjectId $app.Id -RequiredResourceAccess @(
    @{
        ResourceAppId   = $graphSp.AppId
        ResourceAccess  = $resourceAccess
    }
) -ErrorAction Stop

Write-Host ""
Write-Host "Done! Permissions added:" -ForegroundColor Green
Write-Host "  User.Read.All"
Write-Host "  Directory.Read.All"
Write-Host "  IdentityRiskyUser.Read.All"
Write-Host "  UserAuthenticationMethod.Read.All"
Write-Host "  DeviceManagementManagedDevices.Read.All"
Write-Host "  Policy.Read.All"
Write-Host "  RoleManagement.Read.All"
Write-Host "  AuditLog.Read.All"
Write-Host ""
Write-Host "Now grant admin consent in Azure Portal:" -ForegroundColor Yellow
Write-Host "  1. Go to App registrations > $($app.DisplayName)" -ForegroundColor White
Write-Host "  2. Click API permissions" -ForegroundColor White
Write-Host "  3. Click Grant admin consent" -ForegroundColor White
Write-Host ""
