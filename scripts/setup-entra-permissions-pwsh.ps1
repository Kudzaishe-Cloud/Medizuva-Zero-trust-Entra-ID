param(
    [string]$AppId = "092194d1-8c7a-4819-bfff-676f8b80a176",
    [string]$TenantId = "2aa3a349-78f7-4d13-b9b5-bb588852ae6d"
)

Write-Host "Installing Azure PowerShell modules..." -ForegroundColor Yellow
Install-Module -Name Az.Accounts -Force -Scope CurrentUser -AllowClobber
Install-Module -Name Az.Applications -Force -Scope CurrentUser -AllowClobber

Write-Host "Importing modules..." -ForegroundColor Yellow
Import-Module Az.Accounts -Force
Import-Module Az.Applications -Force

Write-Host "Connecting to Azure..." -ForegroundColor Yellow
Connect-AzAccount -TenantId $TenantId

Write-Host "Getting app registration..." -ForegroundColor Yellow
$app = Get-AzADApplication -ApplicationId $AppId
Write-Host "Found: $($app.DisplayName)" -ForegroundColor Green

Write-Host "Getting Microsoft Graph service principal..." -ForegroundColor Yellow
$graphSp = Get-AzADServicePrincipal -ApplicationId "00000003-0000-0000-c000-000000000000"

Write-Host "Building permissions list..." -ForegroundColor Yellow
$permissions = @(
    "User.Read.All",
    "Directory.Read.All",
    "IdentityRiskyUser.Read.All",
    "UserAuthenticationMethod.Read.All",
    "DeviceManagementManagedDevices.Read.All"
)

$allRoles = $graphSp.AppRole | Where-Object { $_.AllowedMemberTypes -contains "Application" }
$resourceAccess = @()

foreach ($perm in $permissions) {
    $role = $allRoles | Where-Object { $_.Value -eq $perm }
    if ($role) {
        $resourceAccess += @{
            Id = $role.Id
            Type = "Role"
        }
        Write-Host "✓ $perm" -ForegroundColor Green
    }
}

Write-Host "Updating app permissions..." -ForegroundColor Yellow
$params = @{
    ObjectId = $app.Id
    RequiredResourceAccess = @(
        @{
            ResourceAppId = $graphSp.AppId
            ResourceAccess = $resourceAccess
        }
    )
}

Update-AzADApplication @params

Write-Host ""
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host "Permissions added!" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "FINAL STEP - Grant Admin Consent:" -ForegroundColor Yellow
Write-Host "1. Go to Azure Portal" -ForegroundColor White
Write-Host "2. Navigate to App registrations" -ForegroundColor White
Write-Host "3. Find: $($app.DisplayName)" -ForegroundColor White
Write-Host "4. Click API permissions" -ForegroundColor White
Write-Host "5. Click the blue button: Grant admin consent" -ForegroundColor White
Write-Host "6. Click Yes to confirm" -ForegroundColor White
Write-Host ""
Write-Host "Then wait 5-10 minutes and trigger GitHub workflow." -ForegroundColor Cyan
