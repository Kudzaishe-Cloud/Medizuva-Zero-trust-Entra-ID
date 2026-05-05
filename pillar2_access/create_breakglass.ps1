# pillar2_access/create_breakglass.ps1
# ============================================================
# Creates a dedicated MediZuva break-glass emergency account.
# This account is excluded from ALL Conditional Access policies
# so you always have a way in if something goes wrong.
#
# AFTER running this script:
#   1. Write the password down and store it OFFLINE (not in M365)
#   2. Assign Global Administrator role to this account in the portal
#   3. Do NOT register MFA on this account
#   4. Never use it for day-to-day work
# ============================================================

Connect-MgGraph -Scopes "User.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -NoWelcome -ContextScope Process

$BreakGlassUPN = "breakglass@micrlabs.onmicrosoft.com"

# Check if it already exists
$existing = Get-MgUser -Filter "userPrincipalName eq '$BreakGlassUPN'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[INFO] Break-glass account already exists: $BreakGlassUPN" -ForegroundColor Yellow
    Write-Host "       Object ID: $($existing.Id)" -ForegroundColor Yellow
    exit 0
}

# Generate a strong random password
$chars   = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#%^&*"
$password = -join ((1..20) | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })

# Create the account
try {
    $newUser = New-MgUser -DisplayName "MediZuva BreakGlass" `
        -UserPrincipalName $BreakGlassUPN `
        -MailNickname "breakglass" `
        -AccountEnabled `
        -PasswordProfile @{
            Password                      = $password
            ForceChangePasswordNextSignIn = $false
        } `
        -UsageLocation "ZW"

    Write-Host "`n=================================================" -ForegroundColor Green
    Write-Host " BREAK-GLASS ACCOUNT CREATED" -ForegroundColor Green
    Write-Host "=================================================" -ForegroundColor Green
    Write-Host " UPN       : $BreakGlassUPN" -ForegroundColor White
    Write-Host " Object ID : $($newUser.Id)" -ForegroundColor White
    Write-Host " Password  : $password" -ForegroundColor Yellow
    Write-Host "=================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host " !! WRITE THIS PASSWORD DOWN NOW - it will not be shown again !!" -ForegroundColor Red
    Write-Host ""

    # Assign Global Administrator role
    $gaRole = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
    if (-not $gaRole) {
        # Role may need to be activated first
        $gaRoleDef = Get-MgDirectoryRoleTemplate | Where-Object { $_.DisplayName -eq "Global Administrator" }
        $gaRole = New-MgDirectoryRole -RoleTemplateId $gaRoleDef.Id
    }

    New-MgDirectoryRoleMember -DirectoryRoleId $gaRole.Id -BodyParameter @{
        "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($newUser.Id)"
    }

    Write-Host " [OK] Global Administrator role assigned" -ForegroundColor Green
    Write-Host ""
    Write-Host " Next steps:" -ForegroundColor Cyan
    Write-Host "   1. Store the password above in a physical safe or offline vault" -ForegroundColor Cyan
    Write-Host "   2. Do NOT register MFA for this account" -ForegroundColor Cyan
    Write-Host "   3. Update create_ca_policies.ps1 to also exclude this UPN" -ForegroundColor Cyan
    Write-Host "=================================================" -ForegroundColor Green

} catch {
    Write-Host "[FAIL] Could not create break-glass account: $($_.Exception.Message)" -ForegroundColor Red
}
