# mover.ps1
# ============================================================
# PURPOSE: Update an employee's department when they transfer
# to a different role at MediZuva.
#
# HOW IT WORKS: Updating the Department attribute triggers
# Entra's dynamic groups to automatically:
#   - Remove the user from their old department group
#   - Add them to their new department group
# This revokes old access and grants new access with no
# manual intervention needed.
# ============================================================

param(
    [string]$UserEmail,       # the employee's full email address
    [string]$NewDepartment,   # their new department name
    [string]$NewJobTitle      # their new job title
)

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome

# Look up the user in Entra ID by their email address
# -Filter is how we search — like a WHERE clause in SQL
$user = Get-MgUser -Filter "userPrincipalName eq '$UserEmail'"

# Check the user was actually found before trying to update
if (-not $user) {
    Write-Host "ERROR: User not found: $UserEmail" -ForegroundColor Red
    exit 1
}

# Show what we are changing before making the change
Write-Host "`nMoving user: $($user.DisplayName)" -ForegroundColor Cyan
Write-Host "Old department: $($user.Department)"
Write-Host "New department: $NewDepartment"
Write-Host "New job title:  $NewJobTitle"

# Update only the changed attributes
# Everything else (name, email, location) stays the same
Update-MgUser -UserId $user.Id -BodyParameter @{
    Department = $NewDepartment
    JobTitle   = $NewJobTitle
}

Write-Host "`nMover complete for: $UserEmail" -ForegroundColor Green
Write-Host "Dynamic groups will recalculate within 5-10 minutes" -ForegroundColor Yellow
Write-Host "Old department access will be revoked automatically"
Write-Host "New department access will be granted automatically"

# ============================================================
# HOW TO TEST:
# First check a Billing user's current department in the portal
# Then run:
# .\mover.ps1 -UserEmail "kudzai.chikwanda1@micrlabs.onmicrosoft.com" `
#             -NewDepartment "Clinical" -NewJobTitle "Doctor"
#
# Wait 10 minutes then check the user in Entra portal
# They should have moved from MZ-Billing-Staff to MZ-Clinical-Staff group
# ============================================================