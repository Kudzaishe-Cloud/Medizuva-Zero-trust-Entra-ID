# joiner.ps1
# ============================================================
# PURPOSE: Create a brand new Entra ID account when a new
# employee joins MediZuva. Once created, dynamic groups
# automatically assign the correct access based on Department.
# ============================================================

# param() defines what information must be provided when running the script
param(
    [string]$FirstName,    # employee's first name
    [string]$LastName,     # employee's last name
    [string]$Department,   # Clinical, Billing, Operations, IT, Pharmacy, or Radiology
    [string]$JobTitle,     # their role e.g. Doctor, Billing Clerk
    [string]$EmployeeID    # unique ID e.g. MZ0501
)

# Connect to Microsoft Graph with permission to create users
Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome

# Build the email address from the employee's details
$email    = "$($FirstName.ToLower()).$($LastName.ToLower()).$EmployeeID@micrlabs.onmicrosoft.com"

# Build the mailNickname — required by Microsoft, must be unique per user
$nickname = "$($FirstName.ToLower()).$($LastName.ToLower())$EmployeeID"

Write-Host "`nCreating account for: $FirstName $LastName" -ForegroundColor Cyan
Write-Host "Email:      $email"
Write-Host "Department: $Department"
Write-Host "EmployeeID: $EmployeeID"

# Create the user account in Entra ID
New-MgUser -BodyParameter @{
    DisplayName       = "$FirstName $LastName"
    GivenName         = $FirstName
    Surname           = $LastName
    UserPrincipalName = $email
    MailNickname      = $nickname

    # Department drives dynamic group assignment automatically
    # Must match exactly: Clinical, Billing, Operations, IT, Pharmacy, Radiology
    Department        = $Department

    JobTitle          = $JobTitle
    EmployeeId        = $EmployeeID
    UsageLocation     = "ZW"
    AccountEnabled    = $true

    # Temporary password — user must change on first login
    PasswordProfile   = @{
        Password                      = "MZWelcome@$EmployeeID!"
        ForceChangePasswordNextSignIn = $true
    }
}

Write-Host "`nAccount created: $email" -ForegroundColor Green
Write-Host "Dynamic group access will assign within 5-10 minutes" -ForegroundColor Yellow