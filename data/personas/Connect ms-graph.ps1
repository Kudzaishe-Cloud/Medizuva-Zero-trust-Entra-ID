# 1. Connect to Microsoft Graph with necessary permissions
Connect-MgGraph -Scopes "User.ReadWrite.All" -UseDeviceAuthentication

# 2. Define the list of 10 users with specific attributes for ABAC testing
$users = @(
    @{DisplayName="Alice Smith"; UPN="alice.smith@micrlabs.onmicrosoft.com"; Job="Cloud Engineer"; Dept="IT"}
    @{DisplayName="Bob Johnson"; UPN="bob.johnson@micrlabs.onmicrosoft.com"; Job="Sales Manager"; Dept="Sales"}
    @{DisplayName="Charlie Davis"; UPN="charlie.davis@micrlabs.onmicrosoft.com"; Job="Accountant"; Dept="Finance"}
    @{DisplayName="Diana Prince"; UPN="diana.prince@micrlabs.onmicrosoft.com"; Job="Security Analyst"; Dept="IT"}
    @{DisplayName="Ethan Hunt"; UPN="ethan.hunt@micrlabs.onmicrosoft.com"; Job="Operations Lead"; Dept="Operations"}
    @{DisplayName="Fiona Gallagher"; UPN="fiona.gallagher@micrlabs.onmicrosoft.com"; Job="HR Specialist"; Dept="HR"}
    @{DisplayName="George Miller"; UPN="george.miller@micrlabs.onmicrosoft.com"; Job="Marketing Lead"; Dept="Marketing"}
    @{DisplayName="Hannah Abbott"; UPN="hannah.abbott@micrlabs.onmicrosoft.com"; Job="Sales Associate"; Dept="Sales"}
    @{DisplayName="Ian Wright"; UPN="ian.wright@micrlabs.onmicrosoft.com"; Job="Cloud Architect"; Dept="IT"}
    @{DisplayName="Jane Doe"; UPN="jane.doe@micrlabs.onmicrosoft.com"; Job="Financial Controller"; Dept="Finance"}
)

# 3. Define a secure temporary password
$passwordProfile = @{
    Password = "TemporaryPassword123!"
    ForceChangePasswordNextSignIn = $true
}

# 4. Loop to create each user
foreach ($user in $users) {
    $params = @{
        AccountEnabled = $true
        DisplayName = $user.DisplayName
        MailNickname = $user.DisplayName -replace " ",""
        UserPrincipalName = $user.UPN
        UsageLocation = "US"
        JobTitle = $user.Job
        Department = $user.Dept
        PasswordProfile = $passwordProfile
    }

    Write-Host "Creating user: $($user.DisplayName)..." -ForegroundColor Cyan
    New-MgUser @params
}

Write-Host "Successfully provisioned 10 users." -ForegroundColor Green