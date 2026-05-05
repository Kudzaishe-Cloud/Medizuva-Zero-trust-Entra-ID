param(
    [string]$CsvPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\medizuva_500_personas.csv",
    [string]$LogPath = "C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\provisioning_log.csv"
)

Connect-MgGraph -Scopes "User.ReadWrite.All"

$personas = Import-Csv $CsvPath
$log = [System.Collections.Generic.List[PSCustomObject]]::new()
$ok = 0
$fail = 0

Write-Host "Starting provisioning of $($personas.Count) users..." -ForegroundColor Cyan

foreach ($p in $personas) {
    try {
        New-MgUser -BodyParameter @{
            DisplayName       = "$($p.FirstName) $($p.LastName)"
            GivenName         = $p.FirstName
            Surname           = $p.LastName
            UserPrincipalName = $p.Email
MailNickname      = "$($p.FirstName.ToLower()).$($p.LastName.ToLower())$($p.EmployeeID)"
Department        = $p.Department
            JobTitle          = $p.JobTitle
            City              = $p.Location
            EmployeeId        = $p.EmployeeID
            UsageLocation     = "ZW"
            AccountEnabled    = $true
            PasswordProfile   = @{
                Password                      = "MZTemp@$($p.EmployeeID)!"
                ForceChangePasswordNextSignIn = $true
            }
        } | Out-Null

        $ok++
        $log.Add([PSCustomObject]@{
            Email     = $p.Email
            Status    = "Success"
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })

        if ($ok % 50 -eq 0) {
            Write-Host "  Progress: $ok / $($personas.Count)" -ForegroundColor Green
        }

    } catch {
        $fail++
        $log.Add([PSCustomObject]@{
            Email     = $p.Email
            Status    = "Failed"
            Error     = $_.Exception.Message
            Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        })
        Write-Warning "Failed: $($p.Email)"
    }

    Start-Sleep -Milliseconds 200
}

$log | Export-Csv $LogPath -NoTypeInformation

Write-Host "=== PROVISIONING COMPLETE ===" -ForegroundColor Yellow
Write-Host "Succeeded: $ok" -ForegroundColor Green
Write-Host "Failed: $fail"
Write-Host "Log saved: $LogPath"