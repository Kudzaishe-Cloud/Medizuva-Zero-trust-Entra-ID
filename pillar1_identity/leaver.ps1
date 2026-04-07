param(
    [string]$UserEmail,
    [string]$TicketNumber = "MANUAL"
)

Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory" -NoWelcome

$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
$auditLog  = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-AuditStep {
    param([string]$StepName, [string]$Status, [string]$Detail = "")
    $entry = [PSCustomObject]@{
        StepName  = $StepName
        Status    = $Status
        Detail    = $Detail
        ElapsedMs = $stopwatch.ElapsedMilliseconds
        Timestamp = (Get-Date -Format "HH:mm:ss.fff")
    }
    $auditLog.Add($entry)
    $colour = if ($Status -eq "OK") {"Green"} elseif ($Status -eq "FAIL") {"Red"} else {"Yellow"}
    Write-Host "[$($entry.Timestamp)] [$Status] $StepName $Detail" -ForegroundColor $colour
}

Write-Host "`n=================================================" -ForegroundColor Red
Write-Host "LEAVER PROCESS STARTED" -ForegroundColor Red
Write-Host "User:   $UserEmail" -ForegroundColor Red
Write-Host "Ticket: $TicketNumber" -ForegroundColor Red
Write-Host "=================================================" -ForegroundColor Red

try {
    
    $user = Get-MgUser -Filter "userPrincipalName eq '$UserEmail'" -ErrorAction Stop
    Write-AuditStep "User located" "OK" $user.DisplayName
} catch {
    Write-AuditStep "User located" "FAIL" $_.Exception.Message
    exit 1
}

try {
    Update-MgUser -UserId $user.Id -AccountEnabled:$false
    Write-AuditStep "Account disabled" "OK" "No new sign-ins possible"
} catch {
    Write-AuditStep "Account disabled" "FAIL" $_.Exception.Message
}

try {
    Revoke-MgUserSignInSession -UserId $user.Id | Out-Null
    Write-AuditStep "Sessions revoked" "OK" "All active logins terminated"
} catch {
    Write-AuditStep "Sessions revoked" "FAIL" $_.Exception.Message
}

try {
    $groups  = Get-MgUserMemberOf -UserId $user.Id -All
    $removed = 0
    foreach ($group in $groups) {
        try {
            Remove-MgGroupMemberByRef -GroupId $group.Id -DirectoryObjectId $user.Id
            $removed++
        } catch {}
    }
    Write-AuditStep "Groups removed" "OK" "$removed groups removed"
} catch {
    Write-AuditStep "Groups removed" "FAIL" $_.Exception.Message
}

try {
    $roles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule `
        -Filter "principalId eq '$($user.Id)'" -All
    foreach ($role in $roles) {
        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter @{
            Action           = "adminRemove"
            PrincipalId      = $user.Id
            RoleDefinitionId = $role.RoleDefinitionId
            DirectoryScopeId = "/"
        } | Out-Null
    }
    Write-AuditStep "PIM roles removed" "OK" "$($roles.Count) roles removed"
} catch {
    Write-AuditStep "PIM roles removed" "FAIL" $_.Exception.Message
}

$stopwatch.Stop()
$totalMs   = $stopwatch.ElapsedMilliseconds
$metTarget = $totalMs -lt 60000
$colour    = if ($metTarget) {"Green"} else {"Red"}
$result    = if ($metTarget) {"SUCCESS - target met"} else {"FAIL - exceeded 60 seconds"}

Write-Host "`n=================================================" -ForegroundColor $colour
Write-Host "LEAVER COMPLETE" -ForegroundColor $colour
Write-Host "Total time: ${totalMs}ms" -ForegroundColor $colour
Write-Host "Target:     60,000ms" -ForegroundColor $colour
Write-Host "Result:     $result" -ForegroundColor $colour
Write-Host "=================================================" -ForegroundColor $colour

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logPath   = "C:\Users\Kudzaishe\medizuva-zt-framework\data\personas\leaver_${TicketNumber}_${timestamp}.csv"
$auditLog | Export-Csv $logPath -NoTypeInformation
Write-Host "Audit log saved: $logPath" -ForegroundColor Cyan