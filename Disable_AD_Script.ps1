param (
    [string]$username,
    [string]$password
)
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

$path = "PATH_TO_CSV_LIST_OF_USERS_TO_DISABLE"
$csv = Import-Csv -path $path

$upns = @()
foreach ($row in $csv) {
    if ($row.UPN) {
        $upns += $row.UPN.Trim()
    }
}

# Prepare named parameters as a hashtable
$args = @{
    userUPNs = $upns
}

# Disable all users + run sync on the remote AD server
Invoke-Command -ComputerName 'serverName' -Credential $cred -ScriptBlock {
    param([string[]]$userUPNs)
    Import-Module ActiveDirectory

    foreach ($user in $userUPNs) {
        $userAccount = Get-ADUser -Identity $user -Properties Enabled
        if ($userAccount.Enabled){
            Disable-ADAccount -Identity $user
            Write-Output "Disabled: $user"
        }
        else{
            Write-Output "User already disabled"
        }
    }
    # Start Azure Sync process
    Start-Process -FilePath "PATH_TO_FILE"
    Write-Output "Running Azure Sync"

} -ArgumentList (,($upns))

Start-ScheduledTask "GADS"
Write-Output "Started Scheduled Task: GADS"

