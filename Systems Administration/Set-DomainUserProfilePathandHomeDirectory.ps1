#$oldServerName = Read-Host -Prompt "What is the name or IP address of the old server?"
$oldServerName = "\\server1"
#$newServerName = Read-Host -Prompt "What is the name or IP address of the new server?"
$newServerName = "\\server2"
Import-Module ActiveDirectory
$userou = 'DC=domain,DC=net'
$users = Get-ADUser -Filter * -SearchBase $userou -Properties SamAccountName, profilePath, HomeDirectory -ResultSetSize $null
foreach ($user in $users) {
    $directoryname = $user.samaccountname
    If ($user.profilePath -eq "$oldServerName\profiles\$directoryname") {
        Set-ADUser -Identity $user.samaccountname -profilePath "$newServerName\profiles\$directoryname"
    }
    If ($user.HomeDirectory -eq "$oldServerName\home\$directoryname") {
        set-ADUser -Identity $user.samaccountname -HomeDirectory "$newServerName\home\$directoryname"
    }
}
Write-Host "You must change the information used in the Common Mapped Network Drives Group Policy Object, log all domain users out of all computers, and then domain users need to login to their computers again before users will connect to their new profile path and home directory."