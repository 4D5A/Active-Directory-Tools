#MIT License

#Copyright (c) 2022 4D5A

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

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