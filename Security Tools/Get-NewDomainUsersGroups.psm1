Function Get-NewDomainUsersGroups()
{
    <#
        .Synopsis
            Enumerate recently created domain user or group accounts.
        
        .Description
            Enumerate recently created domain user or group accounts. Depending on which switches are passed to the script, the enumeration may be domain users that are members of the domain admins group that were created in the last n days, domain users that are not members of the domain admins group that were created in the last n days, or groups that were crated in the last n days.

        .Example
            # Enumerate all domain users that were created in the last 30 days
            Get-NewDomainUsersGroups -age 30 -type user
        
        .Example
            # Enumerate all domain groups that were created in the last 30 days
            Get-NewDomainUsersGroups -age 30 -type group
        
        .Example
            # Enumerate all domain administrators that were created in the last 30 days.
            Get-NewDomainUsersGroups -age 30 -type user -accessslevel admin
    #>

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

param(
    # Use switch m to only display the name for each active administrator account
    [Parameter(Mandatory=$True,Position=1)]
    [string]$age,
    [Parameter(Mandatory=$False)]
    [string]$type,
    [Parameter(Mandatory=$False)]
    [string]$accesslevel
)

Import-Module ActiveDirectory

    $When = ((Get-Date).AddDays(-$age)).Date
    $DomainAdminsDn = (Get-ADGroup 'Domain Admins').DistinguishedName
    $EnterpriseAdminsDn = (Get-ADGroup 'Enterprise Admins').DistinguishedName
    $DomainUsersDn = (Get-ADGroup 'Domain Users').DistinguishedName
    If (($type -ne $null) -AND ($accesslevel -ne $null)) {
        If (($type -like 'user*') -AND ($accesslevel -like 'admin*')) {
            Get-ADUser -Filter { ((memberof -eq $DomainAdminsDn) -and (whenCreated -ge $When))}
            Get-ADUser -Filter { ((memberof -eq $EnterpriseAdminsDn) -and (whenCreated -ge $When))}
        }
        If (($type -like 'user*') -AND ($accesslevel -like 'user*')) {
            Get-ADUser -Filter { ((-not (memberof -eq $DomainUsersDn)) -and (whenCreated -ge $When))}
        }
    }
    If ($accesslevel -eq $null) {
        If ($type -like 'user*') {
            Get-ADUser -Filter {whenCreated -ge $When}
        }
        If ($type -like 'group*') {
            Get-ADGroup -Filter {whenCreated -ge $When}
        }
    }
}
