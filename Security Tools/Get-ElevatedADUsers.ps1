<#
    .Synopsis
    Searches for AD User Accounts which may have at one point been granted elevated privileges.
    
    .Description
    Searches for AD User Accounts which have a value for the Active Directory object attribute adminCount set, for AD User Accounts that have
    a value set for the Active Directory object attribute adminAcount, this script checks for direct and nested (indirect) membership in
    specific Active Directory Security Groups that grant an AD User Account elevated privileges so Systems Administrators can review AD User Account
    membership in the elevated security groups to determine if any AD User Accounts should be removed from one or more elevated security groups.
    Results are sent to the console and to a text file.
    
    .Parameter ReportLocation
    If this parameter is not specified, the value for $ReportLocation will be set to "$env:USERPROFILE\Desktop\".
    
    .Parameter File
    If this paramter is not specified, the value for $File will be set to "Get-ElevatedADUsers_Report_$(Get-Date -Format ddMMyyyy_HHMMss).txt".

    .Parameter IncludeDisabled
    If this parameter is not specified the varaible $ElevatedUsers is set to "Get-ADUser -Filter {(Enabled -eq "true") -and (adminCount -ne 0)}".
    If it is specified the variable $ElevatedUsers to "Get-ADUser -Filter {(adminCount -ne 0)}".
    
    .Parameter Csv
    If this parameter is specified, results are sent to the console and a csv file.
    
    .Parameter Details
    If this parameter is not specified, the object's DistinguishedName, SamAccountName, AccountStatus, HasElevatedRights, and MemberofProtectedUsersGroup
    properties are displayed in the console. If this parameter is specified, all of the object's properties are displayed in the console.
    If the Csv parameter is specified, all of the object's properties are sent to the csv file.
    
    .Example
    Get-ElevatedADUsers.ps1
    
    .Example
    Get-ElevatedADUsers.ps1 -ReportLocation C:\ -File get-elevatedadusers-results.csv -Csv
    
    .Example
    Get-ElevatedADUsers.ps1 -IncludeDisabled

    .Example
    Get-ElevatedADUsers.ps1 -details
    
    .Example
    Get-ElevatedADUsers.ps1 -ReportLocation C:\ -File get-elevatedadusers-results.csv -Csv -IncludeDisabled -Details

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

Param(
    [parameter(Mandatory=$False)]
    [String]$ReportLocation,
    [parameter(Mandatory=$False)]
    [String]$File,
    [parameter(Mandatory=$False)]
    [Switch]$IncludeDisabled,
    [parameter(Mandatory=$False)]
    [Switch]$Csv,
    [parameter(Mandatory=$False)]
    [Switch]$Details
    [parameter(Mandatory=$False)]
    [Switch]$LookCool
)

Import-Module -Name ActiveDirectory -ErrorAction:SilentlyContinue

If (-Not (Get-Module -Name ActiveDirectory)) {
    Add-WindowsCapability -Online -name "RSAT.ActiveDirectory.DS-LDS.Tools"
    Import-Module -Name ActiveDirectory -ErrorAction:SilentlyContinue
}

$global:Content = $null
$global:Content = @()

If($IncludeDisabled){
    $ElevatedUsers = Get-ADUser -Filter *
}
Else{
    $ElevatedUsers = Get-ADUser -Filter {(Enabled -eq "true")}
}

If(-not($ReportLocation)){
    $ReportLocation = "$env:USERPROFILE\Desktop\"
}

If(-not($File)){
    $File = "Get-ElevatedADUsers_Report_$(Get-Date -Format ddMMyyyy_HHMMss).csv"
}

$Filename = $File
$Filepath = $ReportLocation

# Write information about the domain.
$Domain = Get-ADDomain | Select-Object -ExpandProperty DNSRoot
Write-Host "The name of the domain is $Domain"
$DomainController = Get-ADDomainController | Select-Object -ExpandProperty HostName
Write-Host "The name of the Domain Controller is $DomainController"

Foreach($ElevatedUser in $ElevatedUsers){

    $adminCount = $null
    $MembershipinElevatedGroups = $null
    $MemberofProtectedUsersGroup = $null
    $MemberofProtectedUsersNestedGroup = $null
    $MembershipinElevatedNestedGroups = $null

    $MembershipinElevatedGroups = @()

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Enterprise Admins*"){
        $MembershipinElevatedGroups += "Enterprise Admins"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Schema Admins*"){
        $MembershipinElevatedGroups += "Schema Admins"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Domain Admins*"){
        $MembershipinElevatedGroups += "Domain Admins"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Administrators*"){
        $MembershipinElevatedGroups += "Administrators"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Account Operators*"){
        $MembershipinElevatedGroups += "Account Operators"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Server Operators*"){
        $MembershipinElevatedGroups += "Server Operators"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Print Operators*"){
        $MembershipinElevatedGroups += "Print Operators"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Backup Operators*"){
        $MembershipinElevatedGroups += "Backup Operators"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Cert Publishers*"){
        $MembershipinElevatedGroups += "Cert Publishers"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Domain Controllers*"){
        $MembershipinElevatedGroups += "Domain Controllers"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Read-Only Domain Controllers*"){
        $MembershipinElevatedGroups += "Read-Only Domain Controllers"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Replicator*"){
        $MembershipinElevatedGroups += "Replicator"
    }

    If (((Get-ADUser -Identity $ElevatedUser -Properties memberOf).memberOf) -like "*Protected Users*"){
        $MemberofProtectedUsersGroup = "yes"
    }

    $MembershipinElevatedNestedGroups = @()

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Enterprise Admins").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Enterprise Admins"){
            $MembershipinElevatedNestedGroups += "Enterprise Admins"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Schema Admins").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Schema Admins"){
            $MembershipinElevatedNestedGroups += "Schema Admins"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Domain Admins").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Domain Admins"){
            $MembershipinElevatedNestedGroups += "Domain Admins"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Administrators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Administrators"){
            $MembershipinElevatedNestedGroups += "Administrators"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Account Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Account Operators"){
            $MembershipinElevatedNestedGroups += "Account Operators"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Server Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Server Operators"){
            $MembershipinElevatedNestedGroups += "Server Operators"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Print Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Print Operators"){
            $MembershipinElevatedNestedGroups += "Print Operators"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Backup Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Backup Operators"){
            $MembershipinElevatedNestedGroups += "Backup Operators"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Cert Publishers").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Cert Publishers"){
            $MembershipinElevatedNestedGroups += "Cert Publishers"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Domain Controllers").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Domain Controllers"){
            $MembershipinElevatedNestedGroups += "Domain Controllers"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Read-Only Domain Controllers").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Read-Only Domain Controllers"){
            $MembershipinElevatedNestedGroups += "Read-Only Domain Controllers"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Replicator").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MembershipinElevatedGroups -notcontains "Replicator"){
            $MembershipinElevatedNestedGroups += "Replicator"
        }
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Protected Users").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        If ($MemberofProtectedUsersGroup -ne "yes"){
            $MemberofProtectedUsersNestedGroup = "yes"
        }
    }
    
    $adminCount = Get-ADUser -Identity $ElevatedUser -Property adminCount | Select-Object -ExpandProperty adminCount
    $Enabled = Get-ADUser -Identity $ElevatedUser -Property Enabled | Select-Object -ExpandProperty Enabled
        If ($Enabled -eq $True){
            $AccountStatus = "Enabled"
        } Else {
            $AccountStatus = "Disabled"
        }

    $global:Content += [pscustomobject][ordered]@{
        objectGUID = $($ElevatedUser).ObjectGUID;
        DistinguishedName = $($ElevatedUser).DistinguishedName;
        SamAccountName = $($ElevatedUser).SamAccountName;
        adminCount = $adminCount;
        AccountStatus = $AccountStatus
        HasElevatedRights = If (($MembershipinElevatedGroups -ne $null) -or ($MembershipinElevatedNestedGroups -ne $null)) {"Yes"} Else {"No"};
        MemberofProtectedUsersGroup = If ($MembershipinElevatedGroups -ne $null) {"Yes"} Else {"No"};
        MemberofProtectedUsersNestedGroup = If ($MembershipinElevatedNestedGroups -ne $null) {"Yes"} Else {"No"};
        MembershipinElevatedGroups = [System.String]::Join(", ", $MembershipinElevatedGroups);
        MembershipinElevatedNestedGroups = [System.String]::Join(", ", $MembershipinElevatedNestedGroups);
    }
}

If ($Csv) {
    $global:Content | Sort-Object HasElevatedRights -Descending | Export-Csv -Path "$FilePath\$Filename" -Append -Encoding Ascii -NoTypeInformation
}

If ($Details) {
    $global:Content | Sort-Object HasElevatedRights -Descending | Format-Table
}

If ($LookCool) {
    "----------------------------------------------------------------------------------------------" | Tee-Object -FilePath "$Filepath\$Filename" -Append
    "Report for ${ElevatedUser}:" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Cyan
    "Checking the value of the adminCount attribute of the Active Directory object..." | Tee-Object -FilePath "$Filepath\$Filename" -Append
    $adminCount = Get-ADUser -Identity $ElevatedUser -Property adminCount | Select-Object -ExpandProperty adminCount
    If(($adminCount -eq $null) -or ($adminCount -eq 0)){
        "$ElevatedUser has a null value for its adminCount value." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Green
    } ElseIf(($adminCount -eq 1) -or ($adminCount -ne $null)){
        "$ElevatedUser has a non-zero adminCount value." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
        "$ElevatedUser has an adminCount value of $adminCount" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
        "Checking if the value of the enabled attribute of the Active Directory object..." | Tee-Object -FilePath "$Filepath\$Filename" -Append
        $enabled = Get-ADUser -Identity $ElevatedUser -Property Enabled | Select-Object -ExpandProperty Enabled
        If($enabled -eq $True){
            "$ElevatedUser is enabled" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Green
        } ElseIf ($enabled -eq $False){
            "$ElevatedUser is disabled" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Yellow 
        }
        "Checking if the user is a member of a privileged Active Directory group..." | Tee-Object -FilePath "$Filepath\$Filename" -Append
        If((-not $MembershipinElevatedGroups) -and (-not $MembershipinElevatedNestedGroups)){
            "$(($ElevatedUser).SamAccountName) is not a member of a privileged Active Directory group." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Green
        }ElseIf(($MembershipInElevatedGroups -ne $null) -or ($MembershipinElevatedNestedGroups -ne $null)){
            "$(($ElevatedUser).SamAccountName) currently has elevated privileges." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
            If($MembershipinElevatedGroups -ne $null){
                "$(($ElevatedUser).SamAccountName) is a member of the following elevated groups:" | Tee-Object -FilePath "$Filepath\$Filename" -Append
                Foreach($Group in $MembershipinElevatedGroups){
                    "$Group" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
                }
            }
            If($MembershipinElevatedNestedGroups -ne $null){
                "$(($ElevatedUser).SamAccountName) is a member of the following nested elevated groups:" | Tee-Object -FilePath "$Filepath\$Filename" -Append
                Foreach($NestedGroup in $MembershipinElevatedNestedGroups){
                    "$NestedGroup" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
                }
            }
        "Checking if the user is a member of the Protected Users group..." | Tee-Object -FilePath "$Filepath\$Filename" -Append
            If($MemberofProtecedUsersGroup = "no"){
                "$(($ElevatedUser).SamAccountName) is not a member of the Protected Users group." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
            }
        } 
    }
    "----------------------------------------------------------------------------------------------" | Tee-Object -FilePath "$Filepath\$Filename" -Append
}

Else {
    $global:Content | Select-Object DistinguishedName, SamAccountName, AccountStatus, HasElevatedRights | Sort-Object HasElevatedRights -Descending | Format-Table
}