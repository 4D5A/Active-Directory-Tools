<#
    .Synopsis
    Searches for AD User Accounts which may have at one point been granted elevated privileges.
    
    .Description
    Searches for AD User Accounts which have a value for the Active Directory object attribute adminCount set,
    for AD User Accounts that have a value set for the Active Directory object attribute adminAcount, this
    script checks for direct and nested (indirect) membership in specific Active Directory Security Groups
    that grant an AD User Account elevated privileges so Systems Administrators can review AD User Account
    membership in the elevated security groups to determine if any AD User Accounts should be removed from
    one or more elevated security groups. Results are sent to the console and to a text file.
    
    .Parameter ReportLocation
    If this parameter is not specified, the value for $ReportLocation will be set to "$env:USERPROFILE\Desktop\".
    
    .Parameter File
    If this paramter is not specified, the value for $File will be set to "Get-ElevatedADUsers_Report_$(Get-Date -Format ddMMyyyy_HHMMss).txt".

    .Parameter IncludeDisabled
    If this parameter is not specified the varaible $ElevatedUsers is set to "Get-ADUser -Filter {(Enabled -eq "true") -and (adminCount -ne 0)}".
    If it is specified the variable $ElevatedUsers to "Get-ADUser -Filter {(adminCount -ne 0)}".
    
    .Parameter LookCool
    I added this becase the switch -Verbose is reserved by PowerShell v2.
    
    .Example
    Get-ElevatedADUsers.ps1
    
    .Example
    Get-ElevatedADUsers.ps1 -ReportLocation C:\ -File get-elevatedadusers-results.txt
    
    .Example
    Get-ElevatedADUsers.ps1 -IncludeDisabled

    .Example
    Get-ElevatedADUsers.ps1 -LookCool

    .Example
    Get-ElevatedADUsers.ps1 -ReportLocation C:\ -File get-elevatedadusers-results.txt -IncludeDisabled -LookCool
#>
Param(
    [parameter(Mandatory=$False)]
    [String]$ReportLocation,
    [parameter(Mandatory=$False)]
    [String]$File,
    [parameter(Mandatory=$False)]
    [switch]$IncludeDisabled,
    [parameter(Mandatory=$False)]
    [switch]$LookCool
)

Import-Module -Name ActiveDirectory -ErrorAction:SilentlyContinue

If (-Not (Get-Module -Name ActiveDirectory)) {
    Add-WindowsCapability -Online -name "RSAT.ActiveDirectory.DS-LDS.Tools"
    Import-Module -Name ActiveDirectory -ErrorAction:SilentlyContinue
}

If($IncludeDisabled){
    $ElevatedUsers = Get-ADUser -Filter {(adminCount -ne 0)}
}
If($LookCool){
    $ElevatedUsers = Get-ADUser -Filter *
}
Else{
    $ElevatedUsers = Get-ADUser -Filter {(Enabled -eq "true") -and (adminCount -ne 0)}
}

If(-not($ReportLocation)){
    $ReportLocation = "$env:USERPROFILE\Desktop\"
}

If(-not($File)){
    $File = "Get-ElevatedADUsers_Report_$(Get-Date -Format ddMMyyyy_HHMMss).txt"
}

$Filename = $File
$Filepath = $ReportLocation

# Write information about the domain.
$Domain = Get-ADDomain | Select-Object -ExpandProperty DNSRoot
"The name of the domain is $Domain" | Tee-Object -FilePath "$Filepath\$Filename" -Append
$DomainController = Get-ADDomainController | Select-Object -ExpandProperty HostName
"The name of the Domain Controller is $DomainController" | Tee-Object -FilePath "$Filepath\$Filename" -Append

Foreach($ElevatedUser in $ElevatedUsers){
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
        If ($MembershipinElevatedGroups -notcontains "Protected Users"){
            $MemberofProtectedUsersNestedGroup = "yes"
        }
    }

    # Write the results to the host and a text file.
    If(-not $LookCool){
        If(($MembershipInElevatedGroups -ne $null) -or ($MembershipinElevatedNestedGroups -ne $null)){
            "Report for ${ElevatedUser}:" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Cyan
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
            If($MemberofProtecedUsersGroup = "no"){
                "$(($ElevatedUser).SamAccountName) is not a member of the Protected Users group." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
            }
        }
    } ElseIf ($LookCool){
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
}