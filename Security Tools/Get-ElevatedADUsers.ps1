Param(
    [Parameter(Mandatory=$False)]
    [switch]$Full,
    [Parameter(Mandatory=$False)]
    [switch]$IncludeDisabled,
    [parameter(Mandatory=$False)]
    [String]$ReportLocation,
    [parameter(Mandatory=$False)]
    [String]$File,
    [parameter(Mandatory=$False)]
    [switch]$LookCool
)

Import-Module ActiveDirectory
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

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Enterprise Admins").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Enterprise Admins"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Schema Admins").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Schema Admins"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Domain Admins").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Domain Admins"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Administrators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Administrators"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Account Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Account Operators"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Server Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "ServerOperators"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Print Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Print Operators"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Backup Operators").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Backup Operators"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Cert Publishers").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Cert Publishers"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Domain Controllers").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Domain Controllers"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Read-Only Domain Controllers").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Read-Only Domain Controllers"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Replicator").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MembershipinElevatedGroups += "Replicator"
    }

    If (Get-ADUser -Filter "memberOf -RecursiveMatch '$((Get-ADGroup "Protected Users").DistinguishedName)'" -SearchBase ((Get-ADUser -Identity $ElevatedUser).DistinguishedName)){
        $MemberofProtectedUsersGroup = "yes"
    }

    # Write the results to the host and a text file.
    If(-not $LookCool){
        If($MembershipInElevatedGroups -ne $null){
            "Report for ${ElevatedUser}:" | Tee-Object -FilePath "$Filepath\$Filename" -Append
            "$(($ElevatedUser).SamAccountName) currently has elevated privileges." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
            If($MemberofProtecedUsersGroup = "no"){
                "$(($ElevatedUser).SamAccountName) is not a member of the Protected Users group." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
            }
            "$(($ElevatedUser).SamAccountName) is a member of the following elevated groups:" | Tee-Object -FilePath "$Filepath\$Filename" -Append
            Foreach($Group in $MembershipinElevatedGroups){
                "$Group" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
            }
        }
    } ElseIf ($LookCool){
        "----------------------------------------------------------------------------------------------" | Tee-Object -FilePath "$Filepath\$Filename" -Append
        "Report for ${ElevatedUser}:" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Cyan
        "Checking the value of the adminCount attribute of the Active Directory object..." | Tee-Object -FilePath "$Filepath\$Filename" -Append
        $adminCount = Get-ADUser -Identity $ElevatedUser -Property adminCount | Select-Object -ExpandProperty adminCount
        If(($adminCount -eq $null) -or ($adminCount -eq 0)){
            "$ElevatedUser has a null value for its adminCount value." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Green
        } ElseIf(($adminCount -eq 1) -and ($adminCount -ne $null)){
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
            If(-not $MembershipinElevatedGroups){
                "$(($ElevatedUser).SamAccountName) is not a member of a privileged Active Directory group." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Green
            }
            If($MembershipInElevatedGroups -ne $null){
                "$(($ElevatedUser).SamAccountName) currently has elevated privileges." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
                "Checking if the user is a member of the Protected Users group..." | Tee-Object -FilePath "$Filepath\$Filename" -Append
                If($MemberofProtecedUsersGroup = "no"){
                    "$(($ElevatedUser).SamAccountName) is not a member of the Protected Users group." | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
                }
                "$(($ElevatedUser).SamAccountName) is a member of the following elevated groups:" | Tee-Object -FilePath "$Filepath\$Filename" -Append
                Foreach($Group in $MembershipinElevatedGroups){
                    "$Group" | Tee-Object -FilePath "$Filepath\$Filename" -Append | Write-Host -ForegroundColor Red
                }
            }
        }
        "----------------------------------------------------------------------------------------------" | Tee-Object -FilePath "$Filepath\$Filename" -Append
    }
}