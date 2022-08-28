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
If($Full){
    $ElevatedUsers = Get-ADUser -Filter {(adminCount -ne 0)}
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
        $MembershipinElevatedGroups += "ServerOperators"
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