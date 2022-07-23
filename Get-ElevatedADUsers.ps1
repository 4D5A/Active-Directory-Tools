Import-Module ActiveDirectory
$ProtectedUsers = Get-ADUser -Filter {(Enabled -eq "true") -and (adminCount -eq 1)}
Foreach($ProtectedUser in $ProtectedUsers){
    Write-Host "$(($ProtectedUser).samAccountName) Active Directory attribute for adminCount is not 0."
    Write-Host "$(($ProtectedUser).samAccountName) is a member of the following protected groups:"

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Enterprise Admins*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Enterprise Admins."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Schema Admins*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Schema Admins."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Domain Admins*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Domain Admins."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Administrators*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Administrators."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Account Operators*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Account Operators."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Server Operators*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Server Operators."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Print Operators*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Print Operators."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Backup Operators*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Backup Operators."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Cert Publishers*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Cert Publishers."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Domain Controllers*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Domain Controllers."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Read-Only Domain Controllers*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Read-Only Domain Controllers."
    }

    If (((Get-ADUser -Identity $ProtectedUser -Properties memberOf).memberOf) -like "*Replicator*"){
        Write-Host "$($ProtectedUser).samAccountName is a member of Replicator."
    }
    }