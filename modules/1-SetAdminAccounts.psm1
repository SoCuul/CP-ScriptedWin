function Set-AdminAccounts {
    $Response = (Read-Host "Enter which accounts should be admin. Example: account1,account2")
    $AdminsList = $Response.Split(",")

    $AllUsers = Get-LocalUser

    # Don't mess with these accounts
    $DefaultAccounts = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount')

    Foreach ($User in $AllUsers) {
        $UserName = $User.name

        # Don't mess with these accounts
        if ($DefaultAccounts -Contains $UserName) {
            Write-Output "Skipping default account: $UserName"
            continue
        } 

        # Check if user should be admin
        if ($AdminsList -Contains $UserName) {
            Remove-LocalGroupMember -Group "Administrators" -Member $UserName

            Write-Host -NoNewline "+ Admin has been given to: ${UserName}`r`n"
        }
        else {
            Remove-LocalGroupMember -Group "Administrators" -Member $UserName

            Write-Host -NoNewline "- Admin has been revoked from: ${UserName}`r`n"
        }

    }
}