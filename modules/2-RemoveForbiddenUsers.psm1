function Remove-ForbiddenUsers {
    $Response = (Read-Host "Enter which accounts should exist on the system. Example: account1,account2")
    $ValidUsers = $Response.Split(",")

    $AllUsers = Get-LocalUser

    # Don't mess with these accounts
    $DefaultAccounts = @('Administrator', 'DefaultAccount', 'Guest', 'WDAGUtilityAccount', 'defaultuser0', 'sshd')

    Foreach ($User in $AllUsers) {
        $UserName = $User.name

        # Don't mess with these accounts
        if ($DefaultAccounts -Contains $UserName) {
            Write-Output "Skipping default account: $UserName"
            continue
        } 

        # Don't mess with system accounts
        if ($UserName -Match '\$') {
            Write-Output "Skipping system account: $UserName"
            continue
        }

        # Check if account should exist on the system
        if ($ValidUsers -NotContains $UserName) {
            Remove-LocalUser -Name $UserName

            Write-Host -NoNewline "- User has been deleted: ${UserName}`r`n"
        }

    }
}
