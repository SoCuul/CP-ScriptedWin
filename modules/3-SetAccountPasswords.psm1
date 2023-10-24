function Set-AccountPasswords {
    $Response = (Read-Host "Enter which passwords accounts should have. Example: account1;password1,account2;password2")
    $UsersToChange = $Response.Split(",")

    $AllUsers = Get-LocalUser

    Foreach ($ChangeData in $UsersToChange) {
        # Parse name and password
        $SplitChangedData = $ChangeData.Split(";")

        $UserToChange = $SplitChangedData[0]
        $PasswordToChange = $SplitChangedData[1]

        $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String $PasswordToChange

        Set-LocalUser -Name $UserToChange -Password $SecurePassword

        Write-Host -NoNewline "+ User named `"${UserToChange}`" has been given the password: `"${PasswordToChange}`"`r`n"

    }
}