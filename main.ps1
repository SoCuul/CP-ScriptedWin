Import-Module '.\modules\1-SetAdminAccounts.psm1' -Force
Import-Module '.\modules\2-RemoveForbiddenUsers.psm1' -Force
Import-Module '.\modules\3-SetAccountPasswords.psm1' -Force
Import-Module '.\modules\4-InstallAntimalware.psm1' -Force

# Set window title
$Host.UI.RawUI.WindowTitle = "CyberPatriot Team Strawberry • Windows Scripts"

function Show-Menu {
    Clear-Host

    Write-Output @"
========================================================
===  CyberPatriot Team Strawberry - Windows Scripts  ===
========================================================

1) Set Admin Accounts
2) Delete forbidden users
3) Set account passwords
4) Download and install Antimalware software
"@
}

# Interactive Menu
do {
    Show-Menu
    Write-Output ""
    $selection = Read-Host "Please make a selection"
    Write-Output ""
    Write-Output "--------------------------------------------------------"
    Write-Output ""

    switch ($selection) {
        '1' {
            Set-AdminAccounts
        }
        '2' {
            Remove-ForbiddenUsers
        }
        '3' {
            Set-AccountPasswords
        }
        '4' {
            Install-Antimalware
        }
        'q' {
            'Exiting...'
        }
        default {
            'Invalid selection. Please try again.'
        }
    }

    Write-Output ""
    pause
}
until ($selection -eq 'q')