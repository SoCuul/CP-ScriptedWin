Import-Module '.\modules\1-SetAdminAccounts.psm1' -Force
Import-Module '.\modules\2-RemoveForbiddenUsers.psm1' -Force
Import-Module '.\modules\3-SetAccountPasswords.psm1' -Force
Import-Module '.\modules\4-InstallAntimalware.psm1' -Force
Import-Module '.\modules\5-SearchForFiles.psm1' -Force
Import-Module '.\modules\6-SecureSystem.psm1' -Force
Import-Module '.\modules\7-ShowFileShares.psm1' -Force
Import-Module '.\modules\8-ShowProgramsPorts.psm1' -Force

# Check if ran as administrator
$ShouldBypassAdminCheck = Test-Path -Path "./BypassAdmin"
if (!$ShouldBypassAdminCheck -and (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))) {
    Write-Output "This script must be run as Administrator. Exiting..."
    exit
}

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
4) Download and install antimalware software
5) Search for files
6) Secure system
7) Show file shares
8) Show programs using ports
"@
}

# Interactive Menu
while ($true) {
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
        '5' {
            Search-ForFiles
        }
        '6' {
            Secure-System
        }
        '7' {
            Show-FileShares
        }
        '8' {
            Show-ProgramsPorts
        }
        'q' {
            Write-Output 'Exiting...'
            exit
        }
        default {
            'Invalid selection. Please try again.'
        }
    }

    Write-Output ""
    pause
}