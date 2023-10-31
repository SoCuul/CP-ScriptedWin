# check out: https://admx.help/?Category=LAPS
function Set-SecurityPolicy {
    # Set password expiry to 90 days
    net accounts /maxpwage:90

    # Set lockout threshold to 10 logon attempts
    net accounts /lockoutthreshold:10

    # Enable "Accounts: Limit local account use of blank passwords to console logon only"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" LimitBlankPasswordUse -Type DWORD -Value 1 -Force
}