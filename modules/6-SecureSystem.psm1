# check out: https://admx.help/?Category=LAPS
function SecureSysten {
    # Set password expiry to 90 days
    net accounts /maxpwage:90

    # Set lockout threshold to 10 logon attempts
    net accounts /lockoutthreshold:10

    # Enable "Accounts: Limit local account use of blank passwords to console logon only"
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" LimitBlankPasswordUse -Type DWORD -Value 1 -Force

    # Enable windows update services
    Set-Service -Name "wuauserv" -StartupType Automatic
    Set-Service -Name "bits" -StartupType Automatic
    Set-Service -Name "cryptsvc" -StartupType Automatic
    Set-Service -Name "trustedinstaller" -StartupType Automatic

    # Start windows update services
    Start-Service -Name "wuauserv"
    Start-Service -Name "bits"
    Start-Service -Name "cryptsvc"
    Start-Service -Name "trustedinstaller"

    # Stop and disable microsoft ftp service
    Set-Service -Name "msftpsvc" -StartupType Disabled
    Stop-Service -Name "msftpsvc"

    # Enable Windows Defender Firewall with Advanced Security
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

    # Enable Windows Defender entirely (https://support.huntress.io/hc/en-us/articles/4402989131283-Enabling-Microsoft-Defender-using-Powershell-)
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -PropertyType DWORD -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -PropertyType DWORD -Force
    Start-Service -Name "WinDefend"
    Start-Service -Name "WdNisSvc"
}