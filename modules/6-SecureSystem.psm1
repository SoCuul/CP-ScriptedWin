# check out: https://admx.help/?Category=LAPS
function SecureSystem {
    # Set password expiry to 90 days
    net accounts /maxpwage:90

    # Set lockout duration to 30 minutes
    net accounts /lockoutduration:30

    # Set lockout threshold to 10 logon attempts
    net accounts /lockoutthreshold:10

    # Set logon attempt counter reset minutes to 10
    net accounts /lockoutwindow:10

    # Set minimum password length to 10
    net accounts /minpwlen:10

    # Set remembered password history to 10
    net accounts /uniquepw:10

    # Disable unwanted accounts
    Disable-LocalUser -Name "Guest"
    Disable-LocalUser -Name "Administrator"

    # Apply registry keys
    # General keys
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" AutoInstallMinorUpdates -Type DWORD -Value 1 -Force
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate -Type DWORD -Value 0 -Force
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" AUOptions -Type DWORD -Value 4 -Force
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" AUOptions -Type DWORD -Value 4 -Force
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" DisableWindowsUpdateAccess -Type DWORD -Value 0 -Force
    Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" ElevateNonAdmins -Type DWORD -Value 0 -Force
    Set-ItemProperty -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" NoWindowsUpdate -Type DWORD -Value 0 -Force
    Set-ItemProperty -Path "HKLM\SYSTEM\Internet Communication Management\Internet Communication" DisableWindowsUpdateAccess -Type DWORD -Value 0 -Force
    Set-ItemProperty -Path "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" DisableWindowsUpdateAccess -Type DWORD -Value 0 -Force
    # Restrict CD ROM drive
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" AllocateCDRoms -Type DWORD -Value 1 -Force
    # Disallow remote access to floppy disks
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" AllocateFloppies -Type DWORD -Value 1 -Force
    # Disable auto Admin logon
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" AutoAdminLogon -Type DWORD -Value 0 -Force
    # Clear page file, will take longer to shutdown
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" ClearPageFileAtShutdown -Type DWORD -Value 1 -Force
    # Prevent users from installing printer drivers 
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" AddPrinterDrivers -Type DWORD -Value 1 -Force
    # Add auditing to Lsass.exe
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" AuditLevel -Type DWORD -Value 00000008 -Force
    # Enable LSA protection
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL -Type DWORD -Value 00000001 -Force
    # Limit use of blank passwords
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" LimitBlankPasswordUse -Type DWORD -Value 1 -Force
    # Auditing access of Global System Objects
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" auditbaseobjects -Type DWORD -Value 1 -Force
    # Auditing Backup and Restore
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" fullprivilegeauditing -Type DWORD -Value 1 -Force
    # Restrict Anonymous Enumeration #1
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" restrictanonymous -Type DWORD -Value 1 -Force
    # Restrict Anonymous Enumeration #2
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" restrictanonymoussam -Type DWORD -Value 1 -Force
    # Disable storage of domain passwords
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" disabledomaincreds -Type DWORD -Value 1 -Force
    # Take away Anonymous user Everyone permissions
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" everyoneincludesanonymous -Type DWORD -Value 0 -Force
    # Allow Machine ID for NTLM
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" UseMachineId -Type DWORD -Value 0 -Force
    # Do not display last user on logon
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" dontdisplaylastusername -Type DWORD -Value 1 -Force
    # Enable UAC
    # UAC setting, prompt on Secure Desktop
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" PromptOnSecureDesktop -Type DWORD -Value 1 -Force
    # Enable Installer Detection
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableInstallerDetection -Type DWORD -Value 1 -Force
    # Disable undocking without logon
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" undockwithoutlogon -Type DWORD -Value 0 -Force
    # Enable CTRL+ALT+DEL
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" DisableCAD -Type DWORD -Value 0 -Force
    # Max password age
    Set-ItemProperty -Path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA -Type DWORD -Value 1 -Force
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" MaximumPasswordAge -Type DWORD -Value 15 -Force
    # Disable machine account password changes
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" DisablePasswordChange -Type DWORD -Value 1 -Force
    # Require strong session key
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" RequireStrongKey -Type DWORD -Value 1 -Force
    # Require Sign/Seal
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" RequireSignOrSeal -Type DWORD -Value 1 -Force
    # Sign Channel
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" SignSecureChannel -Type DWORD -Value 1 -Force
    # Seal Channel
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" SealSecureChannel -Type DWORD -Value 1 -Force
    # Set idle time to 45 minutes
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" autodisconnect -Type DWORD -Value 45 -Force
    # Require Security Signature - Disabled pursuant to checklist
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" enablesecuritysignature -Type DWORD -Value 0 -Force
    # Enable Security Signature - Disabled pursuant to checklist
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" requiresecuritysignature -Type DWORD -Value 0 -Force
    # Clear null session pipes
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" NullSessionPipes /t REG_MULTI_SZ -Value "" -Force
    # Restict Anonymous user access to named pipes and shares
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" NullSessionShares /t REG_MULTI_SZ -Value "" -Force
    # Encrypt SMB Passwords
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" EnablePlainTextPassword -Type DWORD -Value 0 -Force
    # Clear remote registry paths
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" Machine /t REG_MULTI_SZ -Value "" -Force
    # Clear remote registry paths and sub-paths
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" Machine /t REG_MULTI_SZ -Value "" -Force
    # Enable smart screen for IE8
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" EnabledV8 -Type DWORD -Value 1 -Force
    # Enable smart screen for IE9 and up
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" EnabledV9 -Type DWORD -Value 1 -Force
    # Disable IE password caching
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" DisablePasswordCaching -Type DWORD -Value 1 -Force
    # Warn users if website has a bad certificate
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" WarnonBadCertRecving -Type DWORD -Value 1 -Force
    # Warn users if website redirects
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" WarnOnPostRedirect -Type DWORD -Value 1 -Force
    # Enable Do Not Track
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Internet Explorer\Main" DoNotTrack -Type DWORD -Value 1 -Force
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Internet Explorer\Download" RunInvalidSignatures -Type DWORD -Value 1 -Force
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" LOCALMACHINE_CD_UNLOCK -Type DWORD -Value 1 -Force
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" WarnonZoneCrossing -Type DWORD -Value 1 -Force
    # Show hidden files
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" Hidden -Type DWORD -Value 1 -Force
    # Disable sticky keys
    Set-ItemProperty -Path "HKU\.DEFAULT\Control Panel\Accessibility\StickyKeys" Flags /t REG_SZ -Value 506 -Force
    # Show super hidden files
    Set-ItemProperty -Path "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" ShowSuperHidden -Type DWORD -Value 1 -Force
    # Disable dump file creation
    Set-ItemProperty -Path "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" CrashDumpEnabled -Type DWORD -Value 0 -Force
    # Disable autoruns
    Set-ItemProperty -Path "HKCU\SYSTEM\CurrentControlSet\Services\CDROM" AutoRun -Type DWORD -Value 1 -Force

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