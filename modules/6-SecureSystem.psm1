# check out: https://admx.help/?Category=LAPS
function SecureSystem {
    Write-Host -NoNewLine "Press enter to begin securing the system..."
    $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') | Out-Null
    Write-Host ""

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
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" AutoInstallMinorUpdates -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" NoAutoUpdate -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" AUOptions -Value 4 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" AUOptions -Value 4 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" DisableWindowsUpdateAccess -Value 0 -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" ElevateNonAdmins -Value 0 -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" NoWindowsUpdate -Value 0 -Force
    # Restrict CD ROM drive
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" AllocateCDRoms -Value 1 -Force
    # Disallow remote access to floppy disks
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" AllocateFloppies -Value 1 -Force
    # Disable auto Admin logon
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" AutoAdminLogon -Value 0 -Force
    # Clear page file, will take longer to shutdown
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" ClearPageFileAtShutdown -Value 1 -Force
    # Prevent users from installing printer drivers 
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" AddPrinterDrivers -Value 1 -Force
    # Enable LSA protection
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" RunAsPPL -Value 00000001 -Force
    # Limit use of blank passwords
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" LimitBlankPasswordUse -Value 1 -Force
    # Auditing access of Global System Objects
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" auditbaseobjects -Value 1 -Force
    # Auditing Backup and Restore
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" fullprivilegeauditing -Value 1 -Force
    # Restrict Anonymous Enumeration #1
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" restrictanonymous -Value 1 -Force
    # Restrict Anonymous Enumeration #2
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" restrictanonymoussam -Value 1 -Force
    # Disable storage of domain passwords
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" disabledomaincreds -Value 1 -Force
    # Take away Anonymous user Everyone permissions
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" everyoneincludesanonymous -Value 0 -Force
    # Allow Machine ID for NTLM
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" UseMachineId -Value 0 -Force
    # Do not display last user on logon
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" dontdisplaylastusername -Value 1 -Force
    # Enable UAC
    # UAC setting, prompt on Secure Desktop
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" PromptOnSecureDesktop -Value 1 -Force
    # Enable Installer Detection
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableInstallerDetection -Value 1 -Force
    # Disable undocking without logon
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" undockwithoutlogon -Value 0 -Force
    # Enable CTRL+ALT+DEL
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" DisableCAD -Value 0 -Force
    # Max password age
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA -Value 1 -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" MaximumPasswordAge -Value 15 -Force
    # Disable machine account password changes
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" DisablePasswordChange -Value 1 -Force
    # Require strong session key
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" RequireStrongKey -Value 1 -Force
    # Require Sign/Seal
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" RequireSignOrSeal -Value 1 -Force
    # Sign Channel
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" SignSecureChannel -Value 1 -Force
    # Seal Channel
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Netlogon\Parameters" SealSecureChannel -Value 1 -Force
    # Set idle time to 45 minutes
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" autodisconnect -Value 45 -Force
    # Require Security Signature - Disabled pursuant to checklist
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" enablesecuritysignature -Value 0 -Force
    # Enable Security Signature - Disabled pursuant to checklist
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" requiresecuritysignature -Value 0 -Force
    # Clear null session pipes
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" NullSessionPipes  -Value "" -Force
    # Restict Anonymous user access to named pipes and shares
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanServer\Parameters" NullSessionShares  -Value "" -Force
    # Encrypt SMB Passwords
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\LanmanWorkstation\Parameters" EnablePlainTextPassword -Value 0 -Force -Type DWord
    # Clear remote registry paths
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedExactPaths" Machine  -Value "" -Force -Type DWord
    # Clear remote registry paths and sub-paths
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths" Machine  -Value "" -Force
    # Disable IE password caching
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" DisablePasswordCaching -Value 1 -Force
    # Warn users if website has a bad certificate
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" WarnonBadCertRecving -Value 1 -Force
    # Warn users if website redirects
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" WarnOnPostRedirect -Value 1 -Force
    # Enable Do Not Track
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main" DoNotTrack -Value 1 -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" WarnonZoneCrossing -Value 1 -Force
    # Show hidden files
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" Hidden -Value 1 -Force
    # Show super hidden files
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" ShowSuperHidden -Value 1 -Force
    # Disable dump file creation
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" CrashDumpEnabled -Value 0 -Force

    # Keys that require creation things
    New-Item -Path "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\Internet Communication Management\Internet Communication" DisableWindowsUpdateAccess -Value 0 -Force
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" -Force
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\WindowsUpdate" DisableWindowsUpdateAccess -Value 0 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\Download" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Download" RunInvalidSignatures -Value 1 -Force
    New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_LOCALMACHINE_LOCKDOWN\Settings" LOCALMACHINE_CD_UNLOCK -Value 1 -Force
    # Add auditing to Lsass.exe
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" AuditLevel -Value 00000008 -Force
    # Enable smart screen for IE8
    New-Item -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" -Force
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" EnabledV8 -Value 1 -Force -Type DWord
    # Enable smart screen for IE9 and up
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Internet Explorer\PhishingFilter" EnabledV9 -Value 1 -Force -Type DWord
    # Disable autoruns
    New-Item -Path "HKCU:\SYSTEM\CurrentControlSet\Services\CDROM" -Force
    Set-ItemProperty -Path "HKCU:\SYSTEM\CurrentControlSet\Services\CDROM" AutoRun -Value 1 -Force

    # Disable remote assistance
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" fAllowToGetHelp -Value 0 -Force
    netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

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

    # Enable Windows Defender Firewall with Advanced Security
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

    # Enable Windows Defender entirely (https://support.huntress.io/hc/en-us/articles/4402989131283-Enabling-Microsoft-Defender-using-Powershell-)
    Set-MpPreference -DisableRealtimeMonitoring $false
    Set-MpPreference -DisableIOAVProtection $false
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "Real-Time Protection" -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBehaviorMonitoring" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableOnAccessProtection" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableScanOnRealtimeEnable" -Value 0 -Force
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 0 -Force
    Start-Service -Name "WinDefend"
    Start-Service -Name "WdNisSvc"

    # Stop and disable microsoft ftp service
    Set-Service -Name "msftpsvc" -StartupType Disabled
    Stop-Service -Name "msftpsvc"
}