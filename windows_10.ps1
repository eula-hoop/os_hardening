if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
  Write-Warning "You are not running this as local administrator. Run it again in an elevated prompt."
  Read-Host "Press any key to exit..."
  exit
}

Write-Host "Setting notifications and VoIP calls to lock screen..."

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK /t REG_DWORD /d 0 /f

Write-Host "Setting welcome experience..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f

Write-Host "Setting tips and suggestions..."

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f

Write-Host "Setting shared experiences..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f

Write-Host "Setting clipboard history..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Clipboard" /v EnableClipboardHistory /t REG_DWORD /d 0 /f

Write-Host "Setting sync across devices..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Clipboard" /v EnableCloudClipboard /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\Software\Microsoft\Clipboard" /v CloudClipboardAutomaticUpload /t REG_DWORD /d 0 /f

Write-Host "Setting autocorrect..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\Settings" /v EnableHwkbAutocorrection /t REG_DWORD /d 0 /f

Write-Host "Setting autoplay for devices..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v DisableAutoplay /t REG_DWORD /d 1 /f

Write-Host "Setting online sign up..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /v OsuRegistrationStatus /t REG_DWORD /d 0 /f

Write-Host "Setting cloud search..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f

Write-Host "Setting telemetry..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 1 /f

Write-Host "Setting User Activity..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f

Write-Host "Setting location settings..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f

Write-Host "Setting microphone settings.."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMicrophone /t REG_DWORD /d 2 /f

Write-Host "Setting webcam settings.."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCamera /t REG_DWORD /d 2 /f

Write-Host "Setting voice recognition..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech\Preferences" /v ModeForOff /t REG_DWORD /d 1 /f

Write-Host "Disabling security notifications..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender Security Center\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Notifications" /v DisableNotifications /t REG_DWORD /d 1 /f

Write-Host "Setting account info..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessAccountInfo /t REG_DWORD /d 2 /f

Write-Host "Setting contacts..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessContacts /t REG_DWORD /d 2 /f

Write-Host "Setting calendar..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCalendar /t REG_DWORD /d 2 /f


Write-Host "Setting phone call history..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessCallHistory /t REG_DWORD /d 2 /f


Write-Host "Setting email.."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessEmail /t REG_DWORD /d 2 /f

Write-Host "Setting messaging.."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v Value /t REG_SZ /d Deny /f

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMessaging /t REG_DWORD /d 2 /f

Write-Host "Setting sharing across devices..."

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /v CdpSessionUserAuthzPolicy /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /v NearShareChannelUserAuthzPolicy /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP" /v RomeSdkChannelUserAuthzPolicy /t REG_DWORD /d 0 /f

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v RomeSdkChannelUserAuthzPolicy /t REG_DWORD /d 1 /f

Write-Host "Setting background apps..."

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsRunInBackground /t REG_DWORD /d 2 /f

Write-Host "Clearing history..."

Clear-History

Read-Host "Press any key to exit..."

exit
