@echo off
mode con: cols=80 lines=20
setlocal enabledelayedexpansion
chcp 65001 > nul
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

:: This is not a script detailing every single part for you to try to understand what is happening, 
:: if you're interested the code is right here and you have a plethora of search engines available for you 
:: to find out what each piece of the script does.

if "%errorlevel%" NEQ "0" (
    title Error
    echo This script requires administrative privileges.
    echo Please right click file → Run as an administrator.
    pause
    exit
)

for /f "tokens=1-3 delims=:." %%a in ("%TIME%") do set /a "START_TIME=(((%%a*60)+1%%b %% 100)*60)+1%%c %% 100"
set pwr=powershell.exe -Command
cls
echo This script will harden and debloat your windows system for you.
echo.
title Setting up...
echo Setting up...
echo.
echo The script is now silently running all commands and processes in the background just sit back and let the script work its magic. 
echo The script will sound 5 beeps when it is done.
echo.
title Running...
echo Running...
:: Windows Store
%pwr% "Get-AppxPackage -AllUsers *store* | Remove-AppxPackage" > nul
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f > nul
sc delete PushToInstall > nul

:: Music, TV, ...
%pwr% "Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage" > nul
%pwr% "Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart" > nul

:: Xbox and Game DVR
%pwr% "Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage" > nul
sc delete XblAuthManager > nul
sc delete XblGameSave > nul
sc delete XboxNetApiSvc > nul
sc delete XboxGipSvc > nul
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f > nul
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable > nul
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f > nul

:: Sticky Notes
%pwr% "Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage" > nul

:: Maps
%pwr% "Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage" > nul
sc delete MapsBroker > nul
sc delete lfsvc > nul
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable > nul

:: Alarms, Clock, Mail, Calendar etc...
set Apps=(
    "Microsoft.3DBuilder*"
    "Microsoft.549981C3F5F10*"
    "Microsoft.Appconnector*"
    "Microsoft.BingFinance*"
    "Microsoft.BingFoodAndDrink*"
    "Microsoft.BingHealthAndFitness*"
    "Microsoft.BingNews*"
    "Microsoft.BingSports*"
    "Microsoft.BingTranslator*"
    "Microsoft.BingTravel*"
    "Microsoft.CommsPhone*"
    "Microsoft.ConnectivityStore*"
    "Microsoft.WindowsFeedbackHub*"
    "Microsoft.GetHelp*"
    "Microsoft.Getstarted*"
    "Microsoft.Messaging*"
    "Microsoft.Microsoft3DViewer*"
    "Microsoft.MicrosoftOfficeHub*"
    "Microsoft.MicrosoftPowerBIForWindows*"
    "Microsoft.MixedReality.Portal*"
    "Microsoft.NetworkSpeedTest*"
    "Microsoft.Office.Sway*"
    "Microsoft.OneConnect*"
    "Microsoft.People*"
    "Microsoft.Print3D*"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.SkypeApp*"
    "MicrosoftTeams*"
    "Microsoft.Todos*"
    "Microsoft.Wallet*"
    "Microsoft.Whiteboard*"
    "Microsoft.WindowsMaps*"
    "*maps*"
    "Microsoft.WindowsPhone*"
    "Microsoft.WindowsReadingList*"
    "Microsoft.YourPhone*"
    "Microsoft.ZuneMusic*"
    "Microsoft.ZuneVideo*"
    "*ACGMediaPlayer*"
    "*ActiproSoftwareLLC*"
    "*AdobePhotoshopExpress*"
    "*Amazon.com.Amazon*"
    "*Asphalt8Airborne*"
    "*AutodeskSketchBook*"
    "*BubbleWitch3Saga*"
    "*CaesarsSlotsFreeCasino*"
    "*CandyCrush*"
    "*COOKINGFEVER*"
    "*CyberLinkMediaSuiteEssentials*"
    "*Disney*"
    "*DrawboardPDF*"
    "*Duolingo-LearnLanguagesforFree*"
    "*EclipseManager*"
    "*FarmVille2CountryEscape*"
    "*FitbitCoach*"
    "*Flipboard*"
    "*HiddenCity*"
    "*Hulu*"
    "*iHeartRadio*"
    "*Keeper*"
    "*Kindle*"
    "*LinkedInforWindows*"
    "*MarchofEmpires*"
    "*NYTCrossword*"
    "*OneCalendar*"
    "*Pandora*"
    "*PhototasticCollage*"
    "*PicsArt-PhotoStudio*"
    "*PolarrPhotoEditorAcademicEdition*"
    "*Prime*"
    "*RoyalRevolt*"
    "*Shazam*"
    "*Sidia.LiveWallpaper*"
    "*SlingTV*"
    "*Speed"
    "*Sway*"
    "*TuneInRadio*"
    "*Twitter*"
    "*Viber*"
    "*WinZipUniversal*"
    "*Wunderlist*"
    "*XING*"
    "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*"
    "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*"
    "SAMSUNGELECTRONICSCoLtd.SamsungNotes*"
    "SAMSUNGELECTRONICSCoLtd.SamsungFlux*"
    "SAMSUNGELECTRONICSCO.LTD.StudioPlus*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*"
    "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*"
    "SAMSUNGELECTRONICSCO.LTD.PCGallery*"
    "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*"
    "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*"
)

for %%A in (%Apps%) do (
    %pwr% "Get-AppXPackage -AllUsers |Where-Object {$_.InstallLocation -like '%%A'} | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register $($_.InstallLocation)}"
)

schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable > nul
for /f "tokens=1* delims= " %%I in ('reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit"') do (reg delete "%%I" /f) > nul
for /f "tokens=1* delims= " %%I in ('reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print"') do (reg delete "%%I" /f) > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f > nul
sc delete DiagTrack > nul
sc delete dmwappushservice > nul
sc delete WerSvc > nul
sc delete OneSyncSvc > nul
sc delete MessagingService > nul
sc delete wercplsupport > nul
sc delete PcaSvc > nul
sc config wlidsvc start=demand > nul
sc delete wisvc > nul
sc delete RetailDemo > nul
sc delete diagsvc > nul
sc delete shpamsvc  > nul
sc delete TermService > nul
sc delete UmRdpService > nul
sc delete SessionEnv > nul
sc delete TroubleshootingSvc > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete "%%I" /f > nul) > nul
for /f "tokens=1*" %%I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete "%%I" /f > nul) > nul
sc delete diagnosticshub.standardcollector.service > nul
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f > nul
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f > nul
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f > nul
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable > nul
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable > nul
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable > nul
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable > nul
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable > nul
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable > nul
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable > nul
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable > nul
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable > nul
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable > nul
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" > nul
%pwr% "Get-AppxPackage -Name MicrosoftCorporationII.QuickAssist | Remove-AppxPackage -AllUsers" > nul

:: Fuck edge
taskkill /F /IM browser_broker.exe > nul
taskkill /F /IM RuntimeBroker.exe > nul
taskkill /F /IM MicrosoftEdge.exe > nul
taskkill /F /IM MicrosoftEdgeCP.exe > nul
taskkill /F /IM MicrosoftEdgeSH.exe > nul
%pwr% "mv C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe C:\Windows\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe_BAK" > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\MicrosoftEdge.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f > nul
%pwr% "Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart" > nul
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" /f > nul
reg delete "HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" /f > nul
reg delete "HKLM\SOFTWARE\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" /f > nul
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" /f > nul
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f > nul
reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" /f > nul
if not exist "C:\Program Files (x86)\Microsoft\Edge\Application\BHO" (
    rmdir /s /q "C:\Program Files (x86)\Microsoft\Edge\Application\BHO" > nul
)
schtasks /create /tn "Part of Debloat - IEtoEDGE Removal" /tr "powershell.exe Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft\Edge\Application' -Recurse -Filter 'BHO' | Remove-Item -Force > nul-Recurse" /sc daily /ri 1 /du 1 /f > nul



:: Fuck OneDrive 
taskkill /f /im OneDrive.exe > nul
taskkill /f /im FileCoAuth.exe > nul
:: Official Removal
if exist "%WinDir%\System32\OneDriveSetup.exe" (
    start /wait "%WinDir%\System32\OneDriveSetup.exe" /uninstall > nul
)
if exist "%WinDir%\SysWOW64\OneDriveSetup.exe" (
    start /wait "%WinDir%\SysWOW64\OneDriveSetup.exe" /uninstall > nul
)
:: Files Cleanup
:: File Explorer - Navigation Bar
reg add "HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "(default)" /t REG_SZ /d "OneDrive" /f > nul
reg add "HKCU\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f > nul
:: AppData / Local
rmdir /s /q "%localappdata%\OneDrive" > nul
:: ProgramData
rmdir /s /q "%programdata%\Microsoft OneDrive" > nul
:: Shortcuts
del /f /q "%userprofile%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" > nul
del /f /q "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" > nul
:: Program Files
rmdir /s /q "C:\Program Files (x86)\Microsoft OneDrive" > nul
rmdir /s /q "C:\Program Files\Microsoft OneDrive" > nul
:: Scheduled Tasks
schtasks /delete /tn "*OneDrive*" /f > nul
:: Services
sc stop OneDriveUpdaterService > nul
sc delete OneDriveUpdaterService > nul
:: Remove Previous Accounts/Sync Options
reg delete "HKCU\Software\Microsoft\OneDrive" /f > nul
:: Remove previously set One Drive settings
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /f > nul
:: Remove Right Click Menu Context Options
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\FileSyncHelper" /f > nul
:: Remove from 'Default' user account
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT" > nul
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > nul
reg unload "hku\Default" > nul
:: Disable OneDrive from being used
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f > nul


:: System restore...
%pwr% Disable-ComputerRestore -Drive "C:\" > nul
vssadmin delete shadows /all /Quiet > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f > nul
schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable > nul


reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /v "Enabled" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Mobility" /v "OptedIn" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v EnableStatus /t REG_DWORD /d 1 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /t REG_SZ /d Deny /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /t REG_SZ /d Deny /f > nul
reg delete "HKCR\*\shellex\ContextMenuHandlers\ModernSharing" /f > nul
reg delete "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f > nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f > nul
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f > nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f > nul
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f > nul
reg delete "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul
reg delete "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}" /f > nul
reg delete "HKCR\*\shellex\ContextMenuHandlers\Sharing" /f > nul
reg delete "HKCR\Directory\Background\shellex\ContextMenuHandlers\Sharing" /f > nul
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\Sharing" /f > nul
reg delete "HKCR\Directory\shellex\CopyHookHandlers\Sharing" /f > nul
reg delete "HKCR\Directory\shellex\PropertySheetHandlers\Sharing" /f > nul
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\Sharing" /f > nul
reg delete "HKCR\Drive\shellex\PropertySheetHandlers\Sharing" /f > nul
reg delete "HKCR\LibraryFolder\background\shellex\ContextMenuHandlers\Sharing" /f > nul
reg delete "HKCR\UserLibraryFolder\shellex\ContextMenuHandlers\Sharing" /f > nul
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" /f > nul
reg delete "HKLM\SOFTWARE\Classes\Folder\ShellEx\ContextMenuHandlers\Library Location" /f > nul


:: Install PS7 instead of PS5
%pwr% "Install-Module -SkipPublisherCheck -Name Microsoft.WinGet.Client -Force" > nul
%pwr% "winget install Microsoft.PowerShell" > nul
::powershell.exe -Command "Set-Variable -Name pwsh7Path -Value 'C:\Program Files\PowerShell\7\pwsh.exe'"
::powershell.exe -Command "Set-Variable -Name pwsh5Path -Value 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'"
::powershell.exe -Command "Set-Variable -Name pwsh7Shortcut -Value 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell\Windows PowerShell.lnk'"
::powershell.exe -Command "Set-Variable -Name pwsh5Shortcut -Value 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Windows PowerShell (x86)\Windows PowerShell (x86).lnk'"
::powershell.exe -Command "$pwsh7ShortcutTarget = (Get-Item -Path $pwsh7Shortcut).Target"
::powershell.exe -Command "$pwsh5ShortcutTarget = (Get-Item -Path $pwsh5Shortcut).Target"
::powershell.exe -Command "(Get-Item -Path $pwsh7Shortcut).Target = $pwsh7Path"
::powershell.exe -Command "(Get-Item -Path $pwsh5Shortcut).Target = $pwsh7Path"

::powershell.exe -Command "$env:PATH = ($env:PATH -split ";" | Where-Object { $_ -ne $pwsh5Path }) -join ";"
::powershell.exe -Command "$env:PATH += ';$pwsh7Path'"
::%pwr% "Stop-Process -Name explorer"
::%pwr% "Start-Process -FilePath explorer"
set "PS7InstallerPath=C:\PSTemp\PowerShell-7.3.9-win-x64.msi"
set "PS7InstallerURL=https://github.com/PowerShell/PowerShell/releases/download/v7.4.1/PowerShell-7.4.1-win-x64.msi"
if not exist "C:\Program Files\PowerShell\7\pwsh.exe" (
    mkdir C:\PSTemp
    powershell -Command "Invoke-WebRequest -Uri %PS7InstallerURL% -OutFile %PS7InstallerPath%"
    msiexec /i %PS7InstallerPath% /qn
    rmdir /s /q C:\PSTemp
)
:: Add to Right Click Context Menu
reg add "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin\command" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin\command" /f > nul
reg add "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin" /f > nul
reg add "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin\command" /f > nul
reg delete "HKLM\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShell7AsAdmin" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin" /v "(default)" /t REG_SZ /d "Open with PowerShell 7 (Admin)" /f > nul
reg delete "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin" /v "Extended" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin" /v "HasLUAShield" /t REG_SZ /d "" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin" /v "Icon" /t REG_SZ /d "powershell.exe" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin\command" /v "(default)" /t REG_SZ /d "powershell -WindowStyle Hidden -NoProfile -Command \"Start-Process -Verb RunAs pwsh.exe  -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"\"" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin" /v "(default)" /t REG_SZ /d "Open with PowerShell 7 (Admin)" /f > nul
reg delete "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin" /v "Extended" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin" /v "HasLUAShield" /t REG_SZ /d "" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin" /v "Icon" /t REG_SZ /d "pwsh.exe" /f > nul
reg add "HKLM\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin\command" /v "(default)" /t REG_SZ /d "powershell -WindowStyle Hidden -NoProfile -Command \"Start-Process -Verb RunAs pwsh.exe  -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"\"" /f > nul
reg add "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin" /v "(default)" /t REG_SZ /d "Open with PowerShell 7 (Admin)" /f > nul
reg delete "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin" /v "Extended" /f > nul
reg add "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin" /v "HasLUAShield" /t REG_SZ /d "" /f > nul
reg add "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin" /v "Icon" /t REG_SZ /d "pwsh.exe" /f > nul
reg add "HKLM\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin\command" /v "(default)" /t REG_SZ /d "powershell -WindowStyle Hidden -NoProfile -Command \"Start-Process -Verb RunAs pwsh.exe -ArgumentList  \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"\"" /f > nul



@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin" > nul
choco install mpv > nul
choco install librewolf > nul

:: Disable hardware related bloat and privacy nightmares
bcdedit /deletevalue useplatformclock > nul
bcdedit /set useplatformtick yes > nul
bcdedit /set disabledynamictick yes > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f > nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "ClearPageFileAtShutdown" /t REG_DWORD /d 1 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 5 /f > nul
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f > nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f > nul
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f > nul
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /f > nul
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d 506 /f > nul
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /f > nul
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v Flags /t REG_SZ /d 58 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" /v value /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Input\TIPC" /f > nul
reg add "HKCU\Software\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /f > nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v Disabled /t REG_DWORD /d 1 /f > nul

:: Disable Tailored Experiences
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\System" /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v HistoryViewEnabled /t REG_DWORD /d 0 /f > nul

:: Disable Telemetry
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v MaxTelemetryAllowed /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > nul

:: Disable Scheduled Tasks
schtasks /delete /tn "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /f > nul
schtasks /delete /tn "Microsoft\Windows\Application Experience\ProgramDataUpdater" /f > nul
schtasks /delete /tn "Microsoft\Windows\Autochk\Proxy" /f > nul
schtasks /delete /tn "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /f > nul
schtasks /delete /tn "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /f > nul
schtasks /delete /tn "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /f > nul

:: Disable Activity Feed and User Activities
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f > nul

:: Disable Maps AutoUpdate
reg add "HKLM\SYSTEM\Maps" /v AutoUpdateEnabled /t REG_DWORD /d 0 /f > nul

:: Create registry keys if they don't exist
if not exist "HKCU\SOFTWARE\Microsoft\Siuf\Rules" reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /f > nul
if not exist "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /f > nul

:: Disable WiFi HotSpot Reporting and AutoConnect
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f > nul
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f > nul

:: Disable Content Delivery Manager
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v ContentDeliveryAllowed /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v OemPreInstalledAppsEnabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEnabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v PreInstalledAppsEverEnabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338387Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338388Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353698Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338393Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353694Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-353696Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f > nul
:: Disable CloudContent
if not exist "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f > nul
:: Disable AdvertisingInfo
if not exist "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /f > nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f > nul
:: Disable Windows Error Reporting
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f > nul
schtasks /delete /tn "Microsoft\Windows\Windows Error Reporting\QueueReporting" /f > nul
:: Disable DeliveryOptimization
if not exist "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f > nul
:: Block Windows Telemetry using Windows Firewall
netsh advfirewall firewall show rule name="Block Windows Telemetry in" > nul 2>&1
if %errorlevel% neq 0 (
    netsh advfirewall firewall add rule name="Block Windows Telemetry in" dir=in action=block remoteip=134.170.30.202,137.116.81.24,157.56.106.189,184.86.53.99,2.22.61.43,2.22.61.66,204.79.197.200,23.218.212.69,65.39.117.23,65.55.108.23,64.4.54.254 enable=yes > nul
)
netsh advfirewall firewall show rule name="Block Windows Telemetry out" > nul 2>&1
if %errorlevel% neq 0 (
    netsh advfirewall firewall add rule name="Block Windows Telemetry out" dir=out action=block remoteip=65.55.252.43,65.52.108.29,191.232.139.254,65.55.252.92,65.55.252.63,65.55.252.93,65.55.252.43,65.52.108.29,194.44.4.200,194.44.4.208,157.56.91.77,65.52.100.7,65.52.100.91,65.52.100.93,65.52.100.92,65.52.100.94,65.52.100.9,65.52.100.11,168.63.108.233,157.56.74.250,111.221.29.177,64.4.54.32,207.68.166.254,207.46.223.94,65.55.252.71,64.4.54.22,131.107.113.238,23.99.10.11,68.232.34.200,204.79.197.200,157.56.77.139,134.170.58.121,134.170.58.123,134.170.53.29,66.119.144.190,134.170.58.189,134.170.58.118,134.170.53.30,134.170.51.190,157.56.121.89,134.170.115.60,204.79.197.200,104.82.22.249,134.170.185.70,64.4.6.100,65.55.39.10,157.55.129.21,207.46.194.25,23.102.21.4,173.194.113.220,173.194.113.219,216.58.209.166,157.56.91.82,157.56.23.91,104.82.14.146,207.123.56.252,185.13.160.61,8.254.209.254,198.78.208.254,185.13.160.61,185.13.160.61,8.254.209.254,207.123.56.252,68.232.34.200,65.52.100.91,65.52.100.7,207.46.101.29,65.55.108.23,23.218.212.69 enable=yes > nul
)
:: Disable TIPC and HttpAcceptLanguageOptOut
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v Enabled /t REG_DWORD /d 0 /f > nul
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f > nul
:: Disable DoNotShowFeedbackNotifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f > nul
:: Disable SIUF
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f > nul
:: Set UAC to MAX
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f > nul
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f > nul
:: Install OOSU10
:: Credit: Chris Titus for oosu config file.
%pwr% "Start-BitsTransfer 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe'" > nul
%pwr% "Start-BitsTransfer 'https://raw.githubusercontent.com/Emil8630/hardener/main/ooshutup10.cfg'" > nul
%pwr% "Start-Process -FilePath './OOSU10.exe' -ArgumentList 'ooshutup10.cfg /quiet' -Wait" > nul
%pwr% "Remove-Item -Path '.\OOSU10.exe' -Force" > nul
%pwr% "Remove-Item -Path '.\ooshutup10.cfg' -Force" > nul

title Finishing touches...
echo Finishing touches...
:: Finishing deepclean of filesystem
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*" /v StateFlags0005 /t REG_DWORD /d 2 /f > nul
%pwr% "Start-Process -FilePath CleanMgr.exe -ArgumentList '/sagerun:5' -Wait" > nul
:: Remove files with specific extensions
for %%e in (gid, chk, old) do (
    for /r "%systemdrive%\" %%f in (*%%e) do del "%%f" > nul
)
:: Remove files from Recycle Bin
for /r "%SystemRoot%\RecycleBin\" %%f in (*) do del "%%f" > nul
for /d /r "%SystemRoot%\RecycleBin\" %%d in (*) do rmdir "%%d" > nul
:: Remove files with specific extensions from Windows directory
for %%e in (bak, chk, old) do (
    for /r "%windir%\" %%f in (*%%e) do del "%%f" > nul
)
:: Remove files from Prefetch folder
for %%f in ("%windir%\prefetch\*") do (
    del "%%f" > nul
)
:: Remove Temp folder and recreate it
rmdir /s /q "%windir%\temp" > nul
mkdir "%windir%\temp" > nul
:: Remove files from user profile directories
set userprofile=%userprofile%
for %%d in (cookies, recent) do (
    for /r "%userprofile%\%%d\" %%f in (*) do (
        del "%%f" > nul
    )
)
:: Remove directories
for %%d in ("Local Settings\Temporary Internet Files", "AppData\Local\Microsoft\Windows\Temporary Internet Files", "Local Settings\Temp", "recent") do (
    rmdir /s /q "%userprofile%\%%d" > nul
)
:: Remove $Recycle.bin folder
rmdir /s /q "%systemdrive%\$Recycle.bin" > nul
:: Run commands to clear Internet Explorer cache
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 2 > nul
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 1 > nul
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8 > nul
:: Remove directories
for %%d in (AMD, NVIDIA, INTEL) do (
    rmdir /s /q "%systemdrive%\%%d" > nul
)
:: Remove files from Temp folders
for %%t in ("C:\Windows\Temp", "%userprofile%\AppData\Local\Temp") do (
    pushd "%%t" > nul
    for /r %%d in (*) do rmdir "%%d" /s /q > nul
    popd > nul
)
for /f "tokens=1-3 delims=:." %%a in ("%TIME%") do set /a "END_TIME=(((%%a*60)+1%%b %% 100)*60)+1%%c %% 100"
set /a "ELAPSED_TIME=(END_TIME-START_TIME)"
echo.
echo Script took %ELAPSED_TIME% seconds to run
title Done!
echo Done!
%pwr% "[System.Console]::Beep()"
%pwr% "[System.Console]::Beep()"
%pwr% "[System.Console]::Beep()"
%pwr% "[System.Console]::Beep()"
%pwr% "[System.Console]::Beep()"
msg * Computer will now restart!
timeout /nobreak /t 10
%pwr% "Restart-Computer -Force"