# Alert: File and Directory Discovery

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1083  
**Nazwa:** File and Directory Discovery  
**Taktyki:** Discovery  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Discovery
Technique ID: T1083
Technique Name: File and Directory Discovery
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### File and Directory Discovery (cmd.exe)
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
dir /s c:\ >> #{output_file}
dir /s "c:\Documents and Settings" >> #{output_file}
dir /s "c:\Program Files\" >> #{output_file}
dir "%systemdrive%\Users\*.*" >> #{output_file}
dir "%userprofile%\AppData\Roaming\Microsoft\Windows\Recent\*.*" >> #{output_file}
dir "%userprofile%\Desktop\*.*" >> #{output_file}
tree /F >> #{output_file}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1083\File_and_Directory_Discovery_(cmd.exe)/test_1.cmd)

<b>Polecenia cleanup (cmd):</b>
```
del #{output_file}
```
[Pobierz cleanup_1.cmd](../../scenarios/atomic_tests\T1083\File_and_Directory_Discovery_(cmd.exe)/cleanup_1.cmd)

### File and Directory Discovery (PowerShell)
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
ls -recurse
get-childitem -recurse
gci -recurse
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1083\File_and_Directory_Discovery_(PowerShell/test_1.ps1)

### Simulating MAZE Directory Enumeration
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$folderarray = @("Desktop", "Downloads", "Documents", "AppData/Local", "AppData/Roaming")
Get-ChildItem -Path $env:homedrive -ErrorAction SilentlyContinue | Out-File -append #{File_to_output}
Get-ChildItem -Path $env:programfiles -erroraction silentlycontinue | Out-File -append #{File_to_output}
Get-ChildItem -Path "${env:ProgramFiles(x86)}" -erroraction silentlycontinue | Out-File -append #{File_to_output}
$UsersFolder = "$env:homedrive\Users\"
foreach ($directory in Get-ChildItem -Path $UsersFolder -ErrorAction SilentlyContinue) 
{
foreach ($secondarydirectory in $folderarray)
 {Get-ChildItem -Path "$UsersFolder/$directory/$secondarydirectory" -ErrorAction SilentlyContinue | Out-File -append #{File_to_output}}
}
cat #{File_to_output}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1083\Simulating_MAZE_Directory_Enumeration/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
remove-item #{File_to_output} -ErrorAction SilentlyContinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1083\Simulating_MAZE_Directory_Enumeration/cleanup_1.ps1)

### Launch DirLister Executable
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process "#{dirlister_path}"
Start-Sleep -Second 4
Stop-Process -Name "DirLister"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1083\Launch_DirLister_Executable/test_1.ps1)

### ESXi - Enumerate VMDKs available on an ESXi Host
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
echo "" | "#{plink_file}" "#{vm_host}" -ssh  -l "#{vm_user}" -pw "#{vm_pass}" -m "#{cli_script}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1083\ESXi_-_Enumerate_VMDKs_available_on_an_E/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1083)
