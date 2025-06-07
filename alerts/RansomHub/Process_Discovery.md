# Alert: Process Discovery

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1057  
**Nazwa:** Process Discovery  
**Taktyki:** Discovery  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Discovery
Technique ID: T1057
Technique Name: Process Discovery
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Process Discovery - tasklist
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
tasklist
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1057\Process_Discovery_-_tasklist/test_1.cmd)

### Process Discovery - Get-Process
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Get-Process
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1057\Process_Discovery_-_Get-Process/test_1.ps1)

### Process Discovery - get-wmiObject
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
get-wmiObject -class Win32_Process
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1057\Process_Discovery_-_get-wmiObject/test_1.ps1)

### Process Discovery - wmic process
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wmic process get /format:list
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1057\Process_Discovery_-_wmic_process/test_1.cmd)

### Discover Specific Process - tasklist
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
tasklist | findstr #{process_to_enumerate}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1057\Discover_Specific_Process_-_tasklist/test_1.cmd)

### Process Discovery - Process Hacker
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process -FilePath "$Env:ProgramFiles\Process Hacker 2\#{processhacker_exe}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1057\Process_Discovery_-_Process_Hacker/test_1.ps1)

### Process Discovery - PC Hunter
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process -FilePath "C:\Temp\ExternalPayloads\PCHunter_free\#{pchunter64_exe}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1057\Process_Discovery_-_PC_Hunter/test_1.ps1)

### Launch Taskmgr from cmd to View running processes
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
taskmgr.exe /7
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1057\Launch_Taskmgr_from_cmd_to_View_running_/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1057)
