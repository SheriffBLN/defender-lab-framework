# Alert: File Deletion

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1070.004  
**Nazwa:** File Deletion  
**Taktyki:** Defense-Evasion  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Defense-Evasion
Technique ID: T1070.004
Technique Name: File Deletion
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Delete a single file - Windows cmd
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
del /f #{file_to_delete}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1070.004\Delete_a_single_file_-_Windows_cmd/test_1.cmd)

### Delete an entire folder - Windows cmd
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
rmdir /s /q #{folder_to_delete}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1070.004\Delete_an_entire_folder_-_Windows_cmd/test_1.cmd)

### Delete a single file - Windows PowerShell
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Remove-Item -path #{file_to_delete}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1070.004\Delete_a_single_file_-_Windows_PowerShel/test_1.ps1)

### Delete an entire folder - Windows PowerShell
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Remove-Item -Path #{folder_to_delete} -Recurse
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1070.004\Delete_an_entire_folder_-_Windows_PowerS/test_1.ps1)

### Delete Prefetch File
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Remove-Item -Path (Join-Path "$Env:SystemRoot\prefetch\" (Get-ChildItem -Path "$Env:SystemRoot\prefetch\*.pf" -Name)[0])
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1070.004\Delete_Prefetch_File/test_1.ps1)

### Delete TeamViewer Log Files
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
New-Item -Path #{teamviewer_log_file} -Force | Out-Null
Remove-Item #{teamviewer_log_file} -Force -ErrorAction Ignore
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1070.004\Delete_TeamViewer_Log_Files/test_1.ps1)

### Clears Recycle bin via rd
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
rd /s /q %systemdrive%\$RECYCLE.BIN
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1070.004\Clears_Recycle_bin_via_rd/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1070.004)
