# Alert: SMB/Windows Admin Shares

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1021.002  
**Nazwa:** SMB/Windows Admin Shares  
**Taktyki:** Lateral-Movement  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Lateral-Movement
Technique ID: T1021.002
Technique Name: SMB/Windows Admin Shares
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Map admin share
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
cmd.exe /c "net use \\#{computer_name}\#{share_name} #{password} /u:#{user_name}"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1021.002\Map_admin_share/test_1.cmd)

### Map Admin Share PowerShell
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
New-PSDrive -name #{map_name} -psprovider filesystem -root \\#{computer_name}\#{share_name}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1021.002\Map_Admin_Share_PowerShell/test_1.ps1)

### Copy and Execute File with PsExec
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
"#{psexec_exe}" #{remote_host} -accepteula -c #{command_path}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1021.002\Copy_and_Execute_File_with_PsExec/test_1.cmd)

### Execute command writing output to local Admin Share
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
cmd.exe /Q /c #{command_to_execute} 1> \\127.0.0.1\ADMIN$\#{output_file} 2>&1
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1021.002\Execute_command_writing_output_to_local_/test_1.cmd)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1021.002)
