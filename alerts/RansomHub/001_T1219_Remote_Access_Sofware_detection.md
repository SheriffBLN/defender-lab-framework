# Alert: Remote Access Tools

Ten scenariusz detekcji służy do wykrywania legalnych narzędzi zdalnego dostępu (Remote Access Tools, np. TeamViewer, AnyDesk, Ammyy Admin, UltraVNC, itp.), które są często wykorzystywane przez grupy ransomware/RaaS – w tym RansomHub – do uzyskania zdalnej kontroli nad stacjami roboczymi ofiary.

Technika ta pozwala atakującemu na utrzymanie się w środowisku, zdalne sterowanie, eksfiltrację danych lub koordynację kolejnych etapów ataku, nie budząc podejrzeń (narzędzia te są powszechnie wykorzystywane w legalnych celach).

## Opis scenariusza:

- Adwersarz wdraża i uruchamia oryginalne, podpisane narzędzia RMM na stacji ofiary.
- W środowiskach objętych atakiem RansomHub, detekcja takich zdarzeń (w szczególności na serwerach, maszynach uprzywilejowanych lub terminalach użytkowników nietechnicznych) może wskazywać na przejęcie hosta i zdalne sterowanie.
- Detekcja obejmuje zarówno instalki, wersje portable, jak i egzotyczne buildy narzędzi RMM.

---

## Przykładowa reguła KQL

```kql
let certInfo = DeviceFileCertificateInfo
    | where Signer has_any (
        "AnyDesk", "TeamViewer", "RealVNC", "LogMeIn","Splashtop", "Ammyy", 
        "AeroAdmin", "UltraVNC", "SolarWinds"
    )
    | project DeviceName, SHA1, Signer, CertTimestamp=Timestamp;
let fileEvents = DeviceFileEvents
    | project DeviceName, SHA1, FolderPath, FileName, FileEventTimestamp=Timestamp;
certInfo
| join kind=inner (fileEvents) on DeviceName, SHA1
| extend EventHour = bin(FileEventTimestamp, 1h)
| summarize 
    AlertCount = count(),
    Files = make_list(pack("FileName", FileName, "FolderPath", FolderPath, "CertTimestamp", CertTimestamp, "FileEventTimestamp", FileEventTimestamp)),
    FirstSeen = min(FileEventTimestamp),
    LastSeen = max(FileEventTimestamp)
    by DeviceName, Signer, EventHour
| project DeviceName, Signer, EventHour, AlertCount, FirstSeen, LastSeen, Files
| sort by LastSeen desc
---


## Działania po detekcji

- Zweryfikuj, czy narzędzie zdalnego dostępu (RMM/RAT) zostało wdrożone przez uprawnionego użytkownika (np. dział IT/helpdesk) czy jest to nietypowa lub nieautoryzowana aktywność.
- Przeanalizuj historię konta i hosta – sprawdź, czy w tym samym czasie nie wystąpiły inne podejrzane techniki (np. eskalacja uprawnień, backupy, modyfikacja rejestru, szyfrowanie plików).
- Ustal, czy na maszynie wystąpiła instalacja/uruchomienie narzędzia portable, instalki, lub nietypowej wersji RMM (np. zmieniona lokalizacja, nazwa pliku).
- Skontaktuj się z użytkownikiem maszyny – potwierdź, czy korzystanie z narzędzia było autoryzowane i czy użytkownik rozpoznaje tę aktywność.
- Jeśli incydent wydaje się podejrzany – uruchom procedurę IR (response), izoluj hosta oraz przeanalizuj ruch sieciowy i potencjalne transfery plików przez zdalny pulpit.
- Poinformuj zespół bezpieczeństwa oraz przeprowadź dodatkową analizę pod kątem obecności innych narzędzi z matrycy RansomHub.


---

**Technika:** T1219  
**Nazwa:** Remote Access Tools  
**Taktyki:** Command-And-Control  
**Status:** Tested  
**Autor:** Krzysztof Krzymowski  

---

<!--
Tactics: Command-And-Control
Technique ID: T1219
Technique Name: Remote Access Tools
Status: Tested
--> 


---

## Atomic Red Team – dostępne testy dla tej techniki

### TeamViewer Files Detected Test on Windows
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\TeamViewer_Setup.exe https://download.teamviewer.com/download/TeamViewer_Setup.exe
$file1 = "C:\Users\" + $env:username + "\Desktop\TeamViewer_Setup.exe"
Start-Process -Wait $file1 /S; 
Start-Process 'C:\Program Files (x86)\TeamViewer\TeamViewer.exe'
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\TeamViewer_Files_Detected_Test_on_Window/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$file = 'C:\Program Files (x86)\TeamViewer\uninstall.exe'
if(Test-Path $file){ Start-Process $file "/S" -ErrorAction Ignore | Out-Null }
$file1 = "C:\Users\" + $env:username + "\Desktop\TeamViewer_Setup.exe"
Remove-Item $file1 -ErrorAction Ignore | Out-Null
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\TeamViewer_Files_Detected_Test_on_Window/cleanup_1.ps1)

### AnyDesk Files Detected Test on Windows
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\AnyDesk.exe https://download.anydesk.com/AnyDesk.exe
$file1 = "C:\Users\" + $env:username + "\Desktop\AnyDesk.exe"
Start-Process $file1 /S;
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\AnyDesk_Files_Detected_Test_on_Windows/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$file1 = "C:\Users\" + $env:username + "\Desktop\AnyDesk.exe"
Remove-Item $file1 -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\AnyDesk_Files_Detected_Test_on_Windows/cleanup_1.ps1)

### LogMeIn Files Detected Test on Windows
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Invoke-WebRequest -OutFile C:\Users\$env:username\Desktop\LogMeInIgnition.msi https://secure.logmein.com/LogMeInIgnition.msi
$file1 = "C:\Users\" + $env:username + "\Desktop\LogMeInIgnition.msi"
Start-Process -Wait $file1 /quiet;
Start-Process 'C:\Program Files (x86)\LogMeIn Ignition\LMIIgnition.exe' "/S"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\LogMeIn_Files_Detected_Test_on_Windows/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
get-package *'LogMeIn Client'* -ErrorAction Ignore | uninstall-package 
$file1 = "C:\Users\" + $env:username + "\Desktop\LogMeInIgnition.msi"
Remove-Item $file1 -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\LogMeIn_Files_Detected_Test_on_Windows/cleanup_1.ps1)

### GoToAssist Files Detected Test on Windows
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Invoke-WebRequest -OutFile C:\Users\$env:username\Downloads\GoToAssist.exe "https://launch.getgo.com/launcher2/helper?token=e0-FaCddxmtMoX8_cY4czssnTeGvy83ihp8CLREfvwQshiBW0_RcbdoaEp8IA-Qn8wpbKlpGIflS-39gW6RuWRM-XHwtkRVMLBsp5RSKp-a3PBM-Pb1Fliy73EDgoaxr-q83WtXbLKqD7-u3cfDl9gKsymmhdkTGsXcDXir90NqKj92LsN_KpyYwV06lIxsdRekhNZjNwhkWrBa_hG8RQJqWSGk6tkZLVMuMufmn37eC2Cqqiwq5bCGnH5dYiSUUsklSedRLjh4N46qPYT1bAU0qD25ZPr-Kvf4Kzu9bT02q3Yntj02ZA99TxL2-SKzgryizoopBPg4Ilfo5t78UxKTYeEwo4etQECfkCRvenkTRlIHmowdbd88zz7NiccXnbHJZehgs6_-JSVjQIdPTXZbF9T5z44mi4BQYMtZAS3DE86F0C3D4Tcd7fa5F6Ve8rQWt7pvqFCYyiJAailslxOw0LsGyFokoy65tMF980ReP8zhVcTKYP8s8mhGXihUQJQPNk20Sw&downloadTrigger=restart&renameFile=1"
$file1 = "C:\Users\" + $env:username + "\Downloads\GoToAssist.exe"
Start-Process $file1 /S;
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\GoToAssist_Files_Detected_Test_on_Window/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
try{"$PathToAtomicsFolder/T1219/bin/GoToCleanup.ps1"} catch{}
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\GoToAssist_Files_Detected_Test_on_Window/cleanup_1.ps1)

### ScreenConnect Application Download and Install on Windows
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$installer = "C:\Users\$env:username\Downloads\ScreenConnect.msi"
Invoke-WebRequest -OutFile $installer "https://d1kuyuqowve5id.cloudfront.net/ScreenConnect_25.1.10.9197_Release.msi"
msiexec /i $installer /qn
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\ScreenConnect_Application_Download_and_I/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$installer = "C:\Users\$env:username\Downloads\ScreenConnect.msi"
msiexec /x $installer /qn
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\ScreenConnect_Application_Download_and_I/cleanup_1.ps1)

### Ammyy Admin Software Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process "#{Ammyy_Admin_Path}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\Ammyy_Admin_Software_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name "Ammyy" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\Ammyy_Admin_Software_Execution/cleanup_1.ps1)

### RemotePC Software Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process "#{RemotePC_Path}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\RemotePC_Software_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Unregister-ScheduledTask -TaskName "RemotePC" -Confirm:$False -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "RPCServiceHealthCheck" -Confirm:$False -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "ServiceMonitor" -Confirm:$False -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "StartRPCService" -Confirm:$False -ErrorAction SilentlyContinue      
Stop-Process -Name "RemotePCPerformance" -force -erroraction silentlycontinue
Stop-Process -Name "RPCPerformanceService" -force -erroraction silentlycontinue
Stop-Process -Name "RemotePCUIU" -force -erroraction silentlycontinue
Stop-Process -Name "RPCDownloader" -force -erroraction silentlycontinue
Stop-Process -Name "RemotePCService" -force -erroraction silentlycontinue
Stop-Process -Name "RPCService" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\RemotePC_Software_Execution/cleanup_1.ps1)

### NetSupport - RAT Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process "#{NetSupport_Path}" -ArgumentList "/S /v/qn"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\NetSupport_-_RAT_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name "client32" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\NetSupport_-_RAT_Execution/cleanup_1.ps1)

### UltraViewer - RAT Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process -Wait -FilePath "#{UltraViewer_Path}" -Argument "/silent" -PassThru
Start-Process 'C:\Program Files (x86)\UltraViewer\UltraViewer_Desktop.exe'
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\UltraViewer_-_RAT_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name "UltraViewer_Desktop" -Force -ErrorAction SilentlyContinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\UltraViewer_-_RAT_Execution/cleanup_1.ps1)

### UltraVNC Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process #{UltraVNC_Viewer_Path}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\UltraVNC_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name "vncviewer" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\UltraVNC_Execution/cleanup_1.ps1)

### MSP360 Connect Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process #{MSP360_Connect_Path}
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\MSP360_Connect_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name "Connect" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\MSP360_Connect_Execution/cleanup_1.ps1)

### RustDesk Files Detected Test on Windows
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
$file = Join-Path $env:USERPROFILE "Desktop\rustdesk-1.2.3-1-x86_64.exe"
Invoke-WebRequest  -OutFile $file https://github.com/rustdesk/rustdesk/releases/download/1.2.3-1/rustdesk-1.2.3-1-x86_64.exe
Start-Process -FilePath $file "/S"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\RustDesk_Files_Detected_Test_on_Windows/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
$file = Join-Path $env:USERPROFILE "Desktop\rustdesk-1.2.3-1-x86_64.exe"
Remove-Item $file1 -ErrorAction Ignore
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\RustDesk_Files_Detected_Test_on_Windows/cleanup_1.ps1)

### Splashtop Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process "#{Splashtop_Path}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\Splashtop_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name "strwinclt" -force -erroraction silentlycontinue
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\Splashtop_Execution/cleanup_1.ps1)

### Splashtop Streamer Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process -FilePath "C:Program Files (x86)\Splashtop\Splashtop Remote\Server\#{srserver_exe}"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\Splashtop_Streamer_Execution/test_1.ps1)

### Microsoft App Quick Assist Execution
**Opis:** 

<b>Polecenia testowe (powershell):</b>
```
Start-Process "shell:AppsFolder\MicrosoftCorporationII.QuickAssist_8wekyb3d8bbwe!App"
```
[Pobierz test_1.ps1](../../scenarios/atomic_tests\T1219\Microsoft_App_Quick_Assist_Execution/test_1.ps1)

<b>Polecenia cleanup (powershell):</b>
```
Stop-Process -Name quickassist
```
[Pobierz cleanup_1.ps1](../../scenarios/atomic_tests\T1219\Microsoft_App_Quick_Assist_Execution/cleanup_1.ps1)

[Zobacz testy na GitHubie](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1219)
