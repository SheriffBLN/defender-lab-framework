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
