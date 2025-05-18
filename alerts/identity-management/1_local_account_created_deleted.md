#  Alert: Wykrycie utworzenia nowego lub usunięcia lokalnego konta użytkownika na stacji (Account Created)

##  Opis

Ten alert wykrywa moment utworzenia nowego konta użytkownika lokalnego w systemie Windows, co może wskazywać na:

- dodanie nowego użytkownika przez administratora,
- próbę założenia konta przez malware lub atakującego (np. persistence),
- niespodziewane działania w środowiskach testowych.

---

## Techniczne szczegóły

| Źródło                           | Tabela MDE       | Event ID (klasyczny) | ActionType          |
|----------------------------------|------------------|-----------------------|---------------------|
| Microsoft Defender for Endpoint | `DeviceEvents`   | 4720                  | `UserAccountCreated`|

---


##  KQL – hunting query

```kql
DeviceEvents
| where ActionType == "UserAccountCreated"
| project Timestamp, DeviceName, ReportId, InitiatingProcessAccountName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
```

---

##  Jak przetestować?
Na onboardowanej maszynie Windows 11 (np. Win11Client) wykonaj jeden z poniższych wariantów:

### Opcja 1 – klasyczne polecenie net user:
```cmd.exe
net user testuser123! Pass1234 /add
```

---
###  Przykład 2 – PowerShell z `New-LocalUser`:

```powershell
New-LocalUser -Name "testuser456" -Password (ConvertTo-SecureString "Pass456!" -AsPlainText -Force)
```
---
##  Oczekiwany wynik

Po kilku minutach powinien pojawić się alert w portalu Microsoft 365 Defender:

- Portal: [https://security.microsoft.com](https://security.microsoft.com)
- Sekcja: **Incidents & Alerts**
- Tytuł alertu: **"A user account was created"**
- Detekcja oparta o `ActionType == UserAccountCreated`
- Typowe procesy wyzwalające:
  - `net.exe`
  - `powershell.exe`
  - `lsass.exe` (jeśli konto tworzone programowo)
---

##  Wskazówki triage

W przypadku wyzwolenia alertu warto sprawdzić:

-  **Kto** utworzył konto (`InitiatingProcessAccountName`)
-  **Na jakim hoście** (`DeviceName`)
-  **Jaki proces** zainicjował zmianę (`InitiatingProcessCommandLine`)
-  Czy konto trafiło do wrażliwej grupy (np. `Administrators`)
-  Czy konto ma ustawione hasło, czy może być użyte do persistence

---

**Status testu:**  Potwierdzono skuteczne wykrycie w środowisku labowym

---
**Autor:** Krzysztof Krzymowski
