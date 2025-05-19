# Konfiguracja reguł ASR – Tryb Audit vs Block

##  Cel

Dokument opisuje, jak włączyć reguły ASR (Attack Surface Reduction) w systemie Windows za pomocą PowerShell – zarówno w trybie **Audit** (tryb testowy), jak i **Block** (tryb produkcyjny). Uwzględniono również tabelę z najważniejszymi regułami ASR i ich identyfikatorami (GUID).

---

##  Uruchamianie reguł ASR

###  Tryb Audit – rejestrowanie bez blokowania

```powershell
# Przykład: Persistence through WMI Event Subscription (Audit)
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 `
                 -AttackSurfaceReductionRules_Actions AuditMode
```

---

###  Tryb Block – pełna ochrona (blokowanie aktywne)

```powershell
# Przykład: Persistence through WMI Event Subscription (Block)
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 `
                 -AttackSurfaceReductionRules_Actions Block
```

---

##  Lista popularnych reguł ASR

| Nazwa reguły                                                                 | GUID                                     |
|------------------------------------------------------------------------------|------------------------------------------|
| Block abuse of exploited vulnerable signed drivers                          | 56a863a9-875e-4185-98a7-b882c64b5ce5     |
| Block credential stealing from LSASS                                        | 9e6e4e65-49cb-4e15-bb0a-0a0cfd0d4ef2     |
| Block executable content from email and webmail                             | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550     |
| Block Office applications from creating child processes                     | d4f940ab-401b-4efc-aadc-ad5f3c50688a     |
| Block Office applications from injecting code into other processes          | 3b576869-a4ec-4529-8536-b80a7769e899     |
| Block Office communication app from creating child processes                | 26190899-1602-49e8-8b27-eb1d0a1ce869     |
| Block JavaScript/VBScript from launching downloaded executable content      | d3e037e1-3eb8-44c8-a917-57927947596d     |
| Block execution of potentially obfuscated scripts                           | 5beb7efe-fd9a-4556-801d-275e5ffc04cc     |
| Block Win32 API calls from Office macros                                    | c1db55ab-c21a-4637-bb3f-a12568109d35     |
| Use advanced protection against ransomware                                   | c75c8f86-93e3-4b3d-8b41-46358784664c     |
| Block credential stealing via SMB                                           | 0741b7a8-3b20-42c2-9eb9-4f6f36f00f6c     |
| Block persistence through WMI event subscription                            | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84     |

---

##  Sprawdzanie konfiguracji ASR

### Lista przypisanych akcji (Audit/Block):

```powershell
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Actions
```

### Pełna konfiguracja reguł ASR:

```powershell
Get-MpPreference | fl *AttackSurfaceReduction*
```

---

##  Usuwanie lub resetowanie reguł

### Usunięcie jednej reguły:

```powershell
Remove-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84
```

### Resetowanie wyjątków (exclusions):

```powershell
Set-MpPreference -AttackSurfaceReductionOnlyExclusions @()
```

---

##  Zalecenia praktyczne

- W środowisku testowym zawsze zaczynaj od trybu **AuditMode**
- Obserwuj alerty w portalu: [https://security.microsoft.com](https://security.microsoft.com)
- Po potwierdzeniu braku false positives – przejdź do trybu **Block**
- Do produkcji zalecane są minimum te reguły:
  - `c1db55ab-c21a-4637-bb3f-a12568109d35` – Office macros → Win32 API
  - `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550` – Executable content from email
  - `9e6e4e65-49cb-4e15-bb0a-0a0cfd0d4ef2` – LSASS credential theft
  - `75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84` – WMI event subscription

---

**Autor:** Krzysztof Krzymowski  
**Repozytorium:** `defender-lab-setup/asr-rules/`

> Reguły ASR są skutecznym mechanizmem ograniczania powierzchni ataku i powinny być aktywowane zgodnie z dojrzałością organizacji oraz stopniem testów ich wpływu.
